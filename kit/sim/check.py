"""Compiler checks (docs/kit/simulator.md §8.5): the report and the timeline pass.

Errors (E*) break the ground-truth definition or a world invariant, or make
the scenario unplayable; they stop compilation. Warnings (W*) are legal but
probably not what the author meant. Both go to scenario.check.json.

The compiler checks the world and each HL item as it plays it (it knows the
state at that moment). This module then replays the compiled timeline, so
raw and hand-edited events are checked the same way as expanded ones.
"""

import ipaddress
import re
from collections import Counter, defaultdict

from kit.sim import timeline
from kit.sim.blocklist import Blocklist, BlocklistError, normalize_entry
from kit.sim.engine import DEP_GAP_S, Recent

FORMAT = 'lab2-check/1'
KEEP = 20                        # findings kept per rule (all are counted)
MAX_SIZE = 50 * 1000 * 1000      # the server clamps request sizes here
# A response must arrive within the client's 10 s request timeout (kit/sim/agent.py):
# about 12 MB at 10 Mbit/s, the slowest shaped access link, less under load.
SLOW_SIZE = 10 * 1000 * 1000
EXTERNAL_SPACE = ipaddress.IPv4Network('198.18.0.0/15')
# W11 threshold, network-wide with shaped links: about what the 4-core VM plays
# without falling behind.
LOAD_WARN_REQ_S = 400
NAME_LABEL = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
ID_UNSAFE = re.compile(r'[/?#\s]')


def dns_name_ok(name):
    """Lowercase ASCII DNS name, labels of 1-63 characters, no trailing dot."""
    return (isinstance(name, str) and 0 < len(name) <= 253
            and all(NAME_LABEL.match(l) for l in name.split('.')))


class Report:
    def __init__(self):
        self.findings = []
        self.counts = Counter()
        self.info = {}

    def add(self, rule, where, msg, t=None, origin=None):
        self.counts[rule] += 1
        if self.counts[rule] <= KEEP:
            f = {'rule': rule, 'where': where}
            if t is not None:
                f['t'] = t
            if origin is not None:
                f['origin'] = origin
            f['msg'] = msg
            self.findings.append(f)

    def of(self, level):
        return [f for f in self.findings if f['rule'][0] == level]

    def total(self, level):
        return sum(n for r, n in self.counts.items() if r[0] == level)

    def to_json(self, **extra):
        return dict(extra, format=FORMAT,
                    errors=self.total('E'), warnings=self.total('W'),
                    counts=dict(sorted(self.counts.items())),
                    findings=sorted(self.findings, key=lambda f: (f['rule'][0], f.get('t', -1))),
                    **self.info)

    def lines(self):
        out = []
        for f in sorted(self.findings, key=lambda f: (f['rule'][0], f.get('t', -1))):
            out.append('%s %s%s: %s' % (f['rule'], f['where'],
                                        ' t=%s' % f['t'] if 't' in f else '', f['msg']))
        for r, n in sorted(self.counts.items()):
            if n > KEEP:
                out.append('%s: %d more not shown' % (r, n - KEEP))
        return out


class AddressPlan:
    """What server address an address is: external, cache:<host>, domestic (a PoP /16
    address that is not a subscriber's), or None."""

    def __init__(self, world):
        self.world = world
        self.nets = [(n, 'external') for n in world.external]
        self.nets += [(n, 'cache:' + h) for h, n in world.cache_prefix.items()]
        self.nets += [(p.prefix, 'domestic') for p in world.pops]

    def kind(self, ip):
        try:
            a = ipaddress.IPv4Address(ip)
        except (ValueError, TypeError):
            return None
        k = next((k for n, k in self.nets if a in n), None)
        if k == 'domestic' and self.world.is_subscriber(a):
            return None
        return k

    def agrees(self, hosting, ip):
        k = self.kind(ip)
        return k == hosting or (hosting == 'cache' and k == 'external')


def entries_ok(rep, entries, where, t=None):
    """E11: every entry normalizes. Returns the normalized ones."""
    out = []
    for i, e in enumerate(entries or ()):
        try:
            out.append(normalize_entry(e))
        except BlocklistError as ex:
            rep.add('E11', '%s[%d]' % (where, i), str(ex), t)
    return out


# ---- timeline pass ----------------------------------------------------
class TimelineCheck:
    def __init__(self, rep, header, world, topo, engine):
        self.rep = rep
        self.header = header
        self.world = world
        self.topo = topo
        self.e = engine
        self.plan = AddressPlan(world)
        self.duration = header['duration_s']
        self.pops = {p['pop'] for p in header['pops']}
        self.client_prefix = {p['client']: ipaddress.IPv4Network(p['prefix'])
                              for p in header['pops']}
        self.endpoints = {e['ip']: e for e in header['endpoints']}
        self.ports = {e['ip']: e.get('port') for e in header['endpoints']}
        self.exits = set(world.exits)
        self.external = {str(n) for n in world.external}
        self.links = {frozenset((l.a, l.b)): l for l in topo.links}
        self.bl = Blocklist()
        self.serving = defaultdict(set)      # site -> ips
        self.records = {}                    # site -> [ips over all views]
        self.down = set()
        self.te_pending = {}                 # te_id -> apply_at
        self.ids = set()
        self.orders = set()
        self.tes = set()
        self.names = set()                   # names in server_content / dns_record
        self.site_ips = set()                # every address that serves a site at some t
        self.recent = Recent(world)

    def allowed(self, site):
        x = self.world.sites.get(site)
        return x is not None and not x.targeted

    def ip_hit(self, ip):
        """The in-force ip entry covering ip, or None."""
        return self.bl.match(ips=[ip]) if ip else None

    def add(self, rule, e, msg):
        self.rep.add(rule, 'seq=%d' % e['seq'], msg, e['t'], e.get('origin'))

    def run(self, events):
        for e in events:
            if e['ev'] in ('server_content', 'dns_record'):
                self.names.add(e.get('site') or e.get('domain'))
            if e['ev'] == 'server_content':
                self.site_ips.add(e['ip'])
        for e in sorted(events, key=lambda e: (e['t'], e['ev'] == 'request', e['seq'])):
            getattr(self, 'on_' + e['ev'])(e)
            if e['ev'] != 'request':
                self.recent.note(e)

    # ---- DNS and content ----------------------------------------------
    def on_server_content(self, e):
        site, ip = e['site'], e['ip']
        if e['op'] == 'unserve':
            self.serving[site].discard(ip)
            return
        if self.plan.kind(ip) is None:
            self.add('E4', e, 'site %s served at %s, not a server address' % (site, ip))
        if ip in self.endpoints:
            self.add('W9', e, 'site %s served at endpoint address %s' % (site, ip))
        hit = self.ip_hit(ip)
        if hit and self.allowed(site):
            self.add('E7', e, 'allowed site %s served at %s, which entry %s lists'
                     % (site, ip, hit['value']))
        self.name_hit(e, site)
        self.serving[site].add(ip)

    def on_dns_record(self, e):
        d = e['domain']
        if e['op'] == 'remove':
            self.records.pop(d, None)
            return
        ips = list(e['ips'])
        seen = set()
        for v in e.get('views') or ():
            ips += v.get('ips', [])
            for p in v.get('pops', ()):
                if p not in self.pops:
                    self.add('E8', e, '%s: view %s names unknown PoP %r' % (d, v.get('view'), p))
                elif p in seen:
                    self.add('E8', e, '%s: PoP %s is in two views' % (d, p))
                seen.add(p)
        for ip in ips:
            if self.plan.kind(ip) is None:
                self.add('E4', e, '%s answers %s, not a server address' % (d, ip))
            elif ip not in self.serving[d]:
                self.add('W2', e, '%s set to %s, which does not serve it' % (d, ip))
            hit = self.ip_hit(ip)
            if hit and self.allowed(d):
                self.add('E7', e, 'allowed site %s answers %s, which entry %s lists'
                         % (d, ip, hit['value']))
        self.name_hit(e, d)
        self.records[d] = ips

    def name_hit(self, e, site):
        """W6: an allowed site appears under a name entry already in force."""
        if self.allowed(site) and not self.serving[site] and site not in self.records:
            hit = self.bl.match(site)
            if hit:
                self.add('W6', e, '%s %s covers allowed site %s'
                         % (hit['type'], hit['value'], site))

    # ---- blocklist ----------------------------------------------------
    def on_blocklist_order(self, e):
        oid = e['order_id']
        if oid in self.orders:
            self.add('E2', e, 'duplicate order_id %r' % oid)
        self.orders.add(oid)
        for x in e.get('remove') or ():
            try:
                if normalize_entry(x) not in self.bl:
                    self.add('W7', e, 'removes %s, which is not in force' % (x,))
            except BlocklistError:
                pass                    # E11, reported by the compiler
        adds = []
        for x in e.get('add') or ():
            try:
                adds.append(normalize_entry(x))
            except BlocklistError:
                pass
        self.bl.apply_order(oid, adds, [x for x in e.get('remove') or () if _ok(x)])
        for x in adds:
            self.entry_effects(e, x)

    def entry_effects(self, e, x):
        if x['type'] in ('domain', 'suffix'):
            one = Blocklist()
            one.apply_order('-', [x])
            for s in sorted(set(self.records) | {s for s, ips in self.serving.items() if ips}):
                if self.allowed(s) and one.match(s):
                    self.add('W6', e, '%s %s covers allowed site %s'
                             % (x['type'], x['value'], s))
            return
        if x['type'] != 'ip':
            return
        net = ipaddress.IPv4Network(x['value'])
        for site, ips in list(self.serving.items()) + list(self.records.items()):
            if self.allowed(site):
                for ip in ips:
                    if ipaddress.IPv4Address(ip) in net:
                        self.add('E7', e, 'ip %s covers %s, an address of allowed site %s'
                                 % (x['value'], ip, site))
        if any(net.overlaps(n) for n in self.world.cache_prefix.values()):
            self.add('W6', e, 'ip %s covers a cache address' % x['value'])
        for ip in self.endpoints:
            if ipaddress.IPv4Address(ip) in net:
                self.add('W6', e, 'ip %s covers endpoint %s (use an endpoint entry)'
                         % (x['value'], self.endpoints[ip]['id']))

    # ---- ISP ----------------------------------------------------------
    def on_route_change(self, e):
        if e['prefix'] not in self.external:
            self.add('E5', e, 'route_change of %s, not an external prefix' % e['prefix'])
        if e['to'] not in self.exits:
            self.add('E5', e, 'route_change to %s, not an exit edge port' % e['to'])

    def link(self, e):
        a, _, b = str(e['link']).partition('-')
        return self.links.get(frozenset((a, b)))

    def on_link_down(self, e):
        l = self.link(e)
        if l is None:
            self.add('E2', e, 'unknown link %r' % e['link'])
            return
        if l.index in self.down:
            self.add('W8', e, 'link %s is already down' % e['link'])
            return
        if not connected(self.topo, self.down | {l.index}):
            self.add('E12', e, 'link_down %s splits the switch graph' % e['link'])
        self.down.add(l.index)

    def on_link_up(self, e):
        l = self.link(e)
        if l is None:
            self.add('E2', e, 'unknown link %r' % e['link'])
        elif l.index not in self.down:
            self.add('W8', e, 'link %s is already up' % e['link'])
        else:
            self.down.discard(l.index)

    def on_te_notice(self, e):
        if e['te_id'] in self.tes:
            self.add('E2', e, 'duplicate te_id %r' % e['te_id'])
        self.tes.add(e['te_id'])
        if any(a > e['t'] for a in self.te_pending.values()):
            self.add('W8', e, 'TE notice before the previous TE is applied')
        self.te_pending[e['te_id']] = e['apply_at']

    def on_te_reoptimize(self, e):
        self.te_pending.pop(e['te_id'], None)
        for name, w in (e.get('weights') or {}).items():
            a, _, b = str(name).partition('-')
            if frozenset((a, b)) not in self.links:
                self.add('E10', e, 'weight for unknown link %r' % name)
            elif isinstance(w, bool) or not isinstance(w, int) or w < 1:
                self.add('E10', e, 'weight of %s must be an integer >= 1, not %r' % (name, w))

    # ---- requests -----------------------------------------------------
    def on_request(self, e):
        rid, site, m = e['id'], e['site'], e['method']
        if rid in self.ids:
            self.add('E2', e, 'duplicate request id %r' % rid)
        self.ids.add(rid)
        if not isinstance(rid, str) or ID_UNSAFE.search(rid) or not rid:
            self.add('E9', e, 'request id %r is not URL-path-safe' % (rid,))
        net = self.client_prefix.get(e['client'])
        if net is None:
            self.add('E9', e, 'client %r is not a PoP edge port' % e['client'])
        else:
            try:
                if ipaddress.IPv4Address(e['src_ip']) not in net:
                    self.add('E9', e, 'src_ip %s is outside %s' % (e['src_ip'], net))
                elif e['src_ip'] in self.site_ips:
                    self.add('E9', e, 'src_ip %s is a site address' % e['src_ip'])
            except ValueError:
                self.add('E9', e, 'bad src_ip %r' % e['src_ip'])
        if e['t'] > self.duration:
            self.add('E9', e, 'request after duration_s')
        if not dns_name_ok(site):
            self.add('E9', e, 'site %r is not a lowercase DNS name' % (site,))
        elif site not in self.names:
            for n in self.names:
                if n.lower().rstrip('.') == site:
                    self.add('E9', e, 'site %r is spelled %r in the state events' % (site, n))
                    break
        if 'expect_ip' not in e:
            self.add('E9', e, 'expect_ip is not set')
        if m == 'direct_ip' and not e.get('expect_ip'):
            self.add('E9', e, 'direct_ip without expect_ip')
        if m in timeline.ENDPOINT_METHODS:
            ep = self.endpoints.get(e.get('endpoint'))
            if ep is None or ep['kind'] != m:
                self.add('E9', e, '%s needs the IP of a %s endpoint, not %r'
                         % (m, m, e.get('endpoint')))
        size = e.get('size', 0)
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            self.add('E9', e, 'size must be an integer >= 0, not %r' % (size,))
        elif size > MAX_SIZE:
            self.add('W12', e, 'size %d is above 50 MB (the server clamps it)' % size)
        elif size > SLOW_SIZE:
            self.add('W12', e, 'size %d is above 10 MB: it may not arrive within the '
                     "client's 10 s request timeout on a shaped link" % size)
        for k in ('split_host', 'large_header'):
            if k in e and not isinstance(e[k], bool):
                self.add('E9', e, '%s must be true or false' % k)
        hit = self.ip_hit(e.get('expect_ip'))
        if hit and self.allowed(site):
            self.add('E7', e, 'request for allowed site %s is blocked through ip %s'
                     % (site, hit['value']))
        if e['t'] <= 0:
            self.add('W12', e, 'request at t = 0, the end of the bootstrap phase; '
                     'requests should come after it')
        d = self.recent.last(e)
        if d is not None and e['t'] - d < DEP_GAP_S - 1e-9:
            self.add('W12', e, 'request %.0f ms after a state change it depends on'
                     % (1000 * (e['t'] - d)))


def _ok(x):
    try:
        normalize_entry(x)
        return True
    except BlocklistError:
        return False


def connected(topo, down):
    """True if the switches stay connected with the given links down."""
    nodes = set(topo.switches)
    adj = defaultdict(set)
    for l in topo.links:
        if l.index not in down:
            adj[l.a].add(l.b)
            adj[l.b].add(l.a)
    start = next(iter(nodes))
    seen, stack = {start}, [start]
    while stack:
        for n in adj[stack.pop()]:
            if n not in seen:
                seen.add(n)
                stack.append(n)
    return nodes <= seen


def check_timeline(rep, header, events, world, topo, engine):
    TimelineCheck(rep, header, world, topo, engine).run(events)


def load_estimate(engine):
    """Peak network-wide request rate (req/s), an upper bound: every PoP at its own peak
    (segments, diurnal) plus the largest flash-crowd extra."""
    e = engine
    di = e.demand.get('diurnal') or {}
    amp = di.get('amplitude', 0) if di.get('period_s') else 0
    peak = {p.name: e.peak_rate(p.name) * (1 + amp) for p in e.world.pops}
    extra = max(((f - 1) * peak.get(p, 0) for p, _, f, _, _ in e.flashes), default=0)
    return sum(peak.values()) + max(extra, 0)
