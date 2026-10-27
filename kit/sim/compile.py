"""Scenario compiler: scenario.hl.yaml -> scenario.jsonl (timeline v1).

    python -m kit.sim.compile scenario.hl.yaml -o scenario.jsonl [--seed N]

docs/kit/simulator.md §8. The compiler rebuilds the world the HL
file lists, plays its events on a scenario engine (kit.sim.engine), and
samples requests from its demand model. It is deterministic: the only
randomness is request sampling, seeded by the file's `seed` (or --seed).

Work due at the same t runs in this order: deferred parts of earlier events
(an unserve, a link_up, a delayed record, a TE application), then HL events
in file order, then TE notices, then fast-flux rotations, then requests.

Checks (§3, kit.sim.check) run on the world, on each item as it is played,
and on the compiled timeline. Errors stop compilation (CompileError, with
the report); warnings are kept in the report, which the CLI writes to
scenario.check.json next to the timeline.
"""

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import sys

from kit.config import REPO_ROOT
from kit.sim import check, hl, timeline
from kit.sim.check import AddressPlan, Report, dns_name_ok, entries_ok
from kit.sim.engine import (PRIO_FLUX, PRIO_PROCESS, PRIO_TE, UNSERVE_MARGIN_S, Engine,
                            popularity, rt)
from kit.sim.world import Endpoint, Site, World

VERSION = 'kit.sim.compile 0.1'
DEMAND_DEFAULTS = {'diurnal': {'period_s': None, 'amplitude': 0.0}, 'split_host': 0.0,
                   'large_header': 0.0, 'segments': []}


class CompileError(ValueError):
    def __init__(self, msg, report=None):
        super().__init__(msg)
        self.report = report


def load_topology_named(name):
    from kit.topology import load_topology
    path = REPO_ROOT / 'topologies' / ('%s.yaml' % name)
    if not path.exists():
        raise CompileError('topology %r: no file %s' % (name, path))
    return load_topology(path)


class Compiler:
    def __init__(self, doc, topo=None, seed=None):
        self.report = Report()
        try:
            self.doc = hl.check(doc)
        except hl.HLError as ex:
            self.report.add('E1', 'scenario', str(ex))
            raise CompileError('E1 %s' % ex, self.report)
        self.seed = doc['seed'] if seed is None else seed
        tc = doc['topology']
        self.topo = topo or load_topology_named(tc['name'])
        if self.topo.name != tc['name']:
            self.fail('E2', 'topology', 'the file is for %r, not %r'
                      % (tc['name'], self.topo.name))
        demand = dict(copy.deepcopy(DEMAND_DEFAULTS), **copy.deepcopy(doc['demand']))
        self.world = World(self.topo, {'external_prefixes': 0, 'exit_weights': {},
                                       'endpoints': {}})
        self.world.set_subscribers(demand['subscribers_per_pop'])
        self.e = Engine(self.topo, self.world, self.seed, doc['duration_s'], demand,
                        tc.get('metric', 'hops'), tc.get('tie_break', 'link_order'))
        self.plan = None
        self.flux_left = []          # (where, origin, site, unused ips)
        self.mentioned = mentioned_ips(self.doc)    # addresses the file names anywhere

    # ---- findings -----------------------------------------------------
    def fail(self, rule, where, msg, t=None):
        """An error that leaves nothing sensible to compile: stop now."""
        self.report.add(rule, where, msg, t)
        raise CompileError('%s %s: %s' % (rule, where, msg), self.report)

    def err(self, rule, where, msg, t=None, origin=None):
        self.report.add(rule, where, msg, t, origin)

    warn = err

    def site(self, name, where):
        x = self.world.sites.get(name)
        if x is None:
            self.fail('E2', where, 'unknown site %r' % (name,))
        return x

    # ---- world at t = 0 ---------------------------------------------
    def build_world(self):
        e, w, hw = self.e, self.world, self.doc['world']
        self.external_prefixes(hw['external_prefixes'])
        self.plan = AddressPlan(w)
        self.endpoints(hw['endpoints'])
        pops = {p.name for p in w.pops}
        for c, vp in (hw.get('cache_views') or {}).items():
            if c not in w.caches:
                self.fail('E2', 'world.cache_views', 'unknown cache %r' % (c,))
            for p in vp:
                if p not in pops:
                    self.fail('E2', 'world.cache_views.%s' % c, 'unknown PoP %r' % (p,))
            e.cache_views[c] = list(vp)
        specs = []
        for i, o in enumerate(hw['orgs']):
            if o['org'] in w.orgs:
                self.fail('E2', 'world.orgs[%d]' % i, 'org %r is listed twice' % o['org'])
            w.orgs.append(o['org'])
            for j, s in enumerate(o['sites']):
                where = 'world.orgs[%d].sites[%d]' % (i, j)
                if s['name'] in w.sites:
                    self.fail('E2', where, 'site %r is listed twice' % s['name'])
                if not dns_name_ok(s['name']):
                    self.fail('E1', where, 'site name %r is not a lowercase DNS name'
                              % (s['name'],))
                x = Site(s['name'], o['org'], s.get('content', s['name']), o['targeted'],
                         s['hosting'], s['ttl'])
                x.primary = s['ip']
                x.cache_ips = dict(s.get('cache_ips') or {})
                x.flux = bool(s.get('flux'))
                self.site_address(x, where)
                w.sites[x.name] = x
                specs.append((x, s))
        self.demand_refs()
        e.popularity = popularity(e.demand['popularity'])
        e.snapshot_prefixes()
        for x, s in specs:
            self.publish(x, s)
        initial = self.entries(hw.get('blocklist') or [], 'world.blocklist')
        if len(entries_ok(self.report, initial, 'world.blocklist', 0)) == len(initial):
            e.order(0, initial, origin='initial')

    def entries(self, entries, where):
        """Copies of the entries, with the sugar {site, by: domain|suffix|ip} resolved
        against the state now."""
        out = []
        for i, x in enumerate(entries):
            if isinstance(x, dict) and 'site' in x and 'type' not in x:
                s = self.site(x['site'], '%s[%d]' % (where, i))
                by = x.get('by', 'domain')
                if set(x) - {'site', 'by'} or by not in ('domain', 'suffix', 'ip'):
                    self.fail('E11', '%s[%d]' % (where, i),
                              'sugar is {site, by: domain|suffix|ip}, not %r' % (x,))
                x = ({'type': 'domain', 'value': s.name} if by == 'domain' else
                     {'type': 'suffix', 'value': s.org} if by == 'suffix' else
                     {'type': 'ip', 'value': s.primary})
            out.append(copy.deepcopy(x))
        return out

    def external_prefixes(self, plist):
        nets = []
        for i, p in enumerate(plist):
            where = 'world.external_prefixes[%d]' % i
            try:
                n = ipaddress.IPv4Network(p['cidr'])
            except ValueError as ex:
                self.fail('E1', where, str(ex))
            if not n.subnet_of(check.EXTERNAL_SPACE):
                self.err('E4', where, '%s is outside %s' % (n, check.EXTERNAL_SPACE))
            for m in nets:
                if n.overlaps(m):
                    self.err('E2' if n == m else 'E4', where, '%s overlaps %s' % (n, m))
            if p['exit'] not in self.world.exits:
                self.fail('E2', where, 'unknown exit %r' % (p['exit'],))
            nets.append(n)
        self.world.set_external([(p['cidr'], p['exit']) for p in plist])

    def endpoints(self, elist):
        w = self.world
        eps = [Endpoint(x['id'], x['kind'], x['ip'], x['port']) for x in elist]
        if [x.kind for x in eps].count('authoritative_dns') != 1 \
                or eps[0].kind != 'authoritative_dns':
            self.fail('E6', 'world.endpoints',
                      'exactly one authoritative_dns, listed first')
        seen = set()
        for i, x in enumerate(eps):
            where = 'world.endpoints[%d]' % i
            for k in (('id', x.id), ('ip', x.ip)):
                if k in seen:
                    self.err('E2', where, 'duplicate endpoint %s %r' % k)
                seen.add(k)
            if self.plan.kind(x.ip) is None:
                self.err('E4', where, 'endpoint %s at %s, not a server address'
                         % (x.id, x.ip))
        w.auth_dns, w.endpoints = eps[0], eps[1:]

    def site_address(self, x, where, ip=None):
        """E4: the address agrees with the site's hosting."""
        ip = ip or x.primary
        if not self.plan.agrees(x.hosting, ip):
            self.err('E4', where, 'site %s (%s) at %s, which is %s'
                     % (x.name, x.hosting, ip, self.plan.kind(ip) or 'not a server address'))
        for c, cip in x.cache_ips.items():
            if c not in self.world.caches:
                self.fail('E2', where, 'unknown cache %r' % (c,))
            if self.plan.kind(cip) != 'cache:' + c:
                self.err('E4', where, 'cache_ips.%s = %s is not in %s\'s prefix'
                         % (c, cip, c))

    def demand_refs(self):
        d, w = self.e.demand, self.world
        pops = [p.name for p in w.pops]
        for p in d['rate_per_s']:
            if p not in pops:
                self.fail('E2', 'demand.rate_per_s', 'unknown PoP %r' % (p,))
        for p in pops:
            if p not in d['rate_per_s']:
                self.warn('W9', 'demand.rate_per_s', 'PoP %s has no rate' % p)
        for i, s in enumerate(d.get('segments') or ()):
            where = 'demand.segments[%d]' % i
            named = list(s.get('pops') or ())
            if isinstance(s.get('rate_per_s'), dict):
                named += list(s['rate_per_s'])
            for p in named:
                if p not in pops:
                    self.fail('E2', where, 'unknown PoP %r' % (p,))
            if s['from_s'] >= self.e.duration:
                self.warn('W1', where, 'starts after duration_s')

    def popularity_refs(self):
        """At the end, when every site (mirrors, added sites) exists."""
        pm = self.e.demand['popularity']
        listed = pm['weights'] if pm['dist'] == 'weights' else pm['ranking']
        contents = {x.content for x in self.world.sites.values()}
        for c in listed:
            if c not in contents:
                self.err('E2', 'demand.popularity', 'unknown content %r' % (c,))
        for c in sorted(contents - set(listed) - set(self.e.popularity)):
            self.warn('W9', 'demand.popularity', 'content %s is not ranked (weight 0)' % c)

    def publish(self, x, s):
        """Serve and publish a site at t = 0, with the optional serve / dns overrides."""
        e = self.e
        if 'serve' not in s and 'dns' not in s:
            e.publish(0, x)
            return
        for ip in s.get('serve', [x.primary] + list(x.cache_ips.values())):
            e.emit(0, {'ev': 'server_content', 'op': 'serve', 'site': x.name, 'ip': ip})
        if 'dns' not in s:
            e.emit(0, e.record(x))
        elif s['dns'] is not None:
            d = s['dns']
            rec = {'ev': 'dns_record', 'op': 'set', 'domain': x.name,
                   'ips': list(d['ips']), 'ttl': d.get('ttl', x.ttl)}
            if d.get('views'):
                rec['views'] = copy.deepcopy(d['views'])
            e.emit(0, rec)

    # ---- events -----------------------------------------------------
    def schedule(self):
        e = self.e
        for i, it in enumerate(self.doc['events']):
            origin = it.get('origin') or 'hl[%d]' % i
            where = 'events[%d]' % i
            if it['t'] > e.duration:
                self.warn('W1', where, 'after duration_s; dropped', it['t'], origin)
                continue
            if 'raw' in it:
                e.at(it['t'], lambda now, it=it, o=origin, w=where: self.raw(now, it['raw'], o, w),
                     PRIO_PROCESS)
            elif it['ev'] == 'te':
                if it['t'] - it['notice_s'] < 0:
                    self.err('E3', where, 'TE notice would land before 0', it['t'], origin)
                    continue
                e.at(rt(it['t'] - it['notice_s']),
                     lambda now, it=it, o=origin: e.te_cycle(now, it['t'], it.get('weights'), o),
                     PRIO_TE)
            elif it['ev'] == 'fast_flux':
                self.fast_flux(it, origin, where)
            else:
                fn = getattr(self, 'ev_' + it['ev'])
                e.at(it['t'], lambda now, fn=fn, it=it, o=origin, w=where: fn(now, it, o, w),
                     PRIO_PROCESS)

    def raw(self, t, raw, origin, where):
        e, w = self.e, self.world
        ev = {k: copy.deepcopy(v) for k, v in raw.items() if k != 'ev'}
        ev.update(ev=raw['ev'], origin=origin)
        where += '.raw'
        k = ev['ev']
        need = timeline.EVENTS.get(k)
        if need is None:
            self.fail('E1', where, 'unknown low-level ev %r' % (k,), t)
        missing = [f for f in need if f not in ev and not (k == 'request' and f == 'id')
                   and not (k == 'blocklist_order' and f == 'order_id')]
        if missing:
            self.fail('E1', where, 'missing %s' % ', '.join(map(repr, missing)), t)
        if k == 'request':
            if ev['client'] not in w.pop_of_client:
                self.err('E9', where, 'client %r is not a PoP edge port' % (ev['client'],), t,
                         origin)
                return
            if ev['method'] not in timeline.METHODS:
                self.err('E9', where, 'unknown method %r' % (ev['method'],), t, origin)
                return
            self.raw_request_site(t, ev, where, origin)
        elif k in ('link_down', 'link_up'):
            try:
                e.link_index(ev['link'])
            except ValueError as ex:
                self.err('E2', where, str(ex), t, origin)
                return
        elif k == 'blocklist_order':
            n = len(ev.get('add') or ()) + len(ev.get('remove') or ())
            if len(entries_ok(self.report, list(ev.get('add') or ()) +
                              list(ev.get('remove') or ()), where + '.entries', t)) < n:
                return
        elif k == 'server_content' and ev['op'] == 'serve':
            x = w.sites.get(ev['site'])
            if x is not None:
                self.fresh(x, ev['ip'], where, t, origin)
        e.raw(t, ev)

    def raw_request_site(self, t, ev, where, origin):
        """W5: a raw request for an unknown, stopped or unpublished site."""
        x = self.world.sites.get(ev['site'])
        why = ('unknown' if x is None else 'stopped' if x.dead
               else None if ev['method'] == 'direct_ip' or x.name in self.e.dns.records
               else 'unpublished')
        if why:
            self.warn('W5', where, 'request for %s site %r' % (why, ev['site']), t, origin)

    def fresh(self, x, ip, where, t, origin):
        """W4: an address another site has served (not a shared-IP join or a move back)."""
        others = self.e.ever.get(ip, set()) - {x.name}
        if others:
            self.warn('W4', where, '%s moves to %s, already used by %s'
                      % (x.name, ip, ', '.join(sorted(others))), t, origin)

    def fast_flux(self, it, origin, where):
        e = self.e
        x = self.site(it['site'], where)
        ips = it.get('ips')
        auto = ips is None
        if auto:
            ips = FluxAddresses(self, x.name)
        if it['overlap_s'] < x.ttl:
            self.warn('W3', where, 'overlap_s %s is below the TTL %s: cached answers fail'
                      % (it['overlap_s'], x.ttl), it['t'], origin)
        for ip in [] if auto else ips:
            if self.plan.kind(ip) != 'external':
                self.err('E4', where, 'fast-flux address %s is not external' % ip,
                         it['t'], origin)
        k = 0
        left = [where, origin, x, ips, 0]

        def fire(t):
            nonlocal k
            if x.dead:
                return
            if not auto and k >= len(ips):
                self.warn('W9', where, 'ips run out at t=%s' % t, t, origin)
                return
            self.fresh(x, ips[k], where, t, origin)
            e.flux_rotate(t, x, ips[k], it['overlap_s'], origin)
            k += 1
            left[4] = k
            e.at(t + it['rotate_s'], fire, PRIO_FLUX)
        if not auto:
            self.flux_left.append(left)
        e.at(it['t'], fire, PRIO_FLUX)

    def move(self, t, x, ip, it, origin, where):
        """The three move kinds: W10 (comes back), W4 (fresh), W3 (unserve too soon)."""
        if x.dead:
            self.warn('W10', where, '%s was stopped; it comes back' % x.name, t, origin)
            x.dead, x.primary = False, None
        self.fresh(x, ip, where, t, origin)
        after = it.get('unserve_after_s')
        if after is not None and after < x.ttl + UNSERVE_MARGIN_S:
            self.warn('W3', where, 'unserve_after_s %s is below ttl + %d'
                      % (after, UNSERVE_MARGIN_S), t, origin)
        self.e.move(t, x, ip, origin, after)

    def ev_bgp_change(self, t, it, origin, where):
        if it['prefix'] not in {str(n) for n in self.world.external}:
            self.err('E5', where, '%s is not an external prefix' % it['prefix'], t, origin)
        elif it['to'] not in self.world.exits:
            self.err('E5', where, '%s is not an exit edge port' % it['to'], t, origin)
        else:
            self.e.route_change(t, it['prefix'], it['to'], origin)

    def ev_dns_change(self, t, it, origin, where):
        x = self.site(it['site'], where)
        if not self.plan.agrees(x.hosting, it['ip']):
            self.err('E4', where, '%s is %s, not %s like %s' % (
                it['ip'], self.plan.kind(it['ip']) or 'not a server address', x.hosting,
                x.name), t, origin)
        self.move(t, x, it['ip'], it, origin, where)

    def ev_shared_ip_join(self, t, it, origin, where):
        onto = self.site(it['onto'], where)
        x = self.site(it['site'], where)
        x.hosting = onto.hosting
        if x.dead:
            self.warn('W10', where, '%s was stopped; it comes back' % x.name, t, origin)
            x.dead, x.primary = False, None
        after = it.get('unserve_after_s')
        if after is not None and after < x.ttl + UNSERVE_MARGIN_S:
            self.warn('W3', where, 'unserve_after_s %s is below ttl + %d'
                      % (after, UNSERVE_MARGIN_S), t, origin)
        self.e.move(t, x, onto.primary, origin, after)

    def ev_start_blocked(self, t, it, origin, where):
        x = self.site(it['site'], where)
        x.hosting = 'domestic'
        if self.plan.kind(it['ip']) != 'domestic':
            self.err('E4', where, '%s is not a domestic address (a PoP /16 address no '
                     'subscriber uses)' % it['ip'], t, origin)
        self.move(t, x, it['ip'], it, origin, where)

    def ev_mirror(self, t, it, origin, where):
        w = self.world
        if it['name'] in w.sites:
            self.fail('E2', where, 'site %r already exists' % it['name'], t)
        if it['org'] in w.orgs:
            self.fail('E2', where, 'org %r already exists' % it['org'], t)
        if not dns_name_ok(it['name']):
            self.fail('E1', where, 'site name %r is not a lowercase DNS name' % it['name'], t)
        src = self.site(it['of'], where)
        if self.plan.kind(it['ip']) != 'external':
            self.err('E4', where, 'mirror address %s is not external' % it['ip'], t, origin)
        if self.e.ever.get(it['ip']):
            self.warn('W4', where, 'mirror at %s, already used by %s' % (
                it['ip'], ', '.join(sorted(self.e.ever[it['ip']]))), t, origin)
        self.e.mirror(t, src, it['name'], it['org'], it['ip'],
                      it.get('dns_delay_s') or 0, origin)

    def ev_stop(self, t, it, origin, where):
        self.e.stop(t, self.site(it['site'], where), origin)

    def ev_blocklist_order(self, t, it, origin, where):
        add = self.entries(it.get('add') or [], where + '.add')
        remove = self.entries(it.get('remove') or [], where + '.remove')
        ok = (len(entries_ok(self.report, add, where + '.add', t)) == len(add)
              and len(entries_ok(self.report, remove, where + '.remove', t)) == len(remove))
        if ok:
            self.e.order(t, add, remove, origin, it.get('order_id'))

    def ev_add_site(self, t, it, origin, where):
        w, s = self.world, it['site']
        where += '.site'
        if s['name'] in w.sites:
            self.fail('E2', where, 'site %r already exists' % s['name'], t)
        if not dns_name_ok(s['name']):
            self.fail('E1', where, 'site name %r is not a lowercase DNS name' % s['name'], t)
        if it['org'] in w.orgs:
            same = next((x for x in w.sites.values() if x.org == it['org']), None)
            if same is not None and same.targeted != it['targeted']:
                self.fail('E2', where, 'org %s is %s' % (
                    it['org'], 'targeted' if same.targeted else 'not targeted'), t)
        x = Site(s['name'], it['org'], s.get('content', s['name']), it['targeted'],
                 s['hosting'], s['ttl'])
        x.primary = s['ip']
        x.cache_ips = dict(s.get('cache_ips') or {})
        x.flux = bool(s.get('flux'))
        self.site_address(x, where)
        for ip in [x.primary] + list(x.cache_ips.values()):
            if self.e.ever.get(ip):
                self.warn('W4', where, '%s at %s, already used by %s' % (
                    x.name, ip, ', '.join(sorted(self.e.ever[ip]))), t, origin)
        if 'serve' in s or 'dns' in s:
            self.fail('E1', where, 'serve / dns overrides are for world sites only', t)
        if it.get('weight') is not None:
            self.e.popularity[x.content] = float(it['weight'])
        self.e.add_site(t, x, it.get('dns_delay_s') or 0, origin)

    def ev_flash_crowd(self, t, it, origin, where):
        if it['pop'] not in {p.name for p in self.world.pops}:
            self.fail('E2', where, 'unknown pop %r' % (it['pop'],), t)
        if it.get('site') is not None:
            self.site(it['site'], where)
        if it['factor'] <= 1:
            self.warn('W8', where, 'factor %s adds no requests' % it['factor'], t, origin)
        self.e.flash(t, it['pop'], it.get('site'), it['factor'], it['duration_s'], origin)

    def ev_link_failure(self, t, it, origin, where):
        try:
            self.e.link_index(it['link'])
        except ValueError as ex:
            self.fail('E2', where, str(ex), t)
        self.e.link_failure(t, it['link'], it['duration_s'], origin)

    # ---- run --------------------------------------------------------
    def run(self):
        """(header, events). Raises CompileError if any check failed; self.report has
        every finding."""
        self.build_world()
        self.schedule()
        self.e.start_demand()
        events = self.e.drain()
        for where, origin, x, ips, used in self.flux_left:
            if used < len(ips) and not x.dead:
                self.warn('W1', where, '%d of %d fast-flux ips fall after duration_s'
                          % (len(ips) - used, len(ips)), origin=origin)
        self.popularity_refs()
        sha = hl.canonical_sha256(dict(self.doc, seed=self.seed))
        header = self.e.header(VERSION, sha)
        check.check_timeline(self.report, header, events, self.world, self.topo, self.e)
        load = check.load_estimate(self.e)
        self.report.info['load_req_per_s'] = round(load, 1)
        if check.LOAD_WARN_REQ_S is not None and load > check.LOAD_WARN_REQ_S:
            self.warn('W11', 'demand', 'peak load %.0f req/s is above %d'
                      % (load, check.LOAD_WARN_REQ_S))
        self.report.info['hl_sha256'] = sha
        if self.report.total('E'):
            raise CompileError('%d errors; first: %s' % (
                self.report.total('E'), self.report.lines()[0]), self.report)
        return header, events


def mentioned_ips(doc):
    """Addresses the HL file names anywhere, plus the networks of its `ip` entries."""
    out = set()

    def walk(v):
        if isinstance(v, dict):
            if v.get('type') == 'ip' and isinstance(v.get('value'), str):
                try:
                    out.add(ipaddress.IPv4Network(v['value'], strict=False))
                except ValueError:
                    pass
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str) and v[:1].isdigit() and '/' not in v:
            try:
                out.add(ipaddress.IPv4Network(v))
            except ValueError:
                pass
    walk(doc.get('world'))
    walk(doc.get('events'))
    return out


class FluxAddresses:
    """Rotation addresses for a fast_flux item without `ips`: fresh external addresses,
    the k-th one fixed by a hash of (site, k). It uses no random state, so it stays
    put when the seed or other items change. Skips every address the file names (and
    networks it lists), every address a site has served, and the endpoint host numbers."""

    def __init__(self, c, site):
        self.c, self.site, self.got = c, site, []

    def __getitem__(self, k):
        while len(self.got) <= k:
            self.got.append(self.next(len(self.got)))
        return self.got[k]

    def next(self, k):
        c = self.c
        nets = c.world.external
        taken = {e.ip for e in [c.world.auth_dns] + c.world.endpoints}
        taken.update(self.got)
        for attempt in range(100000):
            h = hashlib.sha256(('flux:%s:%d:%d' % (self.site, k, attempt)).encode()).digest()
            net = nets[int.from_bytes(h[:4], 'big') % len(nets)]
            host = 1 + int.from_bytes(h[4:6], 'big') % 254
            if host in (10, 53):
                continue
            ip = str(net.network_address + host)
            a = ipaddress.IPv4Address(ip)
            if ip in taken or c.e.ever.get(ip) or any(a in n for n in c.mentioned):
                continue
            return ip
        c.fail('E4', 'fast_flux', 'no free external address for %s' % self.site)


def compile_scenario(scenario, seed=None, topo=None):
    """(header, events) from an HL document or the path of a scenario.hl.yaml."""
    doc = scenario if isinstance(scenario, dict) else hl.load(scenario)
    return Compiler(doc, topo, seed).run()


def check_path(out):
    """runs/x/scenario.jsonl -> runs/x/scenario.check.json"""
    base = out[:-len('.jsonl')] if out.endswith('.jsonl') else out
    return base + '.check.json'


def write_report(path, report, **extra):
    with open(path, 'w') as f:
        json.dump(report.to_json(**extra), f, indent=1)
        f.write('\n')


def main(argv=None):
    ap = argparse.ArgumentParser(prog='python -m kit.sim.compile', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('scenario', help='scenario.hl.yaml')
    ap.add_argument('-o', '--out', required=True)
    ap.add_argument('--seed', type=int, help='request-sampling seed (default: the file\'s)')
    ap.add_argument('--check', help='check report (default: <out>.check.json)')
    args = ap.parse_args(argv)
    name = os.path.basename(args.scenario)
    rpath = args.check or check_path(args.out)
    try:
        doc = hl.load(args.scenario)
    except hl.HLError as ex:
        sys.exit('%s: E1 %s' % (name, ex))
    c = None
    try:
        c = Compiler(doc, seed=args.seed)
        header, events = c.run()
    except CompileError as ex:
        if ex.report is not None:
            write_report(rpath, ex.report, scenario=name)
            print('\n'.join(ex.report.lines()), file=sys.stderr)
        sys.exit('%s: %s (report: %s)' % (name, ex, rpath))
    timeline.validate(header, events)
    timeline.write(args.out, header, events)
    write_report(rpath, c.report, scenario=name)
    for line in c.report.lines():
        print(line, file=sys.stderr)
    summary = ', '.join('%s=%d' % kv for kv in sorted(c.e.counts.items()))
    print('%s: %d events (%s); %d warnings (%s)' % (
        args.out, len(events), summary, c.report.total('W'), rpath), file=sys.stderr)


if __name__ == '__main__':
    main()
