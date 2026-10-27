"""Scenario engine: run state and low-level expansion (simulator.md §8).

The engine is a discrete-event simulation that holds the state the run will
have: authoritative DNS, resolver and endpoint caches, server content,
blocklist, prefix locations, links, sites and flash crowds. Its expanders
turn one high-level step (a move, a fast-flux rotation, a mirror, an order,
a TE cycle, a flash crowd) into low-level timeline events. It also samples
requests and fills in each request's `expect_ip`.

The engine makes no random decision of its own. The caller decides which
site, which address and when, and the engine expands that decision. Request
sampling uses per-process RNGs seeded from (seed, name).
"""

import dataclasses
import hashlib
import heapq
import math
import random
from collections import defaultdict, deque

from kit.routing import BaselineRouting, shortest_path_tree
from kit.sim import timeline
from kit.sim.blocklist import Blocklist
from kit.sim.dnsmodel import DnsState, ResolverCache
from kit.sim.world import Site

UNSERVE_MARGIN_S = 5      # old IP keeps serving this long after the last cached answer
# Order of work due at the same t: deferred state parts (an unserve, a link_up, a
# delayed record, a TE application), then high-level steps in file order, then TE
# notices, then fast-flux rotations, then requests.
PRIO_STATE, PRIO_PROCESS, PRIO_TE, PRIO_FLUX, PRIO_REQUEST = 0, 1, 2, 3, 4
# Hosts apply a state change a few ms apart, while truth assumes it came first, so a
# request keeps this far behind the changes it depends on (check W12).
DEP_GAP_S = 0.05


def process_rng(seed, name):
    h = hashlib.sha256(('%s:%s' % (seed, name)).encode()).digest()
    return random.Random(int.from_bytes(h[:8], 'big'))


def rt(t):
    return round(t, 3)


def popularity(model):
    """{content: weight} in ranking order, from HL demand.popularity."""
    if model['dist'] == 'weights':
        return {c: float(w) for c, w in model['weights'].items()}
    s = model.get('s', 1.0) if model['dist'] == 'zipf' else 0.0
    return {c: 1.0 / (r + 1) ** s for r, c in enumerate(model['ranking'])}


def apply_segment(p, s, pop, d):
    """Apply one demand segment to the parameters p (simulator.md §8.3)."""
    if 'rate_per_s' in s:
        r = s['rate_per_s']
        p['rate'] = float(r.get(pop, p['rate']) if isinstance(r, dict) else r)
    elif 'rate_scale' in s:
        p['rate'] *= s['rate_scale']
    if 'methods' in s:
        p['methods'] = s['methods']
    if 'size_bytes' in s:
        p['size_bytes'] = dict(p['size_bytes'], **s['size_bytes'])
    for k in ('split_host', 'large_header'):
        if k in s:
            p[k] = s[k]
    return p


class Recent:
    """Recent state changes that a request can depend on (check W12).

    A request depends on: a dns_record or server_content for its site; a
    server_content at its expect_ip or endpoint IP; a route_change of the
    prefix holding one of them; an order whose added or removed entries
    match it. Changes at t <= 0 do not count: the runtime applies them in the
    bootstrap phase, before the clock starts.
    """

    def __init__(self, world):
        self.world = world
        self.last_t = {}                    # key -> time of the last change
        self.orders = deque()               # (t, Blocklist of the entries an order touched)

    def note(self, ev):
        k, t = ev['ev'], ev['t']
        if t <= 0:
            return
        if k == 'dns_record':
            self.last_t[('site', ev['domain'])] = t
        elif k == 'server_content':
            self.last_t[('site', ev['site'])] = t
            self.last_t[('ip', ev['ip'])] = t
        elif k == 'route_change':
            self.last_t[('prefix', str(ev['prefix']))] = t
        elif k == 'blocklist_order':
            bl = Blocklist()
            bl.apply_order('-', list(ev.get('add') or ()) + list(ev.get('remove') or ()))
            self.orders.append((t, bl))

    def last(self, req):
        """Time of the latest change `req` depends on, or None."""
        t = req['t']
        while self.orders and self.orders[0][0] < t - DEP_GAP_S:
            self.orders.popleft()
        ep = req.get('endpoint')
        ips = [ip for ip in (req.get('expect_ip'), ep) if ip]
        keys = [('site', req['site'])] + [('ip', ip) for ip in ips]
        for ip in ips:
            net = self.world.prefix_of(ip)
            if net is not None:
                keys.append(('prefix', str(net)))
        out = max((self.last_t[k] for k in keys if k in self.last_t), default=None)
        endpoint = None
        if ep:
            e = self.world.endpoint_by_ip(ep)
            endpoint = (ep, e.port if e else None)
        for ot, bl in self.orders:
            if bl.match(req['site'], ips, endpoint) is not None and (out is None or ot > out):
                out = ot
        return out


class Engine:
    def __init__(self, topo, world, seed, duration_s, demand, metric='hops',
                 tie_break='link_order'):
        self.topo = topo
        self.world = world
        self.seed = seed
        self.duration = float(duration_s)
        self.demand = demand                     # HL demand model (simulator.md §8.3)
        self.metric = metric
        self.tie_break = tie_break
        self.routing = BaselineRouting(topo, metric, tie_break=tie_break)
        self.dns = DnsState()
        self.resolver = ResolverCache(use_pop=True)
        # (endpoint ip, exit host) -> ResolverCache. The runtime runs an endpoint on
        # whichever host its prefix is routed to, each with its own cache; caches are
        # never flushed, so a prefix that moves back finds its old cache.
        self.ext_caches = {}
        self.serving = defaultdict(set)          # site -> {ip}
        self.ip_sites = defaultdict(set)         # ip -> {site}
        self.ever = defaultdict(set)             # ip -> {site that has served there}
        self.recent = Recent(world)
        self.last_ip = {}                        # site -> last ip it was served at
        self.client_cache = {}                   # (client, site) -> last answer
        self.blocklist = Blocklist()
        self.down = set()                        # link indices
        self.flashes = []                        # [(pop, site, factor, start, end)]
        self.cache_views = defaultdict(list)     # cache host -> [PoP]
        self.popularity = {}                     # content -> weight
        self.initial_prefixes = []
        self.events = []
        self.heap = []
        self._n = 0
        self._req = 0
        self._order = 0
        self._te = 0
        self.counts = defaultdict(int)

    # ---- plumbing ---------------------------------------------------
    def rng(self, name):
        return process_rng(self.seed, name)

    def at(self, t, fn, prio=PRIO_PROCESS):
        t = rt(t)
        if t <= self.duration:
            self._n += 1
            heapq.heappush(self.heap, (t, prio, self._n, fn))

    def later(self, t, ev):
        """Emit a low-level event at time t (if it is inside the run)."""
        self.at(t, lambda now: self.emit(now, dict(ev)), PRIO_STATE)

    def emit(self, t, ev):
        ev = dict(ev)
        ev['t'] = rt(t)
        self.apply(ev)
        if ev['ev'] != 'request':
            self.recent.note(ev)
        self.events.append(ev)
        self.counts[ev['ev']] += 1
        return ev

    def apply(self, ev):
        """State change for a low-level event (also for raw events)."""
        k = ev['ev']
        if k == 'dns_record':
            self.dns.apply(ev)
        elif k == 'server_content':
            site, ip = ev['site'], ev['ip']
            if ev['op'] == 'serve':
                self.serving[site].add(ip)
                self.ip_sites[ip].add(site)
                self.ever[ip].add(site)
                self.last_ip[site] = ip
            else:
                self.serving[site].discard(ip)
                self.ip_sites[ip].discard(site)
        elif k == 'blocklist_order':
            self.blocklist.apply_order(ev['order_id'], ev.get('add', ()), ev.get('remove', ()))
        elif k == 'route_change':
            net = self.world.prefix_of(ev['prefix'].split('/')[0])
            if net is not None:
                self.world.location[net] = ev['to']
        elif k in ('link_down', 'link_up'):
            idx = self.link_index(ev['link'])
            (self.down.add if k == 'link_down' else self.down.discard)(idx)

    def poisson(self, name, mean, fn):
        """Run fn(t, rng) at Poisson times with the given mean interval."""
        if mean is None:
            return
        rng = self.rng(name)

        def fire(t):
            fn(t, rng)
            self.at(t + rng.expovariate(1.0 / mean), fire)
        self.at(rng.expovariate(1.0 / mean), fire)

    def drain(self):
        """Play the heap to the end; (header-less) sorted events."""
        while self.heap:
            t, _, _, fn = heapq.heappop(self.heap)
            fn(t)
        return timeline.sort_events(self.events)

    def link_name(self, link):
        return '%s-%s' % (link.a, link.b)

    def link_index(self, name):
        a, b = name.split('-')
        for l in self.topo.links:
            if {l.a, l.b} == {a, b}:
                return l.index
        raise ValueError('unknown link %r' % name)

    # ---- queries ----------------------------------------------------
    def live_sites(self, pred=lambda x: True):
        return [x for x in self.world.sites.values() if not x.dead and pred(x)]

    def listed(self, x):
        return self.blocklist.match(x.name, [x.primary]) is not None

    def unlisted_targets(self):
        return self.live_sites(lambda x: x.targeted and not self.listed(x))

    def ip_is_exclusive(self, x):
        """No allowed (untargeted) site is served at x's primary IP."""
        return all(self.world.sites[s].targeted for s in self.ip_sites.get(x.primary, ())
                   if s in self.world.sites)

    def site_entry(self, x, kind):
        if kind == 'suffix':
            return {'type': 'suffix', 'value': x.org}
        if kind == 'ip' and x.hosting != 'cache' and self.ip_is_exclusive(x):
            return {'type': 'ip', 'value': x.primary}
        return {'type': 'domain', 'value': x.name}

    def endpoint_entry(self, e):
        return {'type': 'endpoint', 'kind': e.kind, 'ip': e.ip, 'port': e.port, 'id': e.id}

    def bridges(self):
        """Indices of active links whose loss would split the switch graph."""
        active = [l for l in self.topo.links if l.index not in self.down]
        out = set()
        for l in active:
            topo = dataclasses.replace(self.topo, links=[x for x in active if x is not l])
            start = l.a
            seen, stack = {start}, [start]
            while stack:
                for n, _ in topo.neighbors(stack.pop()):
                    if n not in seen:
                        seen.add(n)
                        stack.append(n)
            if l.b not in seen:
                out.add(l.index)
        return out

    # ---- world and DNS expanders --------------------------------------
    def record(self, x):
        ev = {'ev': 'dns_record', 'op': 'set', 'domain': x.name, 'ips': [x.primary],
              'ttl': x.ttl}
        if x.cache_ips:
            ev['views'] = [{'view': c.lower(), 'pops': sorted(self.cache_views[c]),
                            'ips': [ip]} for c, ip in x.cache_ips.items()]
        return ev

    def publish(self, t, x, dns_at=None, origin=None):
        """Serve x at all its IPs now; publish its record now or at dns_at."""
        extra = {'origin': origin} if origin else {}
        for ip in [x.primary] + list(x.cache_ips.values()):
            self.emit(t, dict({'ev': 'server_content', 'op': 'serve', 'site': x.name,
                               'ip': ip}, **extra))
        rec = dict(self.record(x), **extra)
        if dns_at is None or dns_at <= t:
            self.emit(t, rec)
        else:
            self.later(dns_at, rec)

    def move(self, t, x, new_ip, origin, unserve_after=None):
        """Same content at a new primary IP: serve, re-point DNS, unserve the old one later
        (by default once the last cached answer has expired)."""
        old = x.primary
        x.primary = new_ip
        o = {'origin': origin}
        self.emit(t, dict({'ev': 'server_content', 'op': 'serve', 'site': x.name,
                           'ip': new_ip}, **o))
        self.emit(t, dict(self.record(x), **o))
        if old and old != new_ip:
            if unserve_after is None:
                unserve_after = x.ttl + UNSERVE_MARGIN_S
            self.later(t + unserve_after,
                       dict({'ev': 'server_content', 'op': 'unserve', 'site': x.name,
                             'ip': old}, **o))

    def flux_rotate(self, t, x, new_ip, overlap, origin):
        """One fast-flux rotation: serve and publish new_ip, unserve the old IP after overlap."""
        old = x.primary
        x.primary = new_ip
        o = {'origin': origin}
        self.emit(t, dict({'ev': 'server_content', 'op': 'serve',
                           'site': x.name, 'ip': x.primary}, **o))
        self.emit(t, dict(self.record(x), **o))
        self.later(t + overlap, dict({'ev': 'server_content', 'op': 'unserve',
                                      'site': x.name, 'ip': old}, **o))

    def add_site(self, t, x, dns_delay, origin):
        """A site that appears mid-run: served at t, published at t + dns_delay."""
        w = self.world
        if x.org not in w.orgs:
            w.orgs.append(x.org)
        w.sites[x.name] = x
        self.publish(t, x, dns_at=t + dns_delay, origin=origin)
        return x

    def mirror(self, t, src, name, org, ip, dns_delay, origin):
        """A new targeted site with src's content: served at t, published at t + dns_delay."""
        m = Site(name, org, src.content, True, 'external', src.ttl, mirror_of=src.name)
        m.primary = ip
        return self.add_site(t, m, dns_delay, origin)

    def stop(self, t, x, origin):
        """x stops serving everywhere and its record is removed."""
        x.dead = True
        o = {'origin': origin}
        for ip in sorted(self.serving[x.name]):
            self.emit(t, dict({'ev': 'server_content', 'op': 'unserve', 'site': x.name,
                               'ip': ip}, **o))
        self.emit(t, dict({'ev': 'dns_record', 'op': 'remove', 'domain': x.name}, **o))

    def order(self, t, add=(), remove=(), origin=None, order_id=None):
        if not add and not remove:
            return
        if order_id is None:
            self._order += 1
            order_id = 'o%04d' % self._order
        ev = {'ev': 'blocklist_order', 'order_id': order_id,
              'add': list(add), 'remove': list(remove)}
        if origin:
            ev['origin'] = origin
        self.emit(t, ev)

    # ---- ISP expanders ----------------------------------------------
    def route_change(self, t, prefix, to, origin):
        self.emit(t, {'ev': 'route_change', 'prefix': prefix, 'to': to, 'origin': origin})

    def link_failure(self, t, name, duration, origin):
        self.emit(t, {'ev': 'link_down', 'link': name, 'origin': origin})
        self.later(t + duration, {'ev': 'link_up', 'link': name, 'origin': origin})

    def params(self, pop, t):
        """Demand parameters for `pop` at t: the base model with the segments that cover
        (pop, t) applied in file order (later ones win)."""
        d = self.demand
        out = {'rate': d['rate_per_s'].get(pop, 0.0), 'methods': d['methods'],
               'size_bytes': d['size_bytes'], 'split_host': d['split_host'],
               'large_header': d['large_header']}
        for s in d.get('segments') or ():
            if s['from_s'] <= t < s['to_s'] and pop in s.get('pops', (pop,)):
                apply_segment(out, s, pop, d)
        return out

    def peak_rate(self, pop):
        """Largest rate `pop` has at any time, before the diurnal curve. The rate only
        changes at segment edges, so those are the points to look at."""
        edges = {0.0}
        for s in self.demand.get('segments') or ():
            edges.update((s['from_s'], s['to_s']))
        return max(self.params(pop, t)['rate'] for t in edges if t <= self.duration)

    def pop_rate(self, pop, t):
        d = self.demand
        rate = self.params(pop, t)['rate']
        di = d['diurnal']
        if di.get('period_s'):
            rate *= 1 + di.get('amplitude', 0) * math.sin(2 * math.pi * t / di['period_s'])
        return max(rate, 0.0)

    def demand_matrix(self, t):
        """{(pop switch, location switch): expected bytes/s} from the demand model."""
        w = self.world
        names = defaultdict(list)
        for x in self.live_sites():
            if x.name in self.dns.records:
                names[x.content].append(x.name)
        total = sum(self.popularity.get(c, 0) for c in names) or 1.0
        out = defaultdict(float)
        for p in w.pops:
            r = self.pop_rate(p.name, t)
            sz = self.params(p.name, t)['size_bytes']
            mean = sz['median'] * math.exp(sz['sigma'] ** 2 / 2)
            items = [(n, self.popularity.get(c, 0) / total / len(ns) * r)
                     for c, ns in names.items() for n in ns]
            items += [(s, (f - 1) * r) for fp, s, f, a, b in self.flashes
                      if fp == p.name and a <= t < b]
            for n, rate in items:
                a = self.dns.answer(n, p.name)
                host = w.locate(a.ips[0]) if a and a.ips else None
                if host is not None:
                    out[(p.name, self.topo.hosts[host].switch)] += rate * mean
        return out

    def te_weights(self, t):
        """TE weights: 1 + round(4 * load / max load) per link, load on baseline paths."""
        active = [l for l in self.topo.links if l.index not in self.down]
        topo = dataclasses.replace(self.topo, links=active)
        load = defaultdict(float)
        trees = {}
        for (pop, loc), b in self.demand_matrix(t).items():
            if pop not in trees:
                trees[pop] = shortest_path_tree(topo, pop, self.metric, self.tie_break)[0]
            node = loc
            while node != pop:
                nxt, link = trees[pop][node]
                load[link.index] += b
                node = nxt
        mx = max(load.values(), default=0)
        return {self.link_name(l): 1 + (round(4 * load[l.index] / mx) if mx else 0)
                for l in active}

    def te_cycle(self, t, apply_at, weights=None, origin='te'):
        """te_notice at t; te_reoptimize at apply_at, with the given weights or else the
        demand-model weights of that moment."""
        self._te += 1
        te_id = 'te%03d' % self._te
        apply_at = rt(apply_at)
        if apply_at <= self.duration:
            self.emit(t, {'ev': 'te_notice', 'te_id': te_id, 'apply_at': apply_at,
                          'origin': origin})
            self.at(apply_at, lambda now: self.emit(
                now, {'ev': 'te_reoptimize', 'te_id': te_id,
                      'weights': dict(weights) if weights else self.te_weights(now),
                      'origin': origin}), PRIO_STATE)

    # ---- demand -----------------------------------------------------
    def draw_request(self, rng, pop, t):
        """Attributes drawn up front (state-independent), resolved at fire time."""
        d = self.demand
        p = self.params(pop, t)
        methods = p['methods']
        m = rng.choices(list(methods), weights=list(methods.values()))[0]
        sz = p['size_bytes']
        size = int(sz['median'] * math.exp(sz['sigma'] * rng.gauss(0, 1)))
        return {
            'sub': rng.randrange(d['subscribers_per_pop']),
            'u_content': rng.random(), 'u_name': rng.random(), 'u_ip': rng.random(),
            'u_ep': rng.random(),
            'method': m,
            'size': max(100, min(size, sz.get('max') or size)),
            'split_host': rng.random() < p['split_host'],
            'large_header': rng.random() < p['large_header'],
        }

    def pick_content(self, u):
        live = defaultdict(list)
        for x in self.live_sites():
            live[x.content].append(x)
        cs = [c for c in self.popularity if c in live]
        if not cs:
            return None, []
        total = sum(self.popularity[c] for c in cs)
        acc, target = 0.0, u * total
        for c in cs:
            acc += self.popularity[c]
            if acc >= target:
                return c, live[c]
        return cs[-1], live[cs[-1]]

    def request(self, t, pop, a, site=None, origin=None):
        """One sampled request. If it would land within DEP_GAP_S of a state change it
        depends on, it is drawn again (same attributes) once that gap has passed.
        Requests come strictly after t = 0, the end of the bootstrap phase."""
        if rt(t) <= 0:
            t = 0.001
        p = next(x for x in self.world.pops if x.name == pop)
        ev = {'ev': 'request', 'client': p.client,
              'src_ip': self.world.subscriber_ips(p)[a['sub']]}
        method = a['method']
        name = site
        if name is None:
            _, xs = self.pick_content(a['u_content'])
            if not xs:
                return
            if method != 'direct_ip':
                # nobody looks up a name that is not published yet (an added site
                # during its dns delay); such a draw makes no request
                xs = [x for x in xs if x.name in self.dns.records]
                if not xs:
                    return
            name = xs[min(int(a['u_name'] * len(xs)), len(xs) - 1)].name
        ev['site'] = name
        probe = dict(ev, t=rt(t))
        self.resolve(t, probe, pop, method, a, commit=False)
        d = self.recent.last(probe)
        if d is not None and rt(t) - d < DEP_GAP_S - 1e-9:
            self.at(d + DEP_GAP_S, lambda now: self.request(now, pop, a, site, origin),
                    PRIO_REQUEST)
            return
        self.resolve(t, ev, pop, method, a)
        ev.update(size=a['size'], split_host=a['split_host'], large_header=a['large_header'])
        if origin:
            ev['origin'] = origin
        self._req += 1
        ev['id'] = 'r%06d' % self._req
        self.emit(t, ev)

    def cached(self, cache, site, t, pop, commit):
        """cache.resolve(), or with commit=False the same answer without touching it."""
        if commit:
            return cache.resolve(self.dns, site, t, pop)[0]
        hit = cache.lookup(site, t, pop)
        if hit is not None:
            return hit[0].ips
        a = self.dns.answer(site.lower().rstrip('.'), pop if cache.use_pop else None)
        return a.ips if a else None

    def resolve(self, t, ev, pop, method, a, commit=True):
        """Fill in method, expect_ip (and endpoint, fallback_from). commit=False leaves
        the resolver, endpoint and client caches as they are."""
        site, client = ev['site'], ev['client']
        if method == 'stale_cache':
            ip = self.client_cache.get((client, site))
            if ip is None:
                method = 'dns'
                ev['fallback_from'] = 'stale_cache'
            else:
                ev['method'] = 'stale_cache'
                ev['expect_ip'] = ip
                return
        if method in ('ext_resolver', 'encrypted_dns'):
            eps = self.world.endpoints_of(method)
            if not eps and not ev.get('endpoint'):
                ev['fallback_from'] = method
                method = 'dns'
            else:
                # a raw request keeps the endpoint it names
                ip = ev.get('endpoint') or eps[min(int(a['u_ep'] * len(eps)), len(eps) - 1)].ip
                ev['endpoint'] = ip
                key = (ip, self.world.locate(ip))
                cache = self.ext_caches.get(key) or ResolverCache(use_pop=False)
                if commit:
                    self.ext_caches[key] = cache
                ips = self.cached(cache, site, t, None, commit)
                ev['method'] = method
                ev['expect_ip'] = ips[0] if ips else None
                if ips and commit:
                    self.client_cache[(client, site)] = ips[0]
                return
        if method == 'direct_ip':
            ips = sorted(self.serving.get(site, ()))
            ev['method'] = 'direct_ip'
            ev['expect_ip'] = (ips[min(int(a['u_ip'] * len(ips)), len(ips) - 1)] if ips
                               else self.last_ip.get(site))
            return
        ips = self.cached(self.resolver, site, t, pop, commit)
        ev['method'] = 'dns'
        ev['expect_ip'] = ips[0] if ips else None
        if ips and commit:
            self.client_cache[(client, site)] = ips[0]

    def start_demand(self):
        """One Poisson request stream per PoP, thinned by the diurnal curve."""
        d = self.demand
        amp = d['diurnal'].get('amplitude', 0) if d['diurnal'].get('period_s') else 0
        for p in self.world.pops:
            rng = self.rng('demand:' + p.client)
            peak = self.peak_rate(p.name) * (1 + amp)
            if peak <= 0:
                continue

            fire = self._demand_fire(p.name, rng, peak)
            self.at(rng.expovariate(peak), fire, PRIO_REQUEST)

    def _demand_fire(self, pop, rng, peak):
        def fire(t):
            # thinning for the diurnal curve; draws are consumed either way
            accept = rng.random() * peak < self.pop_rate(pop, t)
            a = self.draw_request(rng, pop, t)
            if accept:
                self.request(t, pop, a)
            self.at(t + rng.expovariate(peak), fire, PRIO_REQUEST)
        return fire

    def flash(self, t, pop, site, factor, duration, origin):
        """One PoP's rate becomes `factor` x normal for `duration`; the extra goes to site.
        With no site, one published site is drawn by popularity."""
        if site is None:
            rs = self.rng('flash:%s:%s:' % (pop, rt(t)))
            _, xs = self.pick_content(rs.random())
            pub = [x for x in xs if x.name in self.dns.records]
            if not pub:
                return
            site = rs.choice(pub).name
        self.flashes.append((pop, site, factor, t, t + duration))
        rate = (factor - 1) * self.pop_rate(pop, t)
        if rate <= 0:
            return
        # The burst's requests have their own RNG, keyed by the flash itself, so they
        # can be drawn again from (pop, t, site) alone.
        rr = self.rng('flash:%s:%s:%s' % (pop, rt(t), site))
        tt = t + rr.expovariate(rate)
        while rt(tt) < t + duration:
            a = self.draw_request(rr, pop, rt(tt))
            self.at(tt, lambda now, a=a: self.request(now, pop, a, site=site, origin=origin),
                    PRIO_REQUEST)
            tt += rr.expovariate(rate)

    def raw(self, t, ev):
        """A low-level event as given; a request gets id/expect_ip, an order an order_id."""
        if ev['ev'] == 'request':
            if 'id' not in ev:
                self._req += 1
                ev['id'] = 'r%06d' % self._req
            if 'expect_ip' not in ev:
                pop = self.world.pop_of_client[ev['client']].name
                self.resolve(t, ev, pop, ev['method'], {'u_ep': 0.0, 'u_ip': 0.0})
        elif ev['ev'] == 'blocklist_order' and 'order_id' not in ev:
            self._order += 1
            ev['order_id'] = 'o%04d' % self._order
        self.emit(t, ev)

    # ---- header -----------------------------------------------------
    def snapshot_prefixes(self):
        """Record the prefix locations at t = 0 for the header."""
        self.initial_prefixes = self.world.header_prefixes()

    def header(self, generator, config_sha256):
        w = self.world
        eps = [w.auth_dns] + w.endpoints
        return {
            'type': 'header', 'format': timeline.FORMAT, 'seed': self.seed,
            'duration_s': self.duration, 'topology': self.topo.name,
            'config_sha256': config_sha256,
            'generator': generator,
            'pops': [{'pop': p.name, 'client': p.client, 'prefix': str(p.prefix)}
                     for p in w.pops],
            'resolver': ({'host': w.resolver.id, 'ip': str(w.resolver.ip)}
                         if w.resolver else None),
            'prefixes': [dict(p) for p in self.initial_prefixes],
            'endpoints': [{'id': e.id, 'kind': e.kind, 'ip': e.ip, 'port': e.port}
                          for e in eps],
        }
