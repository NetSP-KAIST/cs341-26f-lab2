"""Random scenario writer: `simulator:` config + seed -> scenario.hl.yaml.

    python -m kit.sim.write -c configs/default.yaml -o scenario.hl.yaml [--seed N]

docs/kit/simulator.md §1, §6. The config's random processes run on a
scenario engine (kit.sim.engine), so each one sees the state the compiler
will rebuild. Every decision (which site, which address, which exit, which
entries) is applied to that state and also recorded as a high-level item.
Requests are not written: the HL file describes demand as a model, and the
compiler samples requests from it.

Every process has its own random.Random, seeded from (seed, process name),
so turning one process on or off does not change the draws of the others.
Choices that depend on the world state can still differ, as they should.
"""

import argparse
import copy
import hashlib
import json
import math
import sys
from collections import defaultdict

from kit.config import load_config, load_topology_for
from kit.sim import hl, timeline
from kit.sim.config import sim_config
from kit.sim.engine import PRIO_FLUX, PRIO_PROCESS, PRIO_TE, Engine, popularity, rt
from kit.sim.world import Site, World, WorldError

VERSION = 'kit.sim.write 0.1'


class Writer:
    def __init__(self, cfg, topo, seed=None, duration_s=None):
        self.cfg = cfg
        self.sc = sim_config(cfg)
        self.seed = cfg.get('seed', 0) if seed is None else seed
        self.duration = float(duration_s or self.sc['duration_s'])
        self.topo = topo
        r = cfg['topology'].get('routing', {})
        self.metric = r.get('metric', 'hops')
        self.tie_break = r.get('tie_break', 'link_order')
        self.world = World(topo, self.sc['world'])
        self.world.set_subscribers(self.sc['demand']['subscribers_per_pop'])
        self.e = Engine(topo, self.world, self.seed, self.duration, None,
                        self.metric, self.tie_break)
        self.items = []

    def rng(self, name):
        return self.e.rng(name)

    def item(self, t, ev, origin, **fields):
        it = dict({'t': rt(t), 'ev': ev}, **fields)
        it['origin'] = origin
        self.items.append(it)
        return it

    # ---- world at t = 0 ---------------------------------------------
    def build_world(self):
        e, w, wc = self.e, self.world, self.sc['world']
        rng = self.rng('world')
        w.name_rng = self.rng('names')
        w.assign_exits(rng)
        w.make_endpoints(rng)
        nearest = w.nearest_cache(e.routing) if w.caches else {}
        for pop, c in nearest.items():
            e.cache_views[c].append(pop)
        hosting = dict(wc['hosting'])
        if not w.caches:
            hosting.pop('cache', None)
        kinds = [k for k, v in hosting.items() if v > 0] or ['external']
        lo, hi = wc['sites_per_org']
        ttl = wc['ttl_s']
        for _ in range(wc['orgs']):
            org = w.new_org(rng)
            targeted = rng.random() < wc['targeted_orgs']
            for name in w.site_names(org, rng.randint(lo, hi), rng):
                kind = rng.choices(kinds, weights=[hosting[k] for k in kinds])[0]
                w.sites[name] = Site(name, org, name, targeted, kind, ttl['normal'])
        # popularity: a random rank per content
        self.ranking = list(w.sites)
        rng.shuffle(self.ranking)
        self.demand = self.demand_model()
        e.demand = self.demand
        e.popularity = popularity(self.demand['popularity'])
        # fast flux sites: targeted, not cache hosted
        ff = self.sc['external']['fast_flux'] or {}
        flux_n = ff.get('sites') or 0
        cands = [x for x in w.sites.values() if x.targeted and x.hosting != 'cache']
        for x in rng.sample(cands, min(flux_n, len(cands))):
            x.flux, x.ttl, x.hosting = True, ttl['short'], 'external'
        # addresses: allowed sites first, so targeted ones can share their IPs
        allowed_ips = defaultdict(list)          # hosting -> [ip]
        for x in sorted(w.sites.values(), key=lambda x: x.targeted):
            if (x.targeted and not x.flux and x.hosting != 'cache'
                    and allowed_ips[x.hosting] and rng.random() < wc['shared_ip']):
                x.primary = rng.choice(allowed_ips[x.hosting])
            else:
                x.primary = w.new_ip(x.hosting, rng)
                if not x.targeted:
                    allowed_ips[x.hosting].append(x.primary)
            if x.hosting == 'cache':
                for c in w.caches:
                    if e.cache_views[c]:
                        x.cache_ips[c] = w.alloc(w.cache_prefix[c], rng)
        self.hl_world = self.world_model()
        for x in w.sites.values():
            e.publish(0, x)
        self.hl_world['blocklist'] = self.initial_order(rng)

    def world_model(self):
        """The HL `world` section for the state at t = 0 (before any event)."""
        e, w = self.e, self.world
        orgs = []
        for x in w.sites.values():
            if not orgs or orgs[-1]['org'] != x.org:
                orgs.append({'org': x.org, 'targeted': x.targeted, 'sites': []})
            s = {'name': x.name, 'hosting': x.hosting, 'ip': x.primary, 'ttl': x.ttl}
            if x.cache_ips:
                s['cache_ips'] = dict(x.cache_ips)
            if x.flux:
                s['flux'] = True
            orgs[-1]['sites'].append(s)
        return {
            'external_prefixes': [{'cidr': str(n), 'exit': w.location[n]}
                                  for n in w.external],
            'cache_views': {c: list(e.cache_views[c]) for c in w.caches
                            if e.cache_views.get(c)},
            'endpoints': [{'id': x.id, 'kind': x.kind, 'ip': x.ip, 'port': x.port}
                          for x in [w.auth_dns] + w.endpoints],
            'orgs': orgs,
        }

    def demand_model(self):
        """The HL `demand` section from the config's demand knobs."""
        d = self.sc['demand']
        pw = d['pop_weights'] or {}
        pc = d['popularity']
        pop = {'dist': 'zipf', 's': pc.get('s', 1.0)} if pc['dist'] == 'zipf' \
            else {'dist': 'uniform'}
        pop['ranking'] = list(self.ranking)
        share = pc.get('targeted_share')
        if share is not None:
            pop = {'dist': 'weights', 'weights': self.class_weights(pop, share)}
        return {
            'subscribers_per_pop': d['subscribers_per_pop'],
            'rate_per_s': {p.name: d['requests_per_s_per_pop'] * pw.get(p.name, 1.0)
                           for p in self.world.pops},
            'diurnal': dict(d['diurnal']),
            'popularity': pop,
            'methods': dict(d['methods']),
            'size_bytes': dict(d['size_bytes']),
            'split_host': d['split_host'],
            'large_header': d['large_header'],
        }

    def class_weights(self, model, share):
        """{content: weight}, highest first: the ranking split into targeted and
        allowed content, each class with the model's distribution over its own ranks,
        scaled to `share` and 1 - share of the total weight."""
        out = {}
        for targeted, mass in ((True, share), (False, 1 - share)):
            ranks = [c for c in model['ranking'] if self.world.sites[c].targeted == targeted]
            w = popularity(dict(model, ranking=ranks))
            total = sum(w.values()) or 1.0
            out.update({c: v * mass / total for c, v in w.items()})
        return {c: float('%.6g' % v) for c, v in sorted(out.items(), key=lambda x: -x[1])}

    def initial_order(self, rng):
        e, w = self.e, self.world
        mix = dict(self.sc['blocklist']['entry_mix'])
        mix.pop('endpoint', None)
        kinds = [k for k, v in mix.items() if v > 0] or ['domain']
        add, by_org = [], defaultdict(list)
        for x in w.sites.values():
            if x.targeted:
                by_org[x.org].append(x)
        prob = self.listing_chance([x for xs in by_org.values() for x in xs])
        for org, xs in by_org.items():
            kind = rng.choices(kinds, weights=[mix[k] for k in kinds])[0]
            if kind == 'suffix':
                if rng.random() < min(prob[x.name] for x in xs):
                    add.append({'type': 'suffix', 'value': org})
                continue
            for x in xs:
                if rng.random() < prob[x.name]:
                    add.append(e.site_entry(x, kind))
        for ep in w.endpoints:
            if rng.random() < self.sc['world']['endpoints_initially_listed']:
                add.append(e.endpoint_entry(ep))
        f = self.sc['blocklist']['add']['filler']
        add += self.filler(stochastic_round(len(add) * f / (1 - f), rng), rng)
        rng.shuffle(add)
        e.order(0, add, origin='initial')
        return copy.deepcopy(add)

    def listing_chance(self, xs):
        """{site: chance the t = 0 order lists it}: world.initially_listed on average,
        each site's chance ~ popularity ** -initial_listing_bias (0: all equal; > 0 the
        popular sites are listed less at t = 0 and left to later orders), capped at 1."""
        p = self.sc['world']['initially_listed']
        b = self.sc['world'].get('initial_listing_bias') or 0
        if not b or not xs:
            return {x.name: p for x in xs}
        inv = {x.name: (self.e.popularity.get(x.content, 0) or 1e-9) ** -b for x in xs}
        out, want = {}, p * len(xs)
        while True:             # sites capped at 1 hand their excess to the rest
            rest = {n: v for n, v in inv.items() if n not in out}
            norm = (want - len(out)) / sum(rest.values()) if rest else 0
            capped = [n for n, v in rest.items() if v * norm >= 1]
            if not capped:
                out.update({n: v * norm for n, v in rest.items()})
                return out
            out.update({n: 1.0 for n in capped})

    # ---- processes --------------------------------------------------
    def order(self, t, add=(), remove=(), origin=None):
        if add or remove:
            self.item(t, 'blocklist_order', origin, add=copy.deepcopy(list(add)),
                      remove=copy.deepcopy(list(remove)))
        self.e.order(t, add, remove, origin)

    def route_change(self, t, prefix, to, origin):
        self.item(t, 'bgp_change', origin, prefix=prefix, to=to)
        self.e.route_change(t, prefix, to, origin)

    def p_bgp(self, t, rng):
        w = self.world
        net = rng.choice(w.external)
        to = w.pick_exit(rng, exclude=w.location[net])
        if to is not None:
            self.route_change(t, str(net), to, 'bgp_change')

    def p_dns_change(self, t, rng):
        xs = self.e.live_sites(lambda x: not x.flux and x.hosting in ('external', 'domestic'))
        if xs:
            x = rng.choice(xs)
            ip = self.world.new_ip(x.hosting, rng)
            origin = 'dns_change:' + x.name
            self.item(t, 'dns_change', origin, site=x.name, ip=ip)
            self.e.move(t, x, ip, origin)

    def fast_flux(self):
        ff = self.sc['external']['fast_flux'] or {}
        rotate = ff.get('rotate_s')
        flux = [x for x in self.world.sites.values() if x.flux]
        if not flux or not rotate:
            return
        rng = self.rng('fast_flux')
        overlap = ff.get('overlap_s', rotate)

        def rotate_one(x):
            it = None

            def fire(t):
                nonlocal it
                if not x.dead:
                    ip = self.world.new_ip('external', rng)
                    origin = 'fast_flux:' + x.name
                    if it is None:
                        it = self.item(t, 'fast_flux', origin, site=x.name, rotate_s=rotate,
                                       overlap_s=overlap, ips=[])
                    it['ips'].append(ip)
                    self.e.flux_rotate(t, x, ip, overlap, origin)
                    self.e.at(t + rotate, fire, PRIO_FLUX)
            return fire
        for x in flux:
            self.e.at(rng.uniform(0, rotate), rotate_one(x), PRIO_FLUX)

    def p_mirror(self, t, rng):
        e, w = self.e, self.world
        xs = e.live_sites(lambda x: x.targeted and x.mirror_of is None)
        if not xs:
            return
        listed = [x for x in xs if e.listed(x)]
        src = rng.choice(listed or xs)
        org = w.mirror_org(src)
        ip = w.new_ip('external', rng)
        delay = (self.sc['external']['mirror'] or {}).get('dns_delay_s') or 0
        origin = 'mirror:' + src.name
        self.item(t, 'mirror', origin, of=src.name, name='www.' + org, org=org, ip=ip,
                  dns_delay_s=delay)
        e.mirror(t, src, 'www.' + org, org, ip, delay, origin)

    def p_shared_ip_join(self, t, rng):
        # Only onto sites blocked by name (domain/suffix), never onto an IP an ip entry
        # lists: an allowed site there would itself be should-block, and the shared-IP
        # trade-off would be gone.
        e = self.e
        targets = e.live_sites(lambda x: x.targeted and not x.flux
                               and x.hosting in ('external', 'domestic')
                               and x.primary in e.serving[x.name]
                               and e.blocklist.match(x.name) is not None
                               and e.blocklist.match(ips=[x.primary]) is None)
        allowed = e.live_sites(lambda x: not x.targeted and x.hosting in
                               ('external', 'domestic'))
        if targets and allowed:
            tx = rng.choice(targets)
            ax = rng.choice([a for a in allowed if a.primary != tx.primary] or allowed)
            if ax.primary != tx.primary:
                origin = 'shared_ip_join:%s>%s' % (ax.name, tx.name)
                self.item(t, 'shared_ip_join', origin, site=ax.name, onto=tx.name)
                ax.hosting = tx.hosting          # now hosted where tx is
                e.move(t, ax, tx.primary, origin)

    def p_block_add(self, t, rng):
        self.block_order(t, rng, order_size(self.sc['blocklist']['add']['entries'], rng),
                         'block_add')

    def block_order(self, t, rng, n, origin):
        """One order of about n entries: each slot is filler with probability
        blocklist.add.filler, the rest real unlisted targets or endpoints. With too few
        targets the order shrinks, filler with it."""
        e = self.e
        bc = self.sc['blocklist']
        mix = bc['entry_mix']
        k = sum(rng.random() < bc['add']['filler'] for _ in range(n))
        want = n - k
        add, used = [], set()
        for _ in range(want):
            free = [x for x in e.unlisted_targets() if x.name not in used]
            eps = [ep for ep in self.world.endpoints
                   if e.blocklist.match(endpoint=(ep.ip, ep.port)) is None
                   and ep.ip not in used]
            kinds = [k_ for k_ in ('domain', 'suffix', 'ip', 'endpoint')
                     if mix.get(k_, 0) > 0 and (eps if k_ == 'endpoint' else free)]
            if not kinds:
                break
            kind = rng.choices(kinds, weights=[mix[k_] for k_ in kinds])[0]
            if kind == 'endpoint':
                ep = rng.choice(eps)
                used.add(ep.ip)
                add.append(e.endpoint_entry(ep))
                continue
            mirrors = [x for x in free if x.mirror_of]
            pool = mirrors if mirrors and rng.random() < bc['add']['prefer_mirrors'] else free
            x = self.pick_target(pool, rng)
            add.append(e.site_entry(x, kind))
            if kind == 'suffix':
                used.update(y.name for y in free if y.org == x.org)
            else:
                used.add(x.name)
        if want and len(add) < want:
            k = round(k * len(add) / want)
        add += self.filler(k, rng)
        rng.shuffle(add)
        self.order(t, add, origin=origin)

    def pick_target(self, pool, rng):
        """One site of pool, weighted by its content's popularity ** popular_targets
        (blocklist.add; 0 or null: uniform). Real lists go after what people use."""
        a = self.sc['blocklist']['add'].get('popular_targets')
        if a:
            w = [self.e.popularity.get(x.content, 0) ** a for x in pool]
            if sum(w) > 0:
                return rng.choices(pool, weights=w)[0]
        return rng.choice(pool)

    def filler(self, n, rng):
        """n entries that no traffic will ever match, drawn like real ones (§4): types by
        entry_mix, names from the shared namer (reserved), addresses fresh and reserved
        in the targeted sites' hosting mix, endpoints on the .53 / .10 convention."""
        e, w = self.e, self.world
        mix = {k: v for k, v in self.sc['blocklist']['entry_mix'].items() if v > 0}
        if not w.endpoints:
            mix.pop('endpoint', None)
        targets = e.live_sites(lambda x: x.targeted)
        mirrors = [x for x in targets if x.mirror_of]
        ip_kinds = [x.hosting for x in targets if x.hosting in ('external', 'domestic')]
        lo, hi = self.sc['world']['sites_per_org']
        out = []
        for _ in range(n):
            kind = rng.choices(list(mix), weights=list(mix.values()))[0]
            try:
                if kind == 'ip':
                    hk = rng.choice(ip_kinds) if ip_kinds else 'external'
                    out.append({'type': 'ip', 'value': w.new_ip(hk, rng)})
                elif kind == 'endpoint':
                    ep = rng.choice(w.endpoints)
                    host = 53 if ep.kind == 'ext_resolver' else 10
                    nets = [n_ for n_ in w.external if host not in w._used.get(n_, ())]
                    if not nets:
                        continue
                    out.append({'type': 'endpoint', 'kind': ep.kind,
                                'ip': w.alloc(rng.choice(nets), rng, host), 'port': ep.port})
                elif mirrors and rng.random() < len(mirrors) / len(targets):
                    src = w.sites[rng.choice(mirrors).mirror_of]     # like a real mirror
                    org = w.mirror_org(src, filler=True)
                    out.append({'type': 'suffix', 'value': org} if kind == 'suffix'
                               else {'type': 'domain', 'value': 'www.' + org})
                else:
                    org = w.filler_org()
                    name = rng.choice(w.site_names(org, rng.randint(lo, hi), rng))
                    out.append({'type': 'suffix', 'value': org} if kind == 'suffix'
                               else {'type': 'domain', 'value': name})
            except WorldError:
                continue
        return out

    def p_block_remove(self, t, rng):
        cur = [x['entry'] for x in self.e.blocklist.entries()]
        if cur:
            self.order(t, remove=[rng.choice(cur)], origin='block_remove')

    def p_start_blocked(self, t, rng):
        xs = self.e.live_sites(lambda x: x.targeted and not x.flux and x.hosting == 'external')
        if xs:
            x = rng.choice(xs)
            x.hosting = 'domestic'
            ip = self.world.new_ip('domestic', rng)
            origin = 'start_blocked:' + x.name
            self.item(t, 'start_blocked', origin, site=x.name, ip=ip)
            self.e.move(t, x, ip, origin)

    def p_stop(self, t, rng):
        xs = self.e.live_sites(lambda x: x.targeted and x.hosting == 'domestic')
        if xs:
            x = rng.choice(xs)
            origin = 'stop:' + x.name
            self.item(t, 'stop', origin, site=x.name)
            self.e.stop(t, x, origin)

    # ---- ISP --------------------------------------------------------
    def link_failure(self, t, name, duration, origin):
        self.item(t, 'link_failure', origin, link=name, duration_s=duration)
        self.e.link_failure(t, name, duration, origin)

    def p_failure(self, t, rng):
        e = self.e
        if e.down:                         # one failure at a time
            return
        br = e.bridges()
        cands = [l for l in self.topo.links if l.index not in br]
        if not cands:
            return
        l = rng.choice(cands)
        dur = self.sc['isp']['failure'].get('duration_s') or 60
        self.link_failure(t, e.link_name(l), dur, 'failure')

    def te(self):
        """One `te` item per cycle, at its application time; the compiler expands it."""
        te = self.sc['isp']['te'] or {}
        iv = te.get('interval_s')
        if not iv:
            return
        notice = te.get('notice_s') or 0

        def fire(t):
            apply_at = rt(t + notice)
            if apply_at <= self.duration:
                self.item(apply_at, 'te', 'te', notice_s=notice)
            self.e.at(t + iv, fire, PRIO_TE)
        self.e.at(iv - notice, fire, PRIO_TE)

    # ---- demand events ----------------------------------------------
    def flash(self, t, rng, pop, site=None, factor=None, duration=None,
              origin='flash_crowd'):
        """One PoP's rate becomes `factor` x normal for `duration`; the extra goes to one site."""
        fc = self.sc['demand']['flash_crowd'] or {}
        factor = factor or fc.get('factor', 10)
        duration = duration or fc.get('duration_s', 30)
        if site is None:
            _, xs = self.e.pick_content(rng.random())
            pub = [x for x in xs if x.name in self.e.dns.records]
            if not pub:
                return
            site = rng.choice(pub).name
        self.item(t, 'flash_crowd', origin, pop=pop, site=site, factor=factor,
                  duration_s=duration)

    def flash_crowds(self):
        """Independent Poisson process per PoP; mean interval / that PoP's weight."""
        fc = self.sc['demand']['flash_crowd'] or {}
        mean = fc.get('mean_interval_s')
        if mean is None:
            return
        weights = fc.get('pop_weights') or {}
        for p in self.world.pops:
            w = float(weights.get(p.name, 1.0))
            if w > 0:
                self.e.poisson('flash_crowd:' + p.client, mean / w,
                               lambda t, rng, pop=p.name: self.flash(
                                   t, rng, pop, origin='flash_crowd:' + pop))

    # ---- scripted ---------------------------------------------------
    def scripted(self):
        rng = self.rng('scripted')
        for i, s in enumerate(self.sc['scripted']):
            s = dict(s)
            kind = s.pop('ev')
            t = s.pop('t')
            origin = 'scripted[%d]' % i
            if kind in timeline.EVENTS:
                raw = dict({'ev': kind}, **s)
                self.e.at(t, lambda now, raw=raw, origin=origin: self.raw(now, raw, origin),
                          PRIO_PROCESS)
            else:
                self.e.at(t, lambda now, kind=kind, s=s, origin=origin:
                          self.high_level(now, kind, s, rng, origin), PRIO_PROCESS)

    def raw(self, t, raw, origin):
        self.items.append({'t': rt(t), 'raw': copy.deepcopy(raw), 'origin': origin})
        if raw['ev'] != 'request':          # requests are the compiler's
            ev = {k: v for k, v in raw.items() if k != 'ev'}
            ev.update(ev=raw['ev'], origin=origin)
            self.e.raw(t, ev)

    def high_level(self, t, kind, s, rng, origin):
        if kind == 'flash_crowd':
            pop = s.get('pop')
            if pop is None:            # no pop given: one PoP, drawn by flash_crowd.pop_weights
                pw = (self.sc['demand']['flash_crowd'] or {}).get('pop_weights') or {}
                pops = [p.name for p in self.world.pops]
                pop = rng.choices(pops, weights=[float(pw.get(p, 1.0)) for p in pops])[0]
            elif pop not in {p.name for p in self.world.pops}:
                raise ValueError('%s: unknown pop %r' % (origin, pop))
            self.flash(t, rng, pop, s.get('site'), s.get('factor'), s.get('duration_s'),
                       origin)
        elif kind == 'bgp_change':
            w = self.world
            net = w.prefix_of(s['prefix'].split('/')[0]) if s.get('prefix') \
                else rng.choice(w.external)
            to = s.get('to') or w.pick_exit(rng, exclude=w.location.get(net))
            if net is not None and to:
                self.route_change(t, str(net), to, origin)
        elif kind == 'mirror':
            self.p_mirror(t, rng)
        elif kind == 'order':
            n = s.get('entries') or order_size(self.sc['blocklist']['add']['entries'], rng)
            self.block_order(t, rng, n, origin)
        elif kind == 'block':
            add = list(s.get('entries') or [])
            for name in s.get('sites') or ():
                add.append({'type': 'domain', 'value': name})
            self.order(t, add, origin=origin)
        elif kind == 'unblock':
            self.order(t, remove=list(s.get('entries') or []), origin=origin)
        elif kind == 'link_failure':
            self.link_failure(t, s['link'], s.get('duration_s', 60), origin)

    # ---- run --------------------------------------------------------
    def run(self):
        """The HL scenario document."""
        e = self.e
        self.build_world()
        ex, bl, hc = self.sc['external'], self.sc['blocklist'], self.sc['hosting_customers']
        mi = lambda d: (d or {}).get('mean_interval_s')
        e.poisson('bgp_change', mi(ex['bgp_change']), self.p_bgp)
        e.poisson('dns_change', mi(ex['dns_change']), self.p_dns_change)
        self.fast_flux()
        e.poisson('mirror', mi(ex['mirror']), self.p_mirror)
        e.poisson('shared_ip_join', mi(ex['shared_ip_join']), self.p_shared_ip_join)
        e.poisson('blocklist.add', mi(bl['add']), self.p_block_add)
        e.poisson('blocklist.remove', mi(bl['remove']), self.p_block_remove)
        e.poisson('start_blocked', mi(hc['start_blocked']), self.p_start_blocked)
        e.poisson('stop', mi(hc['stop']), self.p_stop)
        self.flash_crowds()
        e.poisson('failure', mi(self.sc['isp']['failure']), self.p_failure)
        self.te()
        self.scripted()
        e.drain()
        events = sorted(self.items, key=lambda it: it['t'])     # stable: execution order
        sha = hashlib.sha256(json.dumps(self.sc, sort_keys=True, default=str).encode())
        return {
            'format': hl.FORMAT,
            'seed': self.seed,
            'duration_s': self.duration,
            'topology': {'name': self.topo.name, 'metric': self.metric,
                         'tie_break': self.tie_break},
            'provenance': {'writer': VERSION, 'config_sha256': sha.hexdigest()},
            'world': self.hl_world,
            'demand': self.demand,
            'events': events,
        }


def order_size(spec, rng):
    """Order size from blocklist.add.entries: [min, max] uniform, or a lognormal
    {median, sigma, max} (mostly small, now and then large)."""
    if isinstance(spec, list):
        return rng.randint(*spec)
    n = round(spec['median'] * math.exp(spec.get('sigma', 0) * rng.gauss(0, 1)))
    return max(1, min(n, spec.get('max') or n))


def stochastic_round(x, rng):
    n = int(x)
    return n + (rng.random() < x - n)


def write_scenario(cfg, topo=None, seed=None, duration_s=None):
    """The HL scenario document for a loaded run config."""
    topo = topo or load_topology_for(cfg)
    return Writer(cfg, topo, seed, duration_s).run()


def main(argv=None):
    ap = argparse.ArgumentParser(prog='python -m kit.sim.write', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-c', '--config', default='configs/default.yaml')
    ap.add_argument('-o', '--out', required=True)
    ap.add_argument('--seed', type=int)
    ap.add_argument('--duration', type=float)
    args = ap.parse_args(argv)
    doc = write_scenario(load_config(args.config), seed=args.seed, duration_s=args.duration)
    hl.check(doc)
    hl.dump(doc, args.out)
    kinds = defaultdict(int)
    for it in doc['events']:
        kinds[it.get('ev', 'raw')] += 1
    print('%s: %d sites, %d events (%s)' % (
        args.out, sum(len(o['sites']) for o in doc['world']['orgs']), len(doc['events']),
        ', '.join('%s=%d' % kv for kv in sorted(kinds.items()))), file=sys.stderr)


if __name__ == '__main__':
    main()
