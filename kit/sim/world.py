"""The simulated world: address plan, orgs and sites, endpoints.

simulator.md §2. Built from the topology by host kind:
  PoP hosts (role client), in file order, i = 1..  -> 10.i.0.0/16
  caches (kind cache), j = 1..                     -> 100.64.j.0/24
  exits (kind external_exit)                       -> M x 198.18.k.0/24 (k = 0..M-1)
A PoP is named after its host's switch (P3 for S3 in isp_v2). Its /16 holds
both its subscribers and its domestic sites: subscriber addresses are a fixed
sample of the /16 (subscriber_ips), and domestic sites get addresses from the
rest, so neither sits in a range of its own.
"""

import ipaddress
import random
from dataclasses import dataclass, field

EXTERNAL_BASE = ipaddress.IPv4Address('198.18.0.0')     # 198.18.0.0/15
CACHE_BASE = ipaddress.IPv4Address('100.64.0.0')
AUTH_DNS_PORT = 53
PORTS = {'ext_resolver': 53, 'encrypted_dns': 443}
TLDS = ('example', 'test')
WORDS = ('portal', 'news', 'stream', 'forum', 'market', 'video', 'cloud', 'photo',
         'music', 'games', 'wiki', 'chat', 'files', 'books', 'sport', 'travel',
         'radio', 'press', 'daily', 'image', 'blog', 'shop', 'mail', 'social')
SUBDOMAINS = ('', 'cdn', 'img', 'api', 'm', 'video', 'news', 'static', 'shop', 'media')
POOL_BLOCK = 10           # org numbers per block of the shuffled name pool


class WorldError(ValueError):
    pass


@dataclass
class Pop:
    name: str            # switch id
    client: str          # client host id
    prefix: ipaddress.IPv4Network


@dataclass
class Endpoint:
    id: str
    kind: str
    ip: str
    port: int


@dataclass
class Site:
    name: str
    org: str
    content: str          # content identity shared by mirrors (the original's name)
    targeted: bool        # content that orders go after
    hosting: str          # external | cache | domestic
    ttl: float
    primary: str = None   # default-view DNS answer
    cache_ips: dict = field(default_factory=dict)   # cache host id -> ip (view = id.lower())
    flux: bool = False
    mirror_of: str = None
    dead: bool = False    # stopped serving; its record is removed


class World:
    def __init__(self, topo, wcfg):
        self.topo = topo
        self.cfg = wcfg
        hosts = list(topo.hosts.values())
        clients = [h for h in hosts if h.role == 'client']
        self.exits = [h.id for h in hosts if h.kind == 'external_exit']
        self.caches = [h.id for h in hosts if h.kind == 'cache']
        if not clients:
            raise WorldError('topology %s has no client hosts' % topo.name)
        if not self.exits:
            raise WorldError('topology %s has no external_exit hosts' % topo.name)
        if len(clients) > 255 or len(self.caches) > 255:
            raise WorldError('at most 255 PoP hosts and caches')
        resolvers = [h for h in hosts if h.role == 'resolver']
        self.resolver = resolvers[0] if resolvers else None

        self.pops = []
        for i, h in enumerate(clients, 1):
            self.pops.append(Pop(h.switch, h.id,
                                 ipaddress.IPv4Network('10.%d.0.0/16' % i)))
        self.pop_of_client = {p.client: p for p in self.pops}
        self.cache_prefix = {
            h: ipaddress.IPv4Network((int(CACHE_BASE) + (j << 8), 24))
            for j, h in enumerate(self.caches, 1)}
        m = wcfg['external_prefixes']
        self.external = [ipaddress.IPv4Network((int(EXTERNAL_BASE) + (k << 8), 24))
                         for k in range(m)]
        self.location = {}          # prefix -> host id (external ones move by BGP)
        self.location.update((p.prefix, p.client) for p in self.pops)
        self.location.update((n, h) for h, n in self.cache_prefix.items())
        self._used = {}             # prefix -> set of used host numbers
        self.subscribers_per_pop = 0
        self._subs = {}             # PoP name -> [subscriber ip]
        self._sub_set = set()
        self.orgs = []
        self.sites = {}             # name -> Site (creation order)
        self.endpoints = []
        self.auth_dns = None
        self.name_rng = None        # set by the writer: shuffles the org-name pool
        self._pool = []
        self._pool_n = 0
        self._next_mirror = {}
        self.reserved_names = set()  # filler names: never given to a real org or mirror

    # ---- exits ------------------------------------------------------
    def exit_weight(self, host_id):
        return float(self.cfg['exit_weights'].get(host_id, 1))

    def assign_exits(self, rng):
        """Initial exit for every external prefix: largest-remainder quotas, shuffled."""
        w = [self.exit_weight(h) for h in self.exits]
        total = sum(w)
        if total <= 0:
            raise WorldError('simulator.world.exit_weights: every exit weighs 0')
        m = len(self.external)
        quota = [m * x / total for x in w]
        counts = [int(q) for q in quota]
        order = sorted(range(len(w)), key=lambda i: (counts[i] - quota[i], i))
        for i in order[:m - sum(counts)]:
            counts[i] += 1
        seq = [h for h, c in zip(self.exits, counts) for _ in range(c)]
        rng.shuffle(seq)
        for net, h in zip(self.external, seq):
            self.location[net] = h

    def set_external(self, pairs):
        """External prefixes and their exits as listed in an HL world: [(cidr, exit)]."""
        for n in self.external:
            self.location.pop(n, None)
        self.external = []
        for cidr, host in pairs:
            n = ipaddress.IPv4Network(cidr)
            self.external.append(n)
            self.location[n] = host

    def pick_exit(self, rng, exclude=None):
        cands = [h for h in self.exits if h != exclude and self.exit_weight(h) > 0]
        if not cands:
            return None
        return rng.choices(cands, weights=[self.exit_weight(h) for h in cands])[0]

    # ---- addresses --------------------------------------------------
    def set_subscribers(self, n):
        """Subscribers per PoP (demand.subscribers_per_pop). Their addresses are taken
        out of the PoP's /16 before any domestic site gets one."""
        if self._subs:
            raise WorldError('subscribers are set once, before any address is drawn')
        self.subscribers_per_pop = n
        for p in self.pops:
            size = p.prefix.num_addresses
            nos = random.Random('subscribers:%s' % p.prefix).sample(range(1, size - 1), n)
            self._used.setdefault(p.prefix, set()).update(nos)
            self._subs[p.name] = [str(p.prefix.network_address + k) for k in nos]
            self._sub_set.update(self._subs[p.name])

    def subscriber_ips(self, pop):
        """[subscriber ip] of a PoP: subscriber j sends from the j-th."""
        return self._subs[pop.name]

    def is_subscriber(self, ip):
        return str(ip) in self._sub_set

    def alloc(self, net, rng, host_no=None):
        used = self._used.setdefault(net, set())
        if host_no is None:
            size = net.num_addresses
            if size <= 256:
                free = [n for n in range(1, size - 1) if n not in used]
                if not free:
                    raise WorldError('prefix %s is full' % net)
                host_no = rng.choice(free)
            else:
                if len(used) >= size - 2:
                    raise WorldError('prefix %s is full' % net)
                host_no = rng.randrange(1, size - 1)
                while host_no in used:
                    host_no = rng.randrange(1, size - 1)
        elif host_no in used:
            raise WorldError('%s.%d already used' % (net, host_no))
        used.add(host_no)
        return str(net.network_address + host_no)

    def new_ip(self, hosting, rng):
        if hosting == 'domestic':
            return self.alloc(rng.choice(self.pops).prefix, rng)
        return self.alloc(rng.choice(self.external), rng)

    def locate(self, ip):
        """Host currently answering for `ip`, or None."""
        a = ipaddress.IPv4Address(ip)
        for net, h in self.location.items():
            if a in net:
                return h
        return None

    def prefix_of(self, ip):
        a = ipaddress.IPv4Address(ip)
        return next((n for n in self.location if a in n), None)

    # ---- names ------------------------------------------------------
    def _pool_name(self):
        """Next name from one shuffled pool of <word><n>.<tld> (real orgs and filler alike),
        refilled a block of POOL_BLOCK numbers at a time."""
        if not self._pool:
            n0 = self._pool_n
            self._pool_n += POOL_BLOCK
            block = ['%s%d.%s' % (w, n, tld) for n in range(n0 + 1, n0 + POOL_BLOCK + 1)
                     for w in WORDS for tld in TLDS]
            self.name_rng.shuffle(block)
            self._pool = block
        return self._pool.pop()

    def new_org(self, rng=None):
        name = self._pool_name()
        self.orgs.append(name)
        return name

    def filler_org(self):
        """A registrable domain for filler: from the same pool, reserved, never a real org."""
        name = self._pool_name()
        self.reserved_names.add(name)
        return name

    def site_names(self, org, n, rng):
        rest = list(SUBDOMAINS)
        rng.shuffle(rest)
        labels = ['www'] + rest[:n - 1]
        return ['%s.%s' % (l, org) if l else org for l in labels]

    def mirror_org(self, site, filler=False):
        """'www.portal3.example' -> 'portal3-mirror1.test' (a new registrable domain).
        filler=True reserves the name instead; later real mirrors skip it."""
        base = site.org.split('.')[0]
        tld = TLDS[(TLDS.index(site.org.rsplit('.', 1)[1]) + 1) % len(TLDS)]
        while True:
            k = self._next_mirror.get(base, 0) + 1
            self._next_mirror[base] = k
            name = '%s-mirror%d.%s' % (base, k, tld)
            if name not in self.reserved_names and name not in self.orgs:
                break
        if filler:
            self.reserved_names.add(name)
        return name

    # ---- endpoints --------------------------------------------------
    def make_endpoints(self, rng):
        """Authoritative DNS in the first external prefix, others in random ones."""
        self.auth_dns = Endpoint('auth-dns', 'authoritative_dns',
                                 self.alloc(self.external[0], rng, 53), AUTH_DNS_PORT)
        for kind, prefix_id, host_no in (('ext_resolver', 'xres', 53),
                                         ('encrypted_dns', 'edns', 10)):
            for i in range(self.cfg['endpoints'].get(kind, 0)):
                for _ in range(len(self.external)):
                    net = rng.choice(self.external)
                    if host_no not in self._used.get(net, ()):
                        break
                else:
                    raise WorldError('no room for %s endpoints' % kind)
                ip = self.alloc(net, rng, host_no)
                self.endpoints.append(Endpoint('%s%d' % (prefix_id, i + 1), kind, ip,
                                               PORTS[kind]))

    def endpoints_of(self, kind):
        return [e for e in self.endpoints if e.kind == kind]

    def endpoint_by_ip(self, ip):
        return next((e for e in self.endpoints if e.ip == ip), None)

    # ---- caches -----------------------------------------------------
    def nearest_cache(self, routing):
        """{pop name: cache host id}, by baseline path length (ties: file order)."""
        out = {}
        for p in self.pops:
            best = min(self.caches, key=lambda c: (len(routing.path(p.name, c)),
                                                   self.caches.index(c)))
            out[p.name] = best
        return out

    def header_prefixes(self):
        out = [{'cidr': str(p.prefix), 'host': p.client, 'kind': 'clients'}
               for p in self.pops]
        out += [{'cidr': str(n), 'host': h, 'kind': 'cache'}
                for h, n in self.cache_prefix.items()]
        out += [{'cidr': str(n), 'host': self.location[n], 'kind': 'external'}
                for n in self.external]
        return out
