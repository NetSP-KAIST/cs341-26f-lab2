"""Authoritative DNS state and resolver caches.

The generator uses these to compute each request's `expect_ip`; the runtime
authoritative server and resolvers use the same classes, so
both sides give the same answers for the same event sequence.

Times are scenario seconds. A cached answer is valid while t < expires.
"""

from dataclasses import dataclass, field

DEFAULT_VIEW = 'default'


@dataclass
class Record:
    ips: list
    ttl: float
    views: list = field(default_factory=list)   # [{"view", "pops", "ips"}]


@dataclass(frozen=True)
class Answer:
    ips: tuple
    ttl: float
    view: str
    pops: frozenset      # named view: the PoPs it covers
    excluded: frozenset  # default view: the PoPs some named view covers


class DnsState:
    """What the authoritative DNS serves: domain -> Record."""

    def __init__(self):
        self.records = {}

    def apply(self, ev):
        """Apply a `dns_record` event."""
        domain = ev['domain'].lower().rstrip('.')
        if ev['op'] == 'remove':
            self.records.pop(domain, None)
        elif ev['op'] == 'set':
            self.records[domain] = Record(list(ev['ips']), float(ev['ttl']),
                                          [dict(v) for v in ev.get('views') or ()])
        else:
            raise ValueError('dns_record op must be set or remove')

    def answer(self, domain, pop=None):
        """Answer for a query from `pop` (None: no client PoP, default view), or None."""
        r = self.records.get(domain.lower().rstrip('.'))
        if r is None:
            return None
        covered = frozenset(p for v in r.views for p in v['pops'])
        if pop is not None:
            for v in r.views:
                if pop in v['pops']:
                    return Answer(tuple(v['ips']), r.ttl, v['view'],
                                  frozenset(v['pops']), frozenset())
        return Answer(tuple(r.ips), r.ttl, DEFAULT_VIEW, frozenset(), covered)


@dataclass
class _Cached:
    answer: Answer
    expires: float

    def covers(self, pop):
        a = self.answer
        if a.view == DEFAULT_VIEW:
            return pop is None or pop not in a.excluded
        return pop in a.pops


class ResolverCache:
    """Caching resolver in front of a DnsState, keyed by (domain, view).

    use_pop=True: the internal resolver, which sends the client's PoP
    upstream (like EDNS Client Subnet). use_pop=False: external resolvers
    and encrypted DNS, which always get the default view.
    No negative caching: a missing record is asked again every time.
    """

    def __init__(self, use_pop=True):
        self.use_pop = use_pop
        self.cache = {}          # domain -> {view: _Cached}
        self.queries = 0         # upstream queries (for logs and tests)

    def lookup(self, domain, t, pop=None):
        """(Answer, expires) cached for a query from `pop`, or None."""
        domain = domain.lower().rstrip('.')
        pop = pop if self.use_pop else None
        for c in self.cache.get(domain, {}).values():
            if t < c.expires and c.covers(pop):
                return c.answer, c.expires
        return None

    def store(self, domain, t, answer):
        self.cache.setdefault(domain.lower().rstrip('.'), {})[answer.view] = \
            _Cached(answer, t + answer.ttl)

    def resolve(self, upstream, domain, t, pop=None):
        """(ips tuple or None, from_cache), asking `upstream` (a DnsState) on a miss."""
        hit = self.lookup(domain, t, pop)
        if hit is not None:
            return hit[0].ips, True
        self.queries += 1
        a = upstream.answer(domain.lower().rstrip('.'), pop if self.use_pop else None)
        if a is None:
            return None, False
        self.store(domain, t, a)
        return a.ips, False

    def expire(self, t):
        """Drop expired entries (memory only; answers do not change)."""
        for domain in list(self.cache):
            views = self.cache[domain]
            for v in [v for v, c in views.items() if c.expires <= t]:
                del views[v]
            if not views:
                del self.cache[domain]
