"""High-level scenario file (scenario.hl.yaml): load, dump, structural check.

docs/kit/simulator.md §8 is the schema, and
docs/kit/scenario.hl.example.yaml is an annotated example. This module only
checks shape: keys, required fields and value types (check E1). The
compiler checks references and world rules.

The file has three parts:
  world    explicit lists: what exists at t = 0
  demand   a model the compiler samples requests from
  events   high-level events at fixed times, plus raw timeline events
"""

import copy
import hashlib
import json

import yaml

FORMAT = 'lab2-hl/1'


class HLError(ValueError):
    pass


TOP = {'format': True, 'seed': True, 'duration_s': True, 'topology': True,
       'provenance': False, 'world': True, 'demand': True, 'events': True}
TOPOLOGY = {'name': True, 'metric': False, 'tie_break': False}
WORLD = {'external_prefixes': True, 'cache_views': False, 'endpoints': True, 'orgs': True,
         'blocklist': False}
ORG = {'org': True, 'targeted': True, 'sites': True}
SITE = {'name': True, 'hosting': True, 'ip': True, 'ttl': True, 'cache_ips': False,
        'flux': False, 'content': False, 'serve': False, 'dns': False}
SITE_DNS = {'ips': True, 'ttl': False, 'views': False}
ENDPOINT = {'id': True, 'kind': True, 'ip': True, 'port': True}
DEMAND = {'subscribers_per_pop': True, 'rate_per_s': True, 'diurnal': False,
          'popularity': True, 'methods': True, 'size_bytes': True, 'split_host': False,
          'large_header': False, 'segments': False}
POPULARITY = {'dist': True, 's': False, 'ranking': False, 'weights': False}
HOSTING = ('external', 'cache', 'domestic')
ENDPOINT_KINDS = ('authoritative_dns', 'ext_resolver', 'encrypted_dns')

# ev -> {field: required}; every item also has t, and optionally origin
EVENTS = {
    'bgp_change': {'prefix': True, 'to': True},
    'dns_change': {'site': True, 'ip': True, 'unserve_after_s': False},
    'shared_ip_join': {'site': True, 'onto': True, 'unserve_after_s': False},
    'start_blocked': {'site': True, 'ip': True, 'unserve_after_s': False},
    'fast_flux': {'site': True, 'rotate_s': True, 'overlap_s': True, 'ips': False},
    'mirror': {'of': True, 'name': True, 'org': True, 'ip': True, 'dns_delay_s': False},
    'add_site': {'org': True, 'targeted': True, 'site': True, 'weight': False,
                 'dns_delay_s': False},
    'stop': {'site': True},
    'blocklist_order': {'add': False, 'remove': False, 'order_id': False},
    'flash_crowd': {'pop': True, 'site': False, 'factor': True, 'duration_s': True},
    'te': {'notice_s': True, 'weights': False},
    'link_failure': {'link': True, 'duration_s': True},
}
NUMBER = (int, float)
# item field -> (lower bound, strict); the remaining typed fields are strings or lists
ITEM_NUMS = {'factor': (0, True), 'duration_s': (0, True), 'rotate_s': (0, True),
             'overlap_s': (0, False), 'dns_delay_s': (0, False), 'notice_s': (0, False),
             'unserve_after_s': (0, False), 'weight': (0, False)}
ITEM_STRS = ('site', 'ip', 'of', 'name', 'org', 'onto', 'pop', 'link', 'prefix', 'to',
             'order_id')
ITEM_LISTS = ('add', 'remove', 'ips')


def _keys(obj, spec, where):
    if not isinstance(obj, dict):
        raise HLError('%s: expected a mapping' % where)
    for k in obj:
        if k not in spec:
            raise HLError('%s: unknown key %r' % (where, k))
    for k, req in spec.items():
        if req and k not in obj:
            raise HLError('%s: missing %r' % (where, k))


def _num(v, where, lo=None, strict=False):
    if isinstance(v, bool) or not isinstance(v, NUMBER):
        raise HLError('%s: expected a number' % where)
    if lo is not None and (v <= lo if strict else v < lo):
        raise HLError('%s: must be %s %s' % (where, '>' if strict else '>=', lo))


def _list(v, where):
    if not isinstance(v, list):
        raise HLError('%s: expected a list' % where)
    return v


def _str(v, where):
    if not isinstance(v, str) or not v:
        raise HLError('%s: expected a non-empty string' % where)


def _mix(d, where):
    if not isinstance(d, dict) or not d:
        raise HLError('%s: expected a non-empty mapping' % where)
    for k, v in d.items():
        _num(v, '%s.%s' % (where, k), 0)
    if sum(d.values()) <= 0:
        raise HLError('%s: weights must have a positive sum' % where)


def check(doc):
    """Structural check (E1). Raises HLError; returns doc."""
    _keys(doc, TOP, 'scenario')
    if doc['format'] != FORMAT:
        raise HLError('format must be %r' % FORMAT)
    if isinstance(doc['seed'], bool) or not isinstance(doc['seed'], int):
        raise HLError('seed: expected an integer')
    _num(doc['duration_s'], 'duration_s', 0, strict=True)
    _keys(doc['topology'], TOPOLOGY, 'topology')

    w = doc['world']
    _keys(w, WORLD, 'world')
    for i, p in enumerate(_list(w['external_prefixes'], 'world.external_prefixes')):
        _keys(p, {'cidr': True, 'exit': True}, 'world.external_prefixes[%d]' % i)
    for c, pops in (w.get('cache_views') or {}).items():
        _list(pops, 'world.cache_views.%s' % c)
    for i, e in enumerate(_list(w['endpoints'], 'world.endpoints')):
        where = 'world.endpoints[%d]' % i
        _keys(e, ENDPOINT, where)
        if e['kind'] not in ENDPOINT_KINDS:
            raise HLError('%s: kind must be one of %s' % (where, ENDPOINT_KINDS))
    for i, o in enumerate(_list(w['orgs'], 'world.orgs')):
        where = 'world.orgs[%d]' % i
        _keys(o, ORG, where)
        if not isinstance(o['targeted'], bool):
            raise HLError('%s.targeted: expected true or false' % where)
        for j, s in enumerate(_list(o['sites'], where + '.sites')):
            _site(s, '%s.sites[%d]' % (where, j))
    _list(w.get('blocklist') or [], 'world.blocklist')

    d = doc['demand']
    _keys(d, DEMAND, 'demand')
    _num(d['subscribers_per_pop'], 'demand.subscribers_per_pop', 1)
    for p, r in d['rate_per_s'].items():
        _num(r, 'demand.rate_per_s.%s' % p, 0)
    _keys(d['popularity'], POPULARITY, 'demand.popularity')
    if d['popularity']['dist'] not in ('zipf', 'uniform', 'weights'):
        raise HLError('demand.popularity.dist: must be zipf, uniform or weights')
    if d['popularity']['dist'] == 'weights':
        if 'weights' not in d['popularity']:
            raise HLError('demand.popularity: dist weights needs `weights`')
    elif 'ranking' not in d['popularity']:
        raise HLError('demand.popularity: dist %s needs `ranking`' % d['popularity']['dist'])
    _mix(d['methods'], 'demand.methods')
    if d['popularity']['dist'] == 'weights':
        _mix(d['popularity']['weights'], 'demand.popularity.weights')
    sz = d['size_bytes']
    _keys(sz, {'median': True, 'sigma': True, 'max': False}, 'demand.size_bytes')
    _num(sz['median'], 'demand.size_bytes.median', 0, strict=True)
    _num(sz['sigma'], 'demand.size_bytes.sigma', 0)
    if sz.get('max') is not None:
        _num(sz['max'], 'demand.size_bytes.max', 0, strict=True)
    for k in ('split_host', 'large_header'):
        if k in d:
            _num(d[k], 'demand.' + k, 0)
            if d[k] > 1:
                raise HLError('demand.%s: a fraction, at most 1' % k)
    di = d.get('diurnal') or {}
    _keys(di, {'period_s': False, 'amplitude': False}, 'demand.diurnal')
    if di.get('period_s') is not None:
        _num(di['period_s'], 'demand.diurnal.period_s', 0, strict=True)
    if 'amplitude' in di:
        _num(di['amplitude'], 'demand.diurnal.amplitude', 0)
    for i, s in enumerate(_list(d.get('segments') or [], 'demand.segments')):
        _segment(s, 'demand.segments[%d]' % i)

    last = None
    for i, it in enumerate(_list(doc['events'], 'events')):
        where = 'events[%d]' % i
        if not isinstance(it, dict):
            raise HLError('%s: expected a mapping' % where)
        if 't' not in it:
            raise HLError('%s: missing t' % where)
        _num(it['t'], where + '.t', 0)
        if last is not None and it['t'] < last:
            raise HLError('%s: events must be sorted by t' % where)
        last = it['t']
        if 'raw' in it:
            _keys(it, {'t': True, 'raw': True, 'origin': False}, where)
            if not isinstance(it['raw'], dict) or 'ev' not in it['raw']:
                raise HLError('%s.raw: expected a low-level event with `ev`' % where)
            continue
        ev = it.get('ev')
        if ev not in EVENTS:
            raise HLError('%s: unknown ev %r' % (where, ev))
        where = '%s (%s)' % (where, ev)
        _keys(it, dict(EVENTS[ev], t=True, ev=True, origin=False), where)
        for k, v in it.items():
            if v is None and EVENTS[ev].get(k) is False:     # optional, left out
                continue
            if k in ITEM_NUMS:
                _num(v, '%s.%s' % (where, k), *ITEM_NUMS[k])
            elif k in ITEM_STRS and not (ev == 'add_site' and k == 'site'):
                _str(v, '%s.%s' % (where, k))
            elif k in ITEM_LISTS:
                _list(v, '%s.%s' % (where, k))
            elif k == 'weights' and not isinstance(v, dict):
                raise HLError('%s.weights: expected a mapping' % where)
        if ev == 'add_site':
            if not isinstance(it['targeted'], bool):
                raise HLError('%s.targeted: expected true or false' % where)
            _site(it['site'], where + '.site')
    return doc


SEGMENT = {'from_s': True, 'to_s': True, 'pops': False, 'rate_scale': False,
           'rate_per_s': False, 'methods': False, 'size_bytes': False, 'split_host': False,
           'large_header': False}


def _segment(s, where):
    _keys(s, SEGMENT, where)
    _num(s['from_s'], where + '.from_s', 0)
    _num(s['to_s'], where + '.to_s')
    if s['from_s'] >= s['to_s']:
        raise HLError('%s: from_s must be below to_s' % where)
    if 'pops' in s:
        for p in _list(s['pops'], where + '.pops'):
            _str(p, where + '.pops[]')
    if 'rate_scale' in s and 'rate_per_s' in s:
        raise HLError('%s: give rate_scale or rate_per_s, not both' % where)
    if 'rate_scale' in s:
        _num(s['rate_scale'], where + '.rate_scale', 0)
    r = s.get('rate_per_s')
    if isinstance(r, dict):
        for p, v in r.items():
            _num(v, '%s.rate_per_s.%s' % (where, p), 0)
    elif r is not None:
        _num(r, where + '.rate_per_s', 0)
    if 'methods' in s:
        _mix(s['methods'], where + '.methods')
    if 'size_bytes' in s:
        sz = s['size_bytes']
        _keys(sz, {'median': False, 'sigma': False, 'max': False}, where + '.size_bytes')
        if 'median' in sz:
            _num(sz['median'], where + '.size_bytes.median', 0, strict=True)
        if 'sigma' in sz:
            _num(sz['sigma'], where + '.size_bytes.sigma', 0)
    for k in ('split_host', 'large_header'):
        if k in s:
            _num(s[k], '%s.%s' % (where, k), 0)
            if s[k] > 1:
                raise HLError('%s.%s: a fraction, at most 1' % (where, k))


def _site(s, where):
    _keys(s, SITE, where)
    if s['hosting'] not in HOSTING:
        raise HLError('%s.hosting: must be one of %s' % (where, HOSTING))
    _num(s['ttl'], where + '.ttl', 0, strict=True)
    if s.get('dns') is not None:
        _keys(s['dns'], SITE_DNS, where + '.dns')


def canonical_sha256(doc):
    """Hash of the scenario content (provenance excluded)."""
    body = {k: v for k, v in doc.items() if k != 'provenance'}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def load(path):
    with open(path) as f:
        doc = yaml.safe_load(f)
    return check(doc)


# ---- dump -----------------------------------------------------------
def _flow(obj):
    text = yaml.safe_dump(obj, default_flow_style=True, sort_keys=False,
                          width=float('inf'))
    if text.endswith('\n...\n'):          # a plain scalar ends the YAML document
        text = text[:-4]
    return text.strip()


def _block(obj, indent):
    text = yaml.safe_dump(obj, default_flow_style=None, sort_keys=False,
                          width=float('inf'))
    pad = ' ' * indent
    return ''.join(pad + line + '\n' for line in text.splitlines())


def dumps(doc):
    """YAML text: one line per prefix, endpoint, site, entry and event."""
    doc = copy.deepcopy(doc)
    out = ['format: %s\n' % _flow(doc['format']),
           'seed: %s\n' % _flow(doc['seed']),
           'duration_s: %s\n' % _flow(doc['duration_s']),
           'topology: %s\n' % _flow(doc['topology'])]
    if doc.get('provenance') is not None:
        out.append('provenance:\n' + _block(doc['provenance'], 2))
    w = doc['world']
    out.append('\nworld:\n')
    out.append('  external_prefixes:\n')
    out += ['    - %s\n' % _flow(p) for p in w['external_prefixes']]
    if w.get('cache_views'):
        out.append('  cache_views:\n')
        out += ['    %s: %s\n' % (_flow(c), _flow(p)) for c, p in w['cache_views'].items()]
    out.append('  endpoints:\n')
    out += ['    - %s\n' % _flow(e) for e in w['endpoints']]
    out.append('  orgs:\n')
    for o in w['orgs']:
        out.append('    - org: %s\n      targeted: %s\n      sites:\n'
                   % (_flow(o['org']), _flow(o['targeted'])))
        out += ['        - %s\n' % _flow(s) for s in o['sites']]
    out.append('  blocklist:%s\n' % ('' if w.get('blocklist') else ' []'))
    out += ['    - %s\n' % _flow(e) for e in w.get('blocklist') or []]
    out.append('\ndemand:\n' + _block(doc['demand'], 2))
    out.append('\nevents:%s\n' % ('' if doc['events'] else ' []'))
    out += ['  - %s\n' % _flow(it) for it in doc['events']]
    return ''.join(out)


def dump(doc, path):
    with open(path, 'w') as f:
        f.write(dumps(doc))
