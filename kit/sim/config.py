"""`simulator:` config: defaults, preset merging, validation.

DEFAULTS is the default scenario (simulator.md §7); a preset and then the run
config's keys are merged over it. `null` turns a random process off. Unknown
keys are errors, so typos do not silently fall back to a default.
"""

import copy

import yaml

from kit.config import ConfigError, resolve_path

DEFAULTS = {
    'preset': None,            # path to a YAML file merged under the run config's keys
    'duration_s': 150,
    'timeline': None,          # path to a ready scenario.jsonl; skips generation
    'world': {
        'external_prefixes': 60,          # M /24s from 198.18.0.0/15
        'exit_weights': {'E1': 6, 'E2': 3, 'E3': 1},   # exits missing here weigh 1
        'orgs': 200,                      # registrable domains
        'sites_per_org': [1, 4],          # site names per org (inclusive range)
        'targeted_orgs': 0.25,            # orgs whose content orders go after
        'initially_listed': 0.7,          # targeted sites listed by the t = 0 order
        # > 0: the t = 0 chance per site ~ popularity ** -bias (same mean), so popular
        # targets are left to later orders; 0 = equal chance
        'initial_listing_bias': 1.0,
        'shared_ip': 0.2,                 # targeted sites placed on an allowed site's IP
        'hosting': {'external': 0.7, 'cache': 0.1, 'domestic': 0.2},
        'ttl_s': {'normal': 60, 'short': 10},   # short: fast-flux sites
        'endpoints': {'ext_resolver': 2, 'encrypted_dns': 1},
        'endpoints_initially_listed': 0.5,
    },
    'demand': {
        'requests_per_s_per_pop': 10.0,
        # rate multiplier per PoP; missing PoPs weigh 1. Big metro PoPs at the core,
        # small single-homed / chained ones (isp_v2; other topologies ignore unknown PoPs)
        'pop_weights': {'P1': 2.0, 'P2': 1.6, 'P3': 1.6, 'P4': 1.3, 'P5': 1.3, 'P6': 1.2,
                        'P17': 0.5, 'P18': 0.5, 'P19': 0.4, 'P20': 0.3},
        'subscribers_per_pop': 200,
        # targeted_share: the share of request weight on targeted content (Zipf or
        # uniform within each class); null = one ranking over all content
        'popularity': {'dist': 'zipf', 's': 1.0, 'targeted_share': 0.50},
        'diurnal': {'period_s': 150, 'amplitude': 0.25},   # one compressed day per run
        # per PoP: each PoP has its own Poisson process (mean_interval_s / pop weight);
        # one event raises that PoP's rate to factor x normal, the extra all to one site
        'flash_crowd': {'mean_interval_s': 1000, 'factor': 5, 'duration_s': 15,
                        'pop_weights': None},
        'size_bytes': {'median': 20000, 'sigma': 1.0, 'max': 2000000},
        'methods': {'dns': 0.87, 'stale_cache': 0.05, 'direct_ip': 0.03,
                    'ext_resolver': 0.03, 'encrypted_dns': 0.02},
        'split_host': 0.02,
        'large_header': 0.02,
    },
    'external': {
        'bgp_change': {'mean_interval_s': 15},
        'dns_change': {'mean_interval_s': 7.5},
        'fast_flux': {'sites': 2, 'rotate_s': 7.5, 'overlap_s': 15},   # overlap = short TTL + 5
        'mirror': {'mean_interval_s': 22.5, 'dns_delay_s': 2.5},
        'shared_ip_join': {'mean_interval_s': 50},
    },
    'blocklist': {
        # order size: [min, max] uniform, or lognormal {median, sigma, max}; each entry
        # is filler (matches nothing, like stale entries in real lists) with p = filler
        'add': {'mean_interval_s': 11.25, 'entries': {'median': 3, 'sigma': 1.0, 'max': 40},
                'filler': 0.2, 'prefer_mirrors': 0.6,
                # later orders pick targets by popularity ** this (0 / null: uniform);
                # the t = 0 order stays uniform
                'popular_targets': 0.5},
        'remove': {'mean_interval_s': 75},
        'entry_mix': {'domain': 0.45, 'suffix': 0.1, 'ip': 0.35, 'endpoint': 0.1},
    },
    'hosting_customers': {
        'start_blocked': {'mean_interval_s': 75},
        'stop': {'mean_interval_s': 75},
    },
    'isp': {
        'te': {'interval_s': 30, 'notice_s': 5},     # notice not compressed with the run
        'failure': {'mean_interval_s': None, 'duration_s': 15},
    },
    'scripted': [],
}

# dict-valued keys replaced as a whole, not merged key by key: free-form maps, and
# mixes (giving {stale_cache: 1.0} means only stale_cache)
FREE_KEYS = ('world.exit_weights', 'demand.pop_weights', 'demand.flash_crowd.pop_weights',
             'demand.methods', 'world.hosting',
             'world.endpoints', 'blocklist.entry_mix')
# keys that were renamed: old path -> new path (an old key is an error naming the new one)
RENAMED = {'demand.large_request': 'demand.large_header'}
# keys that were removed: path -> what to use instead
REMOVED = {'blocklist.bulk': 'there is one order kind: set the order size distribution in '
                             'blocklist.add.entries ([min, max] or {median, sigma, max}) and '
                             'the filler fraction in blocklist.add.filler'}
SCRIPTED_KINDS = ('flash_crowd', 'bgp_change', 'mirror', 'order', 'block', 'unblock',
                  'link_failure')
SCRIPTED_RENAMED = {'bulk_order': 'order'}


def _merge(base, over, path=''):
    for k, v in over.items():
        p = '%s.%s' % (path, k) if path else k
        if k not in base:
            if p in RENAMED:
                raise ConfigError('simulator.%s was renamed to simulator.%s' % (p, RENAMED[p]))
            if p in REMOVED:
                raise ConfigError('simulator.%s was removed: %s' % (p, REMOVED[p]))
            raise ConfigError('simulator.%s: unknown key' % p)
        if isinstance(base[k], dict) and isinstance(v, dict) and p not in FREE_KEYS:
            _merge(base[k], v, p)
        elif v is None and isinstance(base[k], dict) and p not in FREE_KEYS:
            # `process: null` turns a process off: its interval (or period) becomes
            # null, or fast_flux gets 0 sites
            off = [(x, None) for x in ('mean_interval_s', 'interval_s', 'period_s')
                   if x in base[k]] + [('sites', 0)] * ('sites' in base[k])
            if not off:
                raise ConfigError('simulator.%s must be a mapping, not null' % p)
            base[k][off[0][0]] = off[0][1]
        else:
            base[k] = copy.deepcopy(v)


def sim_config(cfg):
    """The run config's `simulator:` section merged over the preset and DEFAULTS."""
    sc = copy.deepcopy(DEFAULTS)
    user = dict(cfg.get('simulator') or {})
    preset = user.get('preset')
    if preset:
        with open(resolve_path(preset)) as f:
            p = yaml.safe_load(f) or {}
        p.pop('preset', None)
        _merge(sc, p)
    _merge(sc, user)
    validate(sc)
    return sc


def _frac(v, name):
    if not (isinstance(v, (int, float)) and 0 <= v <= 1):
        raise ConfigError('simulator.%s must be in [0, 1]' % name)


def _mix(d, name, keys):
    if not isinstance(d, dict) or set(d) - set(keys):
        raise ConfigError('simulator.%s: keys must be from %s' % (name, keys))
    if any(not isinstance(v, (int, float)) or v < 0 for v in d.values()) \
            or sum(d.values()) <= 0:
        raise ConfigError('simulator.%s: weights must be >= 0 with a positive sum' % name)


def _interval(d, name):
    v = (d or {}).get('mean_interval_s')
    if v is not None and not (isinstance(v, (int, float)) and v > 0):
        raise ConfigError('simulator.%s.mean_interval_s must be > 0 or null' % name)


def _range(v, name, lo=0):
    if not (isinstance(v, list) and len(v) == 2 and all(isinstance(x, int) for x in v)
            and lo <= v[0] <= v[1]):
        raise ConfigError('simulator.%s must be [min, max] integers, %d <= min <= max'
                          % (name, lo))


def _size(v, name):
    if isinstance(v, list):
        _range(v, name, 1)
        return
    if not (isinstance(v, dict) and set(v) <= {'median', 'sigma', 'max'} and 'median' in v
            and isinstance(v['median'], (int, float)) and v['median'] > 0
            and isinstance(v.get('sigma', 0), (int, float)) and v.get('sigma', 0) >= 0
            and (v.get('max') is None or (isinstance(v['max'], int) and v['max'] >= 1))):
        raise ConfigError('simulator.%s must be [min, max] integers or '
                          '{median > 0, sigma >= 0, max >= 1}' % name)


def validate(sc):
    if not (isinstance(sc['duration_s'], (int, float)) and sc['duration_s'] > 0):
        raise ConfigError('simulator.duration_s must be > 0')
    w = sc['world']
    if not (isinstance(w['external_prefixes'], int) and 1 <= w['external_prefixes'] <= 512):
        raise ConfigError('simulator.world.external_prefixes must be in 1..512')
    if not (isinstance(w['orgs'], int) and w['orgs'] >= 1):
        raise ConfigError('simulator.world.orgs must be >= 1')
    _range(w['sites_per_org'], 'world.sites_per_org', 1)
    for k in ('targeted_orgs', 'initially_listed', 'shared_ip', 'endpoints_initially_listed'):
        _frac(w[k], 'world.' + k)
    b = w.get('initial_listing_bias')
    if b is not None and not (isinstance(b, (int, float)) and 0 <= b <= 4):
        raise ConfigError('simulator.world.initial_listing_bias must be in [0, 4] or null')
    _mix(w['hosting'], 'world.hosting', ('external', 'cache', 'domestic'))
    for k in ('normal', 'short'):
        if not (isinstance(w['ttl_s'][k], (int, float)) and w['ttl_s'][k] > 0):
            raise ConfigError('simulator.world.ttl_s.%s must be > 0' % k)
    d = sc['demand']
    if not (isinstance(d['requests_per_s_per_pop'], (int, float))
            and d['requests_per_s_per_pop'] >= 0):
        raise ConfigError('simulator.demand.requests_per_s_per_pop must be >= 0')
    if not (isinstance(d['subscribers_per_pop'], int) and 1 <= d['subscribers_per_pop'] <= 65000):
        raise ConfigError('simulator.demand.subscribers_per_pop must be in 1..65000')
    if d['popularity'].get('dist') not in ('zipf', 'uniform'):
        raise ConfigError('simulator.demand.popularity.dist must be zipf or uniform')
    ts = d['popularity'].get('targeted_share')
    if ts is not None and not (isinstance(ts, (int, float)) and 0 < ts < 1):
        raise ConfigError('simulator.demand.popularity.targeted_share must be in (0, 1) or null')
    _mix(d['methods'], 'demand.methods',
         ('dns', 'stale_cache', 'direct_ip', 'ext_resolver', 'encrypted_dns'))
    for k in ('split_host', 'large_header'):
        _frac(d[k], 'demand.' + k)
    _frac(d['diurnal']['amplitude'], 'demand.diurnal.amplitude')
    _interval(d['flash_crowd'], 'demand.flash_crowd')
    for name, m in (('demand.pop_weights', d['pop_weights']),
                    ('demand.flash_crowd.pop_weights', d['flash_crowd'].get('pop_weights'))):
        if m is not None and (not isinstance(m, dict) or any(
                not isinstance(v, (int, float)) or v < 0 for v in m.values())):
            raise ConfigError('simulator.%s must map PoP names to weights >= 0' % name)
    for k, v in sc['external'].items():
        _interval(v, 'external.' + k)
    _interval(sc['blocklist']['add'], 'blocklist.add')
    _size(sc['blocklist']['add']['entries'], 'blocklist.add.entries')
    _frac(sc['blocklist']['add']['filler'], 'blocklist.add.filler')
    if sc['blocklist']['add']['filler'] >= 1:
        raise ConfigError('simulator.blocklist.add.filler must be below 1')
    _frac(sc['blocklist']['add']['prefer_mirrors'], 'blocklist.add.prefer_mirrors')
    pt = sc['blocklist']['add'].get('popular_targets')
    if pt is not None and not (isinstance(pt, (int, float)) and 0 <= pt <= 4):
        raise ConfigError('simulator.blocklist.add.popular_targets must be in [0, 4] or null')
    _interval(sc['blocklist']['remove'], 'blocklist.remove')
    _mix(sc['blocklist']['entry_mix'], 'blocklist.entry_mix',
         ('domain', 'suffix', 'ip', 'endpoint'))
    for k, v in sc['hosting_customers'].items():
        _interval(v, 'hosting_customers.' + k)
    te = sc['isp']['te']
    if te.get('interval_s') is not None:
        if not (te['interval_s'] > 0 and 0 <= te.get('notice_s', 0) < te['interval_s']):
            raise ConfigError('simulator.isp.te: need interval_s > 0 and '
                              '0 <= notice_s < interval_s')
    _interval(sc['isp']['failure'], 'isp.failure')
    if not isinstance(sc['scripted'], list):
        raise ConfigError('simulator.scripted must be a list')
    for i, s in enumerate(sc['scripted']):
        if isinstance(s, dict) and s.get('ev') in SCRIPTED_RENAMED:
            raise ConfigError('simulator.scripted[%d]: ev %s was renamed to %s' % (
                i, s['ev'], SCRIPTED_RENAMED[s['ev']]))
        if not isinstance(s, dict) or not isinstance(s.get('t'), (int, float)) \
                or not (s.get('ev') in SCRIPTED_KINDS or s.get('ev') in _raw_events()):
            raise ConfigError('simulator.scripted[%d]: needs t and ev (one of %s, '
                              'or a timeline event)' % (i, SCRIPTED_KINDS))


def _raw_events():
    from kit.sim.timeline import EVENTS
    return EVENTS
