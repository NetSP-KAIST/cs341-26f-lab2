"""Run config loading (configs/*.yaml).

`null` marks an unset key. `open_keys()` lists them so the kit can report
them; in `eval` mode every budget must be set (a null U_burst means U).
"""

import os
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = 1
SECTIONS = ('topology', 'pipeline', 'controller', 'budgets', 'simulator', 'logging')
MAX_TABLE_ID = 254
TIE_BREAKS = ('link_order',)


class ConfigError(ValueError):
    pass


def resolve_path(p):
    """Relative paths in configs are relative to the repo root."""
    p = Path(os.path.expanduser(str(p)))
    return p if p.is_absolute() else REPO_ROOT / p


def open_keys(tree, prefix=''):
    """Dotted paths of every key whose value is null."""
    out = []
    if isinstance(tree, dict):
        for k, v in tree.items():
            path = '%s.%s' % (prefix, k) if prefix else str(k)
            if v is None:
                out.append(path)
            else:
                out.extend(open_keys(v, path))
    return out


def config_open_keys(cfg):
    """open_keys() of a run config, without `simulator` (where null turns a process off)."""
    return open_keys({k: v for k, v in cfg.items() if k != 'simulator'})


def load_config(path):
    path = resolve_path(path)
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    if cfg.get('version') != SCHEMA_VERSION:
        raise ConfigError('%s: version must be %d' % (path, SCHEMA_VERSION))
    for s in SECTIONS:
        if not isinstance(cfg.get(s), dict):
            raise ConfigError('%s: missing section %r' % (path, s))
    if cfg.get('mode', 'dev') not in ('dev', 'eval'):
        raise ConfigError('mode must be dev or eval')
    if not cfg['topology'].get('file'):
        raise ConfigError('topology.file is required')

    routing = cfg['topology'].setdefault('routing', {})
    routing.setdefault('metric', 'hops')
    routing.setdefault('priority_base', 1000)
    routing.setdefault('tie_break', 'link_order')
    if routing['metric'] not in ('hops', 'weight', 'delay'):
        raise ConfigError('topology.routing.metric must be hops, weight or delay')
    if routing['tie_break'] not in TIE_BREAKS:
        raise ConfigError('topology.routing.tie_break must be one of %s' % (TIE_BREAKS,))
    defaults = cfg['topology'].setdefault('defaults', {})
    defaults.setdefault('link_mtu', 1600)
    mtu = defaults['link_mtu']
    if not (isinstance(mtu, int) and 1500 <= mtu <= 9000):
        raise ConfigError('topology.defaults.link_mtu must be an integer in 1500..9000')

    pipe = cfg['pipeline']
    pipe.setdefault('team_tables', 4)
    pipe.setdefault('routing_table', 200)
    pipe.setdefault('hairpin_table', 201)
    n, rt, ht = pipe['team_tables'], pipe['routing_table'], pipe['hairpin_table']
    if not (isinstance(n, int) and 1 <= n <= MAX_TABLE_ID):
        raise ConfigError('pipeline.team_tables must be an integer in 1..%d' % MAX_TABLE_ID)
    if not (isinstance(rt, int) and n <= rt < MAX_TABLE_ID):
        raise ConfigError('pipeline.routing_table must be in %d..%d (after the team tables)'
                          % (n, MAX_TABLE_ID - 1))
    if not (isinstance(ht, int) and rt < ht <= MAX_TABLE_ID):
        raise ConfigError('pipeline.hairpin_table must be in %d..%d (after the routing table)'
                          % (rt + 1, MAX_TABLE_ID))

    b = cfg['budgets']
    k, u = b.get('K_per_switch'), b.get('U_rule_changes_per_s')
    u_burst = b.get('U_burst') if b.get('U_burst') is not None else u
    if k is not None and u_burst is not None and u_burst < k:
        raise ConfigError('budgets.U_burst (or U) must be >= K_per_switch: a delete over '
                          'a full switch costs up to K')
    if cfg['mode'] == 'eval':
        # U_burst null is the default (= U), not an open budget
        unset = [k for k in open_keys(b) if not k.startswith('enforcement') and k != 'U_burst']
        if unset:
            raise ConfigError('eval mode needs every budget set; null: %s' % ', '.join(unset))
    cfg['_path'] = str(path)
    return cfg


def load_topology_for(cfg, scenario=None):
    """The run's topology; with a scenario.jsonl, plus the prefixes in its header."""
    from kit.topology import load_topology
    topo = load_topology(resolve_path(cfg['topology']['file']))
    if scenario:
        from kit.sim.timeline import read_header
        for p in read_header(scenario)['prefixes']:
            topo.add_prefix(p['cidr'], p['host'], allow_client=p.get('kind') == 'clients')
    return topo
