"""scenario.jsonl: read, write, validate (simulator.md §3).

Line 1 is the header; the rest are events sorted by (t, seq), seq unique
and increasing. The orchestrator plays the file as is; everything a run does
comes from it.

This is format v1. The compiler writes it, and the runtime (orchestrator,
agents, truth) reads it.
"""

import ipaddress
import json
import math

FORMAT = 1

# ev -> required fields (besides t, seq, ev)
EVENTS = {
    'route_change': ('prefix', 'to'),
    'te_notice': ('te_id', 'apply_at'),
    'te_reoptimize': ('te_id', 'weights'),
    'link_down': ('link',),
    'link_up': ('link',),
    'dns_record': ('op', 'domain'),
    'server_content': ('op', 'site', 'ip'),
    'blocklist_order': ('order_id',),
    'request': ('id', 'client', 'src_ip', 'site', 'method'),
}
METHODS = ('dns', 'stale_cache', 'direct_ip', 'ext_resolver', 'encrypted_dns')
ENDPOINT_METHODS = ('ext_resolver', 'encrypted_dns')


class TimelineError(ValueError):
    pass


def sort_events(events):
    """Stable sort by t, then assign seq 1..n. Returns the list."""
    events = sorted(events, key=lambda e: e['t'])      # stable: keeps write order
    for i, e in enumerate(events, 1):
        e['seq'] = i
    return events


def _ordered(e):
    """t, seq, ev first, so the file reads well."""
    out = {k: e[k] for k in ('t', 'seq', 'ev') if k in e}
    out.update((k, v) for k, v in e.items() if k not in out)
    return out


def write(path, header, events):
    with open(path, 'w') as f:
        f.write(json.dumps(dict(header, type='header'), sort_keys=False) + '\n')
        for e in events:
            f.write(json.dumps(_ordered(e)) + '\n')


def read_header(path):
    with open(path) as f:
        header = json.loads(f.readline())
    if header.get('type') != 'header' or header.get('format') != FORMAT:
        raise TimelineError('%s: no format %d header' % (path, FORMAT))
    return header


def iter_events(path, kinds=None):
    """Events of the given kinds, without parsing the others (agents use this)."""
    marks = None if kinds is None else [('"ev": "%s"' % k) for k in kinds]
    with open(path) as f:
        f.readline()
        for line in f:
            if marks is None or any(m in line for m in marks):
                e = json.loads(line)
                if kinds is None or e['ev'] in kinds:
                    yield e


def read(path, check=True):
    """(header, events)."""
    header, events = None, []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError as ex:
                raise TimelineError('%s:%d: %s' % (path, n, ex))
            if header is None:
                header = obj
            else:
                events.append(obj)
    if header is None:
        raise TimelineError('%s: empty' % path)
    if check:
        validate(header, events)
    return header, events


def _need(e, keys, where):
    for k in keys:
        if k not in e:
            raise TimelineError('%s: missing %r' % (where, k))


def validate(header, events):
    if header.get('type') != 'header' or header.get('format') != FORMAT:
        raise TimelineError('header: type must be "header" and format %d' % FORMAT)
    _need(header, ('seed', 'duration_s', 'prefixes', 'endpoints'), 'header')
    for p in header['prefixes']:
        ipaddress.IPv4Network(p['cidr'])
    last = (-math.inf, 0)
    for e in events:
        where = 'event seq=%s' % e.get('seq')
        _need(e, ('t', 'seq', 'ev'), where)
        if not isinstance(e['t'], (int, float)) or e['t'] < 0:
            raise TimelineError('%s: t must be a number >= 0' % where)
        if not isinstance(e['seq'], int):
            raise TimelineError('%s: seq must be an integer' % where)
        if (e['t'], e['seq']) <= last or e['seq'] <= last[1]:
            raise TimelineError('%s: events must be sorted by (t, seq), seq increasing'
                                % where)
        last = (e['t'], e['seq'])
        ev = e['ev']
        if ev not in EVENTS:
            raise TimelineError('%s: unknown ev %r' % (where, ev))
        _need(e, EVENTS[ev], where)
        if ev == 'dns_record':
            if e['op'] not in ('set', 'remove'):
                raise TimelineError('%s: dns_record op must be set or remove' % where)
            if e['op'] == 'set':
                _need(e, ('ips', 'ttl'), where)
        elif ev == 'server_content' and e['op'] not in ('serve', 'unserve'):
            raise TimelineError('%s: server_content op must be serve or unserve' % where)
        elif ev == 'request':
            if e['method'] not in METHODS:
                raise TimelineError('%s: method must be one of %s' % (where, METHODS))
            if e['method'] in ENDPOINT_METHODS and not e.get('endpoint'):
                raise TimelineError('%s: method %s needs endpoint' % (where, e['method']))
        elif ev == 'te_notice' and e['apply_at'] < e['t']:
            raise TimelineError('%s: apply_at is before t' % where)
