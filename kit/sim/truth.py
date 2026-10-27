"""Ground truth per request, and the join with client logs (docs/kit/simulator.md §4, §5).

    python -m kit.sim.truth runs/x/scenario.jsonl -o runs/x/truth.jsonl
    python -m kit.sim.truth runs/x/scenario.jsonl --requests runs/x/requests.jsonl \
        -o runs/x/outcomes.jsonl

A request should be blocked if, at its time (orders at the same t apply first):
  its site name matches a domain or suffix entry, or
  an IP it contacts matches an ip entry (expect_ip, plus the endpoint IP for
  ext_resolver / encrypted_dns), or
  it used a listed endpoint.
servable: expect_ip serves the site at that time (server_content); a fact
from the timeline, not an outcome class.
Outcome classes (docs/kit/simulator.md §5): failed_to_block, blocked, failed_to_serve,
served, missing (see classify()).
"""

import argparse
import json
import sys
from pathlib import Path
from collections import defaultdict

from kit.sim import timeline
from kit.sim.blocklist import Blocklist

STATE_EVENTS = ('blocklist_order', 'server_content')


def _replay_order(events):
    """State events at time t go before requests at the same t."""
    return sorted(events, key=lambda e: (e['t'], e['ev'] == 'request', e['seq']))


def compute(header, events):
    """[truth row] in request order."""
    ports = {e['ip']: e.get('port') for e in header.get('endpoints', ())}
    bl = Blocklist()
    serving = defaultdict(set)
    rows = []
    for e in _replay_order(events):
        k = e['ev']
        if k == 'blocklist_order':
            bl.apply_order(e['order_id'], e.get('add', ()), e.get('remove', ()))
        elif k == 'server_content':
            (serving[e['site']].add if e['op'] == 'serve' else serving[e['site']].discard)(e['ip'])
        elif k == 'request':
            ep = e.get('endpoint')
            ips = [e.get('expect_ip')] + ([ep] if ep else [])
            hit = bl.match(e['site'], ips, (ep, ports.get(ep)) if ep else None)
            rows.append({
                'id': e['id'], 't': e['t'], 'client': e['client'], 'site': e['site'],
                'method': e['method'], 'expect_ip': e.get('expect_ip'), 'endpoint': ep,
                'should_block': hit is not None, 'reason': hit,
                'servable': e.get('expect_ip') in serving[e['site']],
            })
    rows.sort(key=lambda r: r['id'])
    return rows


def classify(row, log):
    """Outcome class for one request.

    "Obtained" means result "ok": HTTP 200 with the content marker of the site
    asked for. A block page is "wrong_content", so it is not obtained.
      failed_to_block   should be blocked, content obtained
      blocked           should be blocked, not obtained
      failed_to_serve   allowed, not obtained, for any reason (the raw `result`
                        and the timeline are there to attribute causes)
      served            allowed, obtained
      missing           no client log line
    """
    if log is None:
        return 'missing'
    ok = log.get('result') == 'ok'
    if row['should_block']:
        return 'failed_to_block' if ok else 'blocked'
    return 'served' if ok else 'failed_to_serve'


def join(rows, logs):
    """truth rows + requests.jsonl records (by id) -> outcome rows."""
    by_id = {}
    for r in logs:
        by_id[r['id']] = r
    out = []
    for row in rows:
        log = by_id.get(row['id'])
        o = dict(row)
        if log is not None:
            for k in ('t_sched', 't_start', 't_end', 'src_ip', 'fallback_from',
                      'resolved_ip', 'result', 'http_status', 'dns_error', 'error',
                      'bytes', 'content_ok'):
                if k in log:
                    o[k] = log[k]
            if log.get('resolved_ip') and row['expect_ip']:
                o['ip_mismatch'] = log['resolved_ip'] != row['expect_ip']
        o['outcome'] = classify(o, log)
        out.append(o)
    return out


def summarize(rows):
    c = defaultdict(int)
    for r in rows:
        c[r.get('outcome', 'should_block' if r['should_block'] else 'allowed')] += 1
    return dict(sorted(c.items()))


def _read_jsonl(path):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def read_logs(paths):
    """Client log records from files and/or directories of *.jsonl."""
    out = []
    for p in paths:
        p = Path(p)
        for f in sorted(p.glob('*.jsonl')) if p.is_dir() else [p]:
            out.extend(_read_jsonl(f))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog='python -m kit.sim.truth', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('scenario')
    ap.add_argument('--requests', nargs='+', metavar='PATH',
                    help='client logs to join: files, or directories of *.jsonl')
    ap.add_argument('-o', '--out', required=True)
    args = ap.parse_args(argv)
    header, events = timeline.read(args.scenario)
    rows = compute(header, events)
    if args.requests:
        rows = join(rows, read_logs(args.requests))
    with open(args.out, 'w') as f:
        for r in rows:
            f.write(json.dumps(r) + '\n')
    print('%s: %d requests %s' % (args.out, len(rows), summarize(rows)), file=sys.stderr)


if __name__ == '__main__':
    main()
