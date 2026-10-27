"""Start the lab network from a run config.

    sudo .venv/bin/python -m kit.net.run -c configs/default.yaml [--cli] [--check]

The controller runs separately (as a normal user):

    .venv/bin/osken-manager --lab2-config configs/default.yaml kit.controller.routing_app

--check waits for every switch to connect, then pings from each client to each
other host and to one address in each destination prefix, and prints a matrix.
"""

import argparse
import sys
import time

from mininet.clean import cleanup
from mininet.cli import CLI
from mininet.log import setLogLevel

from kit.config import load_config, load_topology_for, config_open_keys
from kit.net.build import build_network, start_network


def describe(topo):
    lines = ['topology %s: %d switches, %d links, %d hosts, %d prefixes'
             % (topo.name, len(topo.switches), len(topo.links), len(topo.hosts),
                len(topo.prefixes))]
    for h in topo.hosts.values():
        lines.append('  %-6s %-18s %-15s %s port %d' % (h.id, h.role + '/' + h.kind, h.ip,
                                                      h.switch, h.port))
    for p in topo.prefixes.values():
        lines.append('  prefix %-18s at %s' % (p.cidr, p.host))
    return '\n'.join(lines)


def check(net, topo, timeout=30):
    if not net.waitConnected(timeout=timeout):
        print('not every switch connected to the controller within %ds' % timeout)
        return False
    time.sleep(1.0)
    targets = [(h.id, str(h.ip)) for h in topo.hosts.values()]
    targets += [('%s' % p.cidr, str(p.cidr.network_address + 1)) for p in topo.prefixes.values()]
    ok = True
    for c in (h for h in topo.hosts.values() if h.role == 'client'):
        node = net.get(c.id)
        fails, n = [], 0
        for name, ip in targets:
            if name == c.id:
                continue
            n += 1
            if ' 0% packet loss' not in node.cmd('ping -c1 -W1 %s' % ip):
                fails.append(name)
        ok &= not fails
        print('%-6s %d/%d ok%s' % (c.id, n - len(fails), n,
                                   ('  FAIL: ' + ' '.join(fails)) if fails else ''))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-c', '--config', default='configs/default.yaml')
    ap.add_argument('--cli', action='store_true', help='open the Mininet CLI')
    ap.add_argument('--check', action='store_true', help='connectivity check, then exit')
    args = ap.parse_args()

    cfg = load_config(args.config)
    topo = load_topology_for(cfg)
    setLogLevel('warning')
    print(describe(topo))
    unset = config_open_keys(cfg) + topo.open_keys
    if unset:
        print('unset (null) config keys:', ', '.join(unset))

    cleanup()
    net = build_network(topo, cfg)
    try:
        start_network(net, topo, cfg)
        if args.check:
            sys.exit(0 if check(net, topo) else 1)
        if args.cli:
            CLI(net)
        else:
            print('network up; Ctrl-C to stop')
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        net.stop()


if __name__ == '__main__':
    main()
