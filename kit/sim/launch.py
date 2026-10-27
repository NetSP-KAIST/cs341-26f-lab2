"""Start and stop the simulator agents in a running Mininet network.

    agents = Agents(net, topo, scenario_path, run_dir)
    agents.start(); agents.wait_ready(); t0 = agents.start_clock()
    ...; agents.wait_clients(timeout); agents.stop()

Which agent runs where (by host kind / role):
  external_exit   location --auth-dns --endpoints  (the authoritative DNS and the
                                         resolver / encrypted-DNS endpoints answer
                                         on whichever exit their prefix is routed to)
  cache           location
  resolver        resolver
  pop             location and client (subscribers and hosted sites on one host)
  client          client
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from kit.config import REPO_ROOT

CLOCK_DELAY_S = 1.0


def agent_plan(topo):
    """[(host id, role, extra args)]."""
    out = []
    for h in topo.hosts.values():
        if h.kind == 'external_exit':
            out.append((h.id, 'location', ['--auth-dns', '--endpoints']))
        elif h.kind == 'cache':
            out.append((h.id, 'location', []))
        elif h.role == 'resolver':
            out.append((h.id, 'resolver', []))
        elif h.kind == 'pop':        # subscribers and hosted sites on one host
            out.append((h.id, 'location', []))
            out.append((h.id, 'client', []))
        elif h.role == 'client':
            out.append((h.id, 'client', []))
    return out


class Agents:
    def __init__(self, net, topo, scenario, run_dir, python=sys.executable):
        self.net, self.topo = net, topo
        self.scenario = str(Path(scenario).resolve())
        self.run_dir = Path(run_dir).resolve()
        self.python = python
        self.plan = agent_plan(topo)
        self.procs = {}
        self.t0 = None

    def start(self):
        (self.run_dir / 'agents').mkdir(parents=True, exist_ok=True)
        (self.run_dir / 'requests').mkdir(parents=True, exist_ok=True)
        for p in (self.run_dir / 'clock.json',):
            if p.exists():
                p.unlink()
        for host, role, extra in self.plan:
            name = '%s.%s' % (host, role)
            log = open(self.run_dir / 'agents' / ('%s.out' % name), 'w')
            cmd = [self.python, '-u', '-m', 'kit.sim.agent', role, '--host', host,
                   '--scenario', self.scenario, '--run-dir', str(self.run_dir)] + extra
            self.procs[name] = self.net.get(host).popen(
                cmd, stdout=log, stderr=subprocess.STDOUT, cwd=str(REPO_ROOT),
                env=dict(os.environ, PYTHONPATH=str(REPO_ROOT)))

    def wait_ready(self, timeout=30.0):
        end = time.time() + timeout
        while time.time() < end:
            dead = {h: p.returncode for h, p in self.procs.items() if p.poll() is not None}
            if dead:
                raise RuntimeError('agents exited early: %s (see %s/agents/<host>.<role>.out)'
                                   % (dead, self.run_dir))
            missing = [h for h in self.procs
                       if not (self.run_dir / 'agents' / ('%s.ready' % h)).exists()]
            if not missing:
                return
            time.sleep(0.1)
        raise RuntimeError('agents not ready after %ds: %s' % (timeout, missing))

    def start_clock(self, delay=CLOCK_DELAY_S):
        """Scenario t = 0 is `delay` seconds from now. Returns t0 (wall seconds)."""
        self.t0 = time.time() + delay
        tmp = self.run_dir / 'clock.json.tmp'
        tmp.write_text(json.dumps({'t0': self.t0}))
        os.replace(tmp, self.run_dir / 'clock.json')
        return self.t0

    def clients(self):
        return [h for h, role, _ in self.plan if role == 'client']

    def wait_clients(self, timeout):
        end = time.time() + timeout
        left = self.clients()
        while left and time.time() < end:
            left = [h for h in left
                    if not (self.run_dir / 'agents' / ('%s.done' % h)).exists()]
            time.sleep(0.2)
        return left

    def stop(self):
        for p in self.procs.values():
            if p.poll() is None:
                p.terminate()
        end = time.time() + 5
        for p in self.procs.values():
            try:
                p.wait(max(0.1, end - time.time()))
            except subprocess.TimeoutExpired:
                p.kill()

    def request_logs(self):
        return sorted((self.run_dir / 'requests').glob('*.jsonl'))
