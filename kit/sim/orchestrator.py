"""Timeline playback for routing and controller notifications.

Data-plane events (server_content, dns_record, request) are played by the
agents themselves (kit.sim.agent). The orchestrator plays the rest, in
timeline order, on the shared scenario clock:

  route_change   add the prefix's local route on the new exit, notify the
                 controller and wait for its ack (table 200 updated and
                 barrier-confirmed), then remove the route on the old exit.
                 There is no moment when no host answers for the prefix.
  link_down/up   set the Mininet link down / up, then notify.
  te_notice, te_reoptimize, blocklist_order
                 notify.

A reply slower than REPLY_TIMEOUT_S is logged and playback goes on; events
are never dropped or reordered. Log: <run dir>/orchestrator.jsonl.

Bootstrap (simulator.md §1): bootstrap() plays the t = 0 events before the
clock starts, then asks the controller to end its bootstrap phase (the
team's ready() or the controller's timeout); start_at() plays the rest.
"""

import json
import socket
import threading
import time

from kit.net.hosts import attach_prefix, detach_prefix
from kit.sim import timeline

KINDS = ('route_change', 'link_down', 'link_up', 'te_notice', 'te_reoptimize',
         'blocklist_order')
REPLY_TIMEOUT_S = 2.0
PASS_THROUGH = ('origin',)       # fields not sent to the controller


class NotifyClient:
    def __init__(self, path, connect_timeout=20.0):
        end = time.time() + connect_timeout
        while True:
            try:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(path)
                break
            except OSError:
                self.sock.close()
                if time.time() > end:
                    raise RuntimeError('controller notify socket %s not reachable' % path)
                time.sleep(0.2)
        self.buf = b''

    def request(self, req, timeout=REPLY_TIMEOUT_S):
        """Send one event; the reply with ack == req['seq'], or None on timeout.
        Late replies to earlier requests are skipped."""
        self.sock.sendall((json.dumps(req) + '\n').encode())
        end = time.time() + timeout
        while True:
            while b'\n' in self.buf:
                line, self.buf = self.buf.split(b'\n', 1)
                reply = json.loads(line)
                if reply.get('ack') == req.get('seq'):
                    return reply
            left = end - time.time()
            if left <= 0:
                return None
            self.sock.settimeout(left)
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                return None
            if not chunk:
                raise RuntimeError('controller closed the notify socket')
            self.buf += chunk

    def close(self):
        self.sock.close()


class Orchestrator(threading.Thread):
    def __init__(self, net, header, scenario, notify_path, log_path):
        super().__init__(name='orchestrator', daemon=True)
        self.net = net
        self.events = list(timeline.iter_events(scenario, KINDS))
        self.location = {p['cidr']: p['host'] for p in header['prefixes']}
        self.client = NotifyClient(notify_path)
        hello = self.client.request({'seq': 0, 'ev': 'hello'})
        if not hello or not hello.get('ok'):
            raise RuntimeError('controller did not answer hello: %r' % (hello,))
        self.log = open(log_path, 'a', buffering=1)
        self.t0 = None
        self.done = threading.Event()
        self._halt = threading.Event()
        self.errors = 0

    def bootstrap(self, wait_s):
        """Play the t = 0 events now, then wait (up to wait_s) for the
        controller to end bootstrap. Returns its summary, or None."""
        n = 0
        while n < len(self.events) and self.events[n]['t'] <= 0:
            n += 1
        first, self.events = self.events[:n], self.events[n:]
        start = time.time()
        for e in first:
            self.play(e)
        reply = self.client.request({'seq': 'bootstrap', 'ev': 'bootstrap'}, timeout=wait_s)
        ok = bool(reply and reply.get('ok'))
        self.errors += not ok
        self._write({'ev': 'bootstrap', 'events': n, 'ok': ok,
                     'ms': round((time.time() - start) * 1000, 1),
                     'reply': reply})
        return reply

    def start_at(self, t0):
        self.t0 = t0
        self.start()

    def stop(self):
        self._halt.set()

    def _write(self, rec):
        self.log.write(json.dumps(rec) + '\n')

    def run(self):
        try:
            for e in self.events:
                delay = self.t0 + e['t'] - time.time()
                if delay > 0 and self._halt.wait(delay):
                    return
                self.play(e)
        finally:
            self.done.set()

    def play(self, e):
        start = time.time()
        req = {k: v for k, v in e.items() if k not in PASS_THROUGH}
        kind, extra = e['ev'], {}
        if kind == 'route_change':
            prefix, new = e['prefix'], e['to']
            old = self.location.get(prefix)
            if old != new:
                attach_prefix(self.net.get(new), prefix)
            reply = self.client.request(req)
            if old is not None and old != new:
                detach_prefix(self.net.get(old), prefix)
            self.location[prefix] = new
            extra = {'from': old, 'to': new}
        elif kind in ('link_down', 'link_up'):
            a, b = e['link'].split('-')
            self.net.configLinkStatus(a, b, 'down' if kind == 'link_down' else 'up')
            reply = self.client.request(req)
        else:
            reply = self.client.request(req)
        ok = bool(reply and reply.get('ok'))
        self.errors += not ok
        lag = None if self.t0 is None else round((start - self.t0 - e['t']) * 1000, 1)
        self._write(dict({'seq': e['seq'], 't': e['t'], 'ev': kind, 'lag_ms': lag,
                          'bootstrap': self.t0 is None,
                          'ms': round((time.time() - start) * 1000, 1), 'ok': ok,
                          'reply': reply if not ok else None,
                          'flow_mods': (reply or {}).get('flow_mods')}, **extra))
