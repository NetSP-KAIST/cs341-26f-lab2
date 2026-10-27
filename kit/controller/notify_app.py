"""Kit notification listener.

The run's orchestrator connects to a Unix socket and sends the timeline's
controller-facing events, one JSON object per line; each gets one reply line:

    -> {"seq": 17, "t": 12.5, "ev": "route_change", "prefix": "198.18.4.0/24", "to": "E2"}
    <- {"ack": 17, "ok": true, "flow_mods": 23, "late": [], "applied_wall": 1792814000.123}

Routing events are applied to table 200 by RoutingApp and acknowledged by a
barrier from every changed switch before the team event is emitted and the
reply is sent. Socket path: $LAB2_NOTIFY_SOCK, else controller.notify_socket,
else <run dir>/notify.sock.

Bootstrap (kit.run): the orchestrator plays the t = 0 events, then sends
{"ev": "bootstrap"}; the reply comes when bootstrap ends (KitBase.bootstrap_wait:
the team's ready() or the timeout) and carries the 'bootstrap_end' summary.

Team API: get_blocklist(), ready(), and the events in kit.controller.events.
"""

import json
import os
import socket
import threading
import time

from os_ken.base import app_manager
from os_ken.lib import hub
from os_ken.ofproto import ofproto_v1_3

from kit.config import load_config, resolve_path
from kit.controller.base_app import config_path
from kit.controller.events import (TEAM_EVENTS, EventBlocklistOrder, EventBootstrap,
                                   EventRoutingChanged, EventTENotice)
from kit.log import JsonlLog, run_dir
from kit.sim.blocklist import Blocklist

BARRIER_TIMEOUT_S = 2.0


def get_blocklist():
    """The blocklist in force: [{'entry': {...}, 'order_id': 'o0003'}], or None
    when the kit's NotifyApp is not running."""
    app = app_manager.lookup_service_brick('NotifyApp')
    return None if app is None else app.blocklist_entries()


def ready():
    """Tell the kit the team's rules for the state at t = 0 are in place: the
    bootstrap phase ends and the scenario clock starts (simulator.md §1). Call
    it from (or after) your EventBootstrap handler; earlier calls are
    ignored. Returns True if this call ended bootstrap."""
    kit = app_manager.lookup_service_brick('KitBase')
    if kit is None:
        return False
    return kit.ready()


def _team_entry(e):
    """Entry as teams see it (the endpoint id is for ground truth only)."""
    e = dict(e)
    e.pop('id', None)
    return e


class NotifyApp(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = TEAM_EVENTS

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cfg = load_config(config_path())
        p = (os.environ.get('LAB2_NOTIFY_SOCK')
             or self.cfg['controller'].get('notify_socket'))
        self.sock_path = str(resolve_path(p)) if p else str(run_dir(self.cfg) / 'notify.sock')
        self.blocklist = Blocklist()
        self.bl_lock = threading.Lock()
        self.log = None

    def start(self):
        t = super().start()
        kit = app_manager.lookup_service_brick('KitBase')
        self.log = kit.kit_log if kit is not None else JsonlLog(run_dir(self.cfg) /
                                                                 'kit_events.jsonl')
        hub.spawn(self._serve)
        return t

    # ---- team API -----------------------------------------------------
    def blocklist_entries(self):
        with self.bl_lock:
            return [{'entry': _team_entry(x['entry']), 'order_id': x['order_id']}
                    for x in self.blocklist.entries()]

    def _emit(self, ev):
        kit = app_manager.lookup_service_brick('KitBase')
        if kit is not None:
            kit.deliver(self, ev)           # never blocks on a slow team app
        else:
            self.send_event_to_observers(ev)

    # ---- socket -------------------------------------------------------
    def _serve(self):
        try:
            os.unlink(self.sock_path)
        except FileNotFoundError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.sock_path)
        os.chmod(self.sock_path, 0o660)
        srv.listen(4)
        self.logger.info('notify socket %s', self.sock_path)
        self.log.write('notify_listen', path=self.sock_path)
        while True:
            conn, _ = srv.accept()
            hub.spawn(self._conn, conn)

    def _conn(self, conn):
        f = conn.makefile('rwb')
        try:
            for line in f:
                if not line.strip():
                    continue
                try:
                    req = json.loads(line)
                    reply = self.handle(req)
                except ValueError as ex:
                    reply = {'ack': None, 'ok': False, 'error': 'bad request: %s' % ex}
                f.write((json.dumps(reply) + '\n').encode())
                f.flush()
        except OSError:
            pass
        finally:
            conn.close()

    # ---- events -------------------------------------------------------
    def handle(self, req):
        seq, kind = req.get('seq'), req.get('ev')
        t = req.get('t')
        start = time.time()
        reply = {'ack': seq, 'ok': True}
        try:
            fn = getattr(self, '_on_' + str(kind), None)
            if fn is None:
                raise ValueError('unknown event %r' % kind)
            reply.update(fn(req, t) or {})
        except Exception as ex:          # reply with the error; keep serving
            reply.update(ok=False, error='%s: %s' % (type(ex).__name__, ex))
            self.logger.exception('notify %s failed', kind)
        reply['applied_wall'] = round(time.time(), 6)
        self.log.write('notify', seq=seq, scenario_t=t, event=kind, ok=reply['ok'],
                       ms=round((time.time() - start) * 1000, 1),
                       **{k: v for k, v in reply.items()
                          if k in ('flow_mods', 'late', 'error')})
        return reply

    def _routing(self):
        r = app_manager.lookup_service_brick('RoutingApp')
        if r is None:
            raise RuntimeError('RoutingApp is not running')
        return r

    def _on_hello(self, req, t):
        return {}

    def _on_bootstrap(self, req, t):
        kit = app_manager.lookup_service_brick('KitBase')
        if kit is None:
            return {'ended_by': 'no_kit_base'}
        return kit.bootstrap_wait(
            lambda: self._emit(EventBootstrap(kit.bootstrap_timeout)))

    def _on_route_change(self, req, t):
        old, changed, n, late = self._routing().relocate(req['prefix'], req['to'],
                                                         BARRIER_TIMEOUT_S)
        self._emit(EventRoutingChanged('bgp', t, changed,
                                       {'prefix': req['prefix'], 'from': old,
                                        'to': req['to']}))
        return {'flow_mods': n, 'late': late}

    def _link(self, req, t, up):
        a, b = req['link'].split('-')
        changed, n, late = self._routing().set_link(a, b, up, BARRIER_TIMEOUT_S)
        self._emit(EventRoutingChanged('link_up' if up else 'link_down', t, changed,
                                       {'link': req['link']}))
        return {'flow_mods': n, 'late': late}

    def _on_link_down(self, req, t):
        return self._link(req, t, False)

    def _on_link_up(self, req, t):
        return self._link(req, t, True)

    def _on_te_notice(self, req, t):
        self._emit(EventTENotice(req['te_id'], t, req['apply_at']))
        return {}

    def _on_te_reoptimize(self, req, t):
        changed, n, late = self._routing().apply_te(req['weights'], BARRIER_TIMEOUT_S)
        self._emit(EventRoutingChanged('te', t, changed,
                                       {'te_id': req['te_id'], 'weights': req['weights']}))
        return {'flow_mods': n, 'late': late}

    def _on_blocklist_order(self, req, t):
        add, remove = req.get('add') or [], req.get('remove') or []
        with self.bl_lock:
            self.blocklist.apply_order(req['order_id'], add, remove)
        self._emit(EventBlocklistOrder(req['order_id'], t,
                                       [_team_entry(e) for e in add],
                                       [_team_entry(e) for e in remove]))
        return {'entries': len(self.blocklist)}
