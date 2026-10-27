"""Kit base layer: budget enforcement between team apps and the switches.

Loaded automatically by `osken-manager --lab2-config ...` (see launcher.py),
before kit.controller.routing_app and the team app. Team apps use the normal
os-ken API; the base layer sits under it:

- Outgoing: Datapath.send_msg is wrapped. Only the basic OpenFlow surface in
  allowlist.py may be sent (flow-mods, packet-outs, barriers, read-only
  stats); anything else is rejected. Flow-mods then go through TeamPolicy
  (table range, kit cookies, priority bump, K, U).
  Kit code sends with kit_send(), which bypasses the policy.
  A rejected message is not sent: send_msg returns False, the rejection is
  logged, and EventBudgetReject is sent to observers. send_msg also returns
  False if the switch connection is gone (nothing is recorded then).
- Incoming: the 'ofp_event' brick's dispatch is wrapped.
  * SwitchFeatures: the kit resets the team tables and installs the default
    table-misses before any app sees the event.
  * FlowRemoved: updates the kit's K bookkeeping; passed on to apps only
    for entries where the team set OFPFF_SEND_FLOW_REM itself.
  * ErrorMsg for a team flow-mod: the switch refused it, so the kit re-reads
    that table at once instead of waiting for the cross-check.
  * PacketIn: delivered to apps through a bounded queue (P_queue_len) at the
    rate the P bucket allows; overflow is dropped and counted.
- P = controller message throughput: Packet-In deliveries (1 token each) and
  team packet-outs (packet_out_cost each) share one network-wide bucket.
  A packet-out goes out at once if the bucket is not in debt (it may push it
  into debt by its cost) and is rejected otherwise; the debt delays the next
  Packet-In. So the total stays at P, re-injecting an inspected packet costs
  2 tokens, and packet-outs are never starved by queued Packet-Ins.
- Stats requests: flow/aggregate stats only for team tables; every stats
  request is rate-capped per switch (controller.stats_requests_per_s_per_switch,
  a fixed kit constraint, not a budget).
- Bootstrap ($LAB2_BOOTSTRAP=1, set by kit.run): from controller start until
  the scenario clock starts, U is not enforced (K, flow_limit and the
  allowlist are). NotifyApp calls bootstrap_wait() once the t = 0 events are
  delivered, which sends EventBootstrap; bootstrap then ends when a team app calls
  notify_app.ready() or after controller.bootstrap_timeout_s, and U starts
  with a full bucket. Team flow-mods sent meanwhile are counted in the
  'bootstrap_end' event (simulator.md §1).
- K cross-check: every k_crosscheck_interval_s the kit compares table stats
  (active_count) with its shadow; on a mismatch it re-reads the table with
  flow stats and replays flow-mods sent meanwhile.
- Logs (JSONL under the run directory): kit_events.jsonl, budgets.jsonl.

Threads (os-ken 4.x runs the 'native' hub: real OS threads). Kit state is
changed from switch receive threads, the team's threads and kit loops, so all
of it is under one lock. Events for team apps go through a per-app relay
thread: a slow or stuck team app never blocks a switch connection or the kit
(only its own Packet-Ins back up, into the P queue).

Bypass: a team app can still write raw bytes with Datapath.send(). That is
forbidden by the handout and caught when staff re-run submissions (drift in
the K cross-check is logged); it is not blocked in code.
"""

import collections
import os
import queue
import threading
import time

from os_ken.base import app_manager
from os_ken.controller import event, ofp_event
from os_ken.controller.controller import Datapath
from os_ken.controller.handler import DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.ofproto import ofproto_v1_3

from kit.config import load_config, open_keys
from kit.controller import allowlist
from kit.controller.budget import TokenBucket
from kit.controller.policy import TeamPolicy
from kit.log import JsonlLog, run_dir

# os-ken 4.2.2 'native' hub defines TaskExit = Exception, so app_manager's
# event loop re-raises any exception from a handler and the app's event
# thread ends silently: one bug in a team handler would freeze that app and,
# once its queue is full, everything that delivers to it. Nothing raises
# TaskExit in the native hub (kill() is a no-op), so a private class is safe.
if getattr(hub, 'HUB_TYPE', None) == 'native' and hub.TaskExit is Exception:
    class _TaskExit(BaseException):
        pass
    hub.TaskExit = _TaskExit

QueueFull = queue.Full          # also what eventlet's queues raise

KIT_APPS = frozenset(['KitBase', 'RoutingApp', 'NotifyApp'])
NOT_TEAM_APPS = KIT_APPS | {'ofp_event'}
TEAM_EVENT_BACKLOG = 10000      # per team app, beyond its own os-ken queue (128)
TEAM_XID_MEMORY = 8192          # recent team flow-mod xids, to match errors
P_BURST_S = 0.01                # P bucket depth, in seconds of P
REJECT_LOG_PER_INTERVAL = 50    # 'reject' lines per kind per sample interval;
                                #   exact counts are always in budgets.jsonl

_ORIG_SEND_MSG = Datapath.send_msg
_HOOK = None


def kit_send(dp, msg):
    """Send without budget checks (kit-internal messages only)."""
    return _ORIG_SEND_MSG(dp, msg)


_BARRIERS = {}                  # (dpid, xid) -> threading.Event, kit barriers in flight
_BARRIER_LOCK = threading.Lock()


def kit_barrier(dp):
    """Send a kit barrier request. Returns its key, or None if the switch is gone.
    The reply is consumed by the base layer (team apps never see it)."""
    msg = dp.ofproto_parser.OFPBarrierRequest(dp)
    dp.set_xid(msg)
    key = (dp.id, msg.xid)
    with _BARRIER_LOCK:
        _BARRIERS[key] = threading.Event()
    if kit_send(dp, msg) is False:
        with _BARRIER_LOCK:
            _BARRIERS.pop(key, None)
        return None
    return key


def wait_barriers(keys, timeout):
    """Wait for kit_barrier() replies. Returns the dpids that did not answer in time."""
    end = time.time() + timeout
    late = []
    for key in keys:
        if key is None:
            continue
        with _BARRIER_LOCK:
            ev = _BARRIERS.get(key)
        if ev is not None and not ev.wait(max(0.0, end - time.time())):
            late.append(key[0])
        with _BARRIER_LOCK:
            _BARRIERS.pop(key, None)
    return late


def _barrier_reply(msg):
    with _BARRIER_LOCK:
        ev = _BARRIERS.get((msg.datapath.id, msg.xid))
    if ev is None:
        return False
    ev.set()
    return True


def _send_msg(self, msg, close_socket=False):
    if _HOOK is None:
        return _ORIG_SEND_MSG(self, msg, close_socket=close_socket)
    return _HOOK(self, msg, close_socket)


Datapath.send_msg = _send_msg


def config_path():
    from os_ken import cfg as oscfg
    try:
        p = oscfg.CONF.lab2_config
    except (oscfg.NoSuchOptError, AttributeError):
        p = None
    return os.environ.get('LAB2_CONFIG') or p or 'configs/default.yaml'


class EventBudgetReject(event.EventBase):
    """A team message was not sent.
    kind: K | U | P | flow_mod | packet_out | message | stats | stats_rate."""

    def __init__(self, dpid, msg, kind, reason):
        super().__init__()
        self.dpid = dpid
        self.msg = msg
        self.kind = kind
        self.reason = reason


class _Relay:
    """Delivers events to one team app, in order, from its own thread, so
    whoever produces the event never waits for the team app."""

    def __init__(self, name, on_drop):
        self.name = name
        self.on_drop = on_drop
        self.q = collections.deque()
        self.cv = threading.Condition()
        hub.spawn(self._loop)

    def put(self, ev, state):
        with self.cv:
            if len(self.q) >= TEAM_EVENT_BACKLOG:
                dropped = True
            else:
                dropped = False
                self.q.append((ev, state))
                self.cv.notify()
        if dropped:
            self.on_drop(self.name, ev)

    def _loop(self):
        while True:
            with self.cv:
                while not self.q:
                    self.cv.wait()
                ev, state = self.q.popleft()
            brick = app_manager.SERVICE_BRICKS.get(self.name)
            if brick is not None:
                brick._send_event(ev, state)        # may block: only this thread


class KitBase(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = [EventBudgetReject]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cfg = cfg = load_config(config_path())
        b = cfg['budgets']
        enf = b.get('enforcement') or {}
        self.n = cfg['pipeline']['team_tables']
        self.routing_table = cfg['pipeline']['routing_table']
        self.K = b.get('K_per_switch')
        self.P = b.get('P_controller_msgs_per_s')
        self.P_queue_len = b.get('P_queue_len')
        self.packet_out_cost = b.get('packet_out_cost', 1)
        if self.packet_out_cost is None or self.packet_out_cost < 0:
            raise ValueError('budgets.packet_out_cost must be a number >= 0')
        if enf.get('U_over_budget', 'reject') != 'reject':
            raise ValueError('budgets.enforcement.U_over_budget: only "reject" is implemented')
        self.u_bucket = TokenBucket(b.get('U_rule_changes_per_s'), b.get('U_burst'))
        # burst: P_BURST_S worth of tokens. With burst 1 the pacer could take only
        # one token per sleep (>= 1 ms), so delivery capped near 900/s whatever P was.
        self.p_bucket = TokenBucket(self.P, max(1.0, (self.P or 0) * P_BURST_S))
        ctl = cfg['controller']
        self.stats_rate = ctl.get('stats_requests_per_s_per_switch', 1.0)
        self.stats_burst = ctl.get('stats_burst_per_switch', 1)
        self.stats_buckets = {}     # dpid -> TokenBucket
        self.crosscheck_s = enf.get('k_crosscheck_interval_s', 5.0)
        self.sample_s = cfg['logging'].get('sample_interval_s', 1.0)
        self.policy = TeamPolicy(self.n, self.routing_table, self.K, self.u_bucket,
                                 cfg['pipeline'].get('restore_default_miss', True))
        self.bootstrap_timeout = ctl.get('bootstrap_timeout_s', 60)
        self.in_bootstrap = os.environ.get('LAB2_BOOTSTRAP') == '1'
        self.policy.u_enforced = not self.in_bootstrap
        self.boot = {'start': time.time(), 'delivered': None, 'flow_mods': 0,
                     'u_cost': 0, 'ready_ignored': 0}
        self.boot_ready = threading.Event()

        d = run_dir(cfg)
        streams = cfg['logging'].get('streams') or {}
        self.kit_log = JsonlLog(d / 'kit_events.jsonl')
        self.budget_log = JsonlLog(d / 'budgets.jsonl') if streams.get('budgets', True) else None
        unset = [k for k in open_keys(b) if not k.startswith('enforcement')]
        self.kit_log.write('start', run_dir=str(d), team_tables=self.n,
                           routing_table=self.routing_table, budgets_unset=unset,
                           hub=getattr(hub, 'HUB_TYPE', None))
        if unset:
            self.logger.info('budgets not enforced (null): %s', ', '.join(unset))
        if self.in_bootstrap:
            self.kit_log.write('bootstrap_start', timeout_s=self.bootstrap_timeout)

        self.lock = threading.RLock()
        self.dps = {}
        self.pin_q = None
        if self.P is not None:      # no length: unbounded (eventlet's Queue(0) is a channel)
            self.pin_q = hub.Queue(self.P_queue_len) if self.P_queue_len else hub.Queue()
        self.pending_tstats = {}    # dpid -> (xid, snapshot, body)
        self.pending_fstats = {}    # (dpid, xid) -> {'table', 'body', 'journal'}
        self.team_xids = collections.OrderedDict()     # (dpid, xid) -> table
        self.relays = {}            # team app name -> _Relay
        self.dropped_logged = set()
        self.reject_logged = {}     # kind -> lines this sample interval
        self.cnt = self._zero_counters()
        self._orig_dispatch = None
        self._brick = None

    @staticmethod
    def _zero_counters():
        return {'pin_rx': {}, 'pin_delivered': 0, 'pin_dropped': 0, 'u_used': 0,
                'rejected': {}, 'bumps': 0, 'restores': 0,
                'packet_out': {}, 'stats_req': {}, 'team_events_dropped': 0,
                'send_failed': 0, 'reject_lines_suppressed': 0}

    def start(self):
        global _HOOK
        t = super().start()
        self._brick = brick = app_manager.lookup_service_brick('ofp_event')
        self._orig_dispatch = brick.send_event_to_observers
        brick.send_event_to_observers = self._dispatch
        _HOOK = self._on_send
        if self.pin_q is not None:
            hub.spawn(self._pin_loop)
        hub.spawn(self._sample_loop)
        if self.crosscheck_s:
            hub.spawn(self._crosscheck_loop)
        return t

    # ---- delivery to apps -----------------------------------------------
    def deliver(self, src, ev, state=None):
        """src.send_event_to_observers(ev, state), except that team apps get
        the event through their relay (never blocks the caller)."""
        for name in src.get_observers(ev, state):
            if name in KIT_APPS:
                src.send_event(name, ev, state)
                continue
            with self.lock:
                relay = self.relays.get(name)
                if relay is None:
                    relay = self.relays[name] = _Relay(name, self._team_event_dropped)
            relay.put(ev, state)

    def _team_event_dropped(self, name, ev):
        with self.lock:
            self.cnt['team_events_dropped'] += 1
            first = name not in self.dropped_logged
            self.dropped_logged.add(name)
        if first:
            self.kit_log.write('team_event_dropped', app=name, event=type(ev).__name__,
                               backlog=TEAM_EVENT_BACKLOG)

    # ---- incoming -------------------------------------------------------
    def _dispatch(self, ev, state=None):
        if isinstance(ev, ofp_event.EventOFPPacketIn):
            dpid = ev.msg.datapath.id
            with self.lock:
                rx = self.cnt['pin_rx']
                rx[dpid] = rx.get(dpid, 0) + 1
                if self.pin_q is None:
                    self.cnt['pin_delivered'] += 1
            if self.pin_q is None:
                self.deliver(self._brick, ev, state)
                return
            try:
                self.pin_q.put_nowait((ev, state))
            except QueueFull:
                with self.lock:
                    self.cnt['pin_dropped'] += 1
            return
        with self.lock:
            if isinstance(ev, ofp_event.EventOFPSwitchFeatures):
                self._on_connect(ev.msg.datapath, ev.msg.datapath_id)
            elif isinstance(ev, ofp_event.EventOFPFlowRemoved):
                if not self._on_flow_removed(ev.msg):
                    return          # expiry the team did not ask to hear about
            elif isinstance(ev, ofp_event.EventOFPTableStatsReply):
                if self._on_table_stats(ev.msg):
                    return          # reply to the kit's own request
            elif isinstance(ev, ofp_event.EventOFPFlowStatsReply):
                if self._on_flow_stats(ev.msg):
                    return
            elif isinstance(ev, ofp_event.EventOFPBarrierReply):
                if _barrier_reply(ev.msg):
                    return          # the kit's own barrier
            elif isinstance(ev, ofp_event.EventOFPErrorMsg):
                self._on_error(ev.msg)
        self.deliver(self._brick, ev, state)

    def _pin_loop(self):
        # Packet-Ins go to the team directly (blocking): a slow team backs up
        # into the bounded P queue, where the overflow is dropped and counted.
        while True:
            ev, state = self.pin_q.get()
            while True:
                with self.lock:         # the bucket is shared with packet-outs
                    if self.p_bucket.take():
                        self.cnt['pin_delivered'] += 1
                        break
                    wait = self.p_bucket.wait_time()
                hub.sleep(max(wait, 0.001))
            self._orig_dispatch(ev, state)

    def _on_connect(self, dp, dpid):
        ofp = dp.ofproto
        self.pending_tstats.pop(dpid, None)
        for key in [k for k in self.pending_fstats if k[0] == dpid]:
            del self.pending_fstats[key]
        for m in self.policy.connect(dp, dpid):
            kit_send(dp, m)
            if isinstance(m, dp.ofproto_parser.OFPFlowMod):
                self.policy.apply(dpid, m, ofp)
        self.kit_log.write('switch_connect', dpid=dpid)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def on_state(self, ev):
        dp = ev.datapath
        with self.lock:
            if ev.state == MAIN_DISPATCHER:
                self.dps[dp.id] = dp
            elif dp.id is not None and self.dps.get(dp.id) is dp:
                del self.dps[dp.id]
                self.kit_log.write('switch_disconnect', dpid=dp.id)

    def _on_flow_removed(self, msg):
        """Kit bookkeeping; True if the team app should see this FlowRemoved."""
        dp = msg.datapath
        known, notify = self.policy.flow_removed(dp.id, msg, dp.ofproto)
        if known:
            self._restore_slots(dp)
        else:
            self.kit_log.write('flow_removed_unknown', dpid=dp.id, table=msg.table_id,
                               priority=msg.priority)
        return notify

    def _on_error(self, msg):
        dp = msg.datapath
        table = self.team_xids.pop((dp.id, msg.xid), None)
        self.kit_log.write('ofp_error', dpid=dp.id, xid=msg.xid, type=msg.type,
                           code=msg.code, team_flow_mod_table=table)
        if table is None:
            return
        # The switch refused a team flow-mod the shadow already applied: drop
        # it from journals of pending re-reads and re-read the table.
        for (dpid, _), p in self.pending_fstats.items():
            if dpid == dp.id:
                p['journal'] = [m for m in p['journal'] if m.xid != msg.xid]
        self._resync(dp, table)

    # ---- outgoing -------------------------------------------------------
    def _on_send(self, dp, msg, close_socket):
        with self.lock:
            return self._on_send_locked(dp, msg, close_socket)

    def _on_send_locked(self, dp, msg, close_socket):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        if not isinstance(msg, allowlist.ALLOWED_MESSAGES):
            return self._reject(dp, msg, 'message', '%s is not allowed for team apps'
                                % type(msg).__name__)
        if isinstance(msg, parser.OFPPacketOut):
            err = allowlist.check_packet_out(msg)
            if err:
                return self._reject(dp, msg, 'packet_out', err)
            if self.P is not None and self.packet_out_cost and \
                    not self.p_bucket.take_debt(self.packet_out_cost):
                return self._reject(dp, msg, 'P', 'P: controller message budget exceeded '
                                    '(packet-out costs %g)' % self.packet_out_cost)
            self._count('packet_out', dp.id)
        if isinstance(msg, allowlist.STATS_REQUESTS):
            err = allowlist.check_stats(msg, self.n)
            if err:
                return self._reject(dp, msg, 'stats', err)
            bucket = self.stats_buckets.get(dp.id)
            if bucket is None:
                bucket = self.stats_buckets[dp.id] = TokenBucket(self.stats_rate,
                                                                 self.stats_burst)
            if not bucket.take():
                return self._reject(dp, msg, 'stats_rate', 'stats requests: at most %s/s '
                                    'per switch' % self.stats_rate)
            self._count('stats_req', dp.id)
        if not isinstance(msg, parser.OFPFlowMod):
            return self._sent(dp, msg, _ORIG_SEND_MSG(dp, msg, close_socket=close_socket))
        err = allowlist.check_flow_mod(msg, self.n, self.routing_table)
        if err:
            return self._reject(dp, msg, 'flow_mod', err)
        d = self.policy.flow_mod(dp, dp.id, msg)
        kind = 'K' if (d.reject or '').startswith('K') else \
            'U' if (d.reject or '').startswith('U') else 'flow_mod'

        if d.reject:
            return self._reject(dp, msg, kind, d.reject)
        for ev_name, fields in d.notes:
            if ev_name == 'priority_bump':
                self.cnt['bumps'] += 1
            self.kit_log.write(ev_name, dpid=dp.id, **fields)
        self.cnt['u_used'] += d.u_cost
        if self.in_bootstrap:
            self.boot['flow_mods'] += 1
            self.boot['u_cost'] += d.u_cost
        for m in d.send:
            if not self._sent(dp, m, _ORIG_SEND_MSG(dp, m)):
                return False        # connection gone; it is reset on reconnect
            self.policy.apply(dp.id, m, ofp)
            self.team_xids[(dp.id, m.xid)] = m.table_id
            while len(self.team_xids) > TEAM_XID_MEMORY:
                self.team_xids.popitem(last=False)
            for (dpid, _), p in self.pending_fstats.items():
                if dpid == dp.id:
                    p['journal'].append(m)
        self._restore_slots(dp)
        return True

    def _sent(self, dp, msg, ok):
        if not ok:
            self.cnt['send_failed'] += 1
            self.kit_log.write('send_failed', dpid=dp.id, msg=type(msg).__name__)
        return bool(ok)

    def _count(self, key, dpid):
        c = self.cnt[key]
        c[dpid] = c.get(dpid, 0) + 1

    def _reject(self, dp, msg, kind, reason):
        rej = self.cnt['rejected']
        rej[kind] = rej.get(kind, 0) + 1
        logged = self.reject_logged.get(kind, 0)
        if logged < REJECT_LOG_PER_INTERVAL:
            self.reject_logged[kind] = logged + 1
            self.kit_log.write('reject', dpid=dp.id, kind=kind, reason=reason,
                               msg=type(msg).__name__)
        else:
            self.cnt['reject_lines_suppressed'] += 1
        self.deliver(self, EventBudgetReject(dp.id, msg, kind, reason))
        return False

    def _restore_slots(self, dp):
        for m in self.policy.missing_slots(dp, dp.id):
            kit_send(dp, m)
            self.policy.apply(dp.id, m, dp.ofproto)
            self.cnt['restores'] += 1
            self.kit_log.write('default_miss_restored', dpid=dp.id, table=m.table_id)

    # ---- bootstrap --------------------------------------------------------
    def team_apps(self):
        return sorted(n for n in app_manager.AppManager.get_instance().applications
                      if n not in NOT_TEAM_APPS)

    def ready(self):
        """A team app's ready() (notify_app.ready). True if it ends bootstrap.
        Calls before EventBootstrap is sent are ignored (and logged)."""
        with self.lock:
            if not self.in_bootstrap:
                return False
            early = self.boot['delivered'] is None
            if early:
                self.boot['ready_ignored'] += 1
        if early:
            self.kit_log.write('ready_ignored', reason='before the t = 0 state was delivered')
            self.logger.warning('ready() ignored: the t = 0 state is not delivered yet')
            return False
        self.kit_log.write('ready')
        self.boot_ready.set()
        return True

    def bootstrap_wait(self, announce, timeout=None):
        """The t = 0 events are delivered: announce() (EventBootstrap), wait for
        ready() or the timeout, then end bootstrap. Returns the 'bootstrap_end'
        summary."""
        timeout = self.bootstrap_timeout if timeout is None else timeout
        with self.lock:
            if not self.in_bootstrap:
                return {'ended_by': 'not_in_bootstrap'}
            self.boot['delivered'] = time.time()
        announce()
        teams = self.team_apps()
        if not teams:
            reason = 'no_team_app'
        else:
            reason = 'ready' if self.boot_ready.wait(timeout) else 'timeout'
        return self._end_bootstrap(reason, teams)

    def _end_bootstrap(self, reason, teams):
        now = time.time()
        with self.lock:
            self.in_bootstrap = False
            self.policy.u_enforced = True
            u = self.u_bucket
            if not u.unlimited:
                u.tokens, u.last = u.burst, u.clock()
            k = [self.policy.k_used(dpid) for dpid in self.dps]
            b = self.boot
        out = {'ended_by': reason, 'team_apps': teams,
               'bootstrap_s': round(now - b['start'], 3),
               'wait_s': round(now - b['delivered'], 3),
               'team_flow_mods': b['flow_mods'], 'u_cost': b['u_cost'],
               'ready_ignored': b['ready_ignored'],
               'k_used_total': sum(k), 'k_used_max': max(k, default=0)}
        self.kit_log.write('bootstrap_end', **out)
        self.logger.info('bootstrap ended (%s) after %.1f s: %d team flow-mods',
                         reason, out['bootstrap_s'], b['flow_mods'])
        return out

    # ---- K cross-check --------------------------------------------------
    def _crosscheck_loop(self):
        while True:
            hub.sleep(self.crosscheck_s)
            with self.lock:
                for dpid, dp in list(self.dps.items()):
                    snap = self.policy.table_counts(dpid)
                    req = dp.ofproto_parser.OFPTableStatsRequest(dp, 0)
                    dp.set_xid(req)
                    self.pending_tstats[dpid] = (req.xid, snap, [])
                    kit_send(dp, req)

    # Replies to the kit's own stats requests are handled here, in the
    # receive path, and never reach the team app.
    def _on_table_stats(self, msg):
        dp = msg.datapath
        pend = self.pending_tstats.get(dp.id)
        if pend is None or pend[0] != msg.xid:
            return False
        pend[2].extend(msg.body)
        if msg.flags & dp.ofproto.OFPMPF_REPLY_MORE:
            return True
        del self.pending_tstats[dp.id]
        active = {s.table_id: s.active_count for s in pend[2]}
        for t, expected in pend[1].items():
            if active.get(t, 0) != expected:
                self.kit_log.write('k_drift', dpid=dp.id, table=t, shadow=expected,
                                   switch=active.get(t, 0))
                self._resync(dp, t)
        return True

    def _resync(self, dp, t):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(dp, 0, t, ofp.OFPP_ANY, ofp.OFPG_ANY, 0, 0,
                                         parser.OFPMatch())
        dp.set_xid(req)
        self.pending_fstats[(dp.id, req.xid)] = {'table': t, 'body': [], 'journal': []}
        kit_send(dp, req)

    def _on_flow_stats(self, msg):
        dp = msg.datapath
        p = self.pending_fstats.get((dp.id, msg.xid))
        if p is None:
            return False
        p['body'].extend(msg.body)
        if msg.flags & dp.ofproto.OFPMPF_REPLY_MORE:
            return True
        del self.pending_fstats[(dp.id, msg.xid)]
        before = self.policy.k_used(dp.id)
        self.policy.rebuild_table(dp.id, p['table'], p['body'], dp.ofproto)
        for m in p['journal']:
            self.policy.apply(dp.id, m, dp.ofproto)
        self.kit_log.write('k_resync', dpid=dp.id, table=p['table'], k_before=before,
                           k_after=self.policy.k_used(dp.id), replayed=len(p['journal']))
        return True

    # ---- budget samples -------------------------------------------------
    def _sample_loop(self):
        while True:
            hub.sleep(self.sample_s)
            with self.lock:
                c, self.cnt = self.cnt, self._zero_counters()
                self.reject_logged = {}
                k_used = {dpid: self.policy.k_used(dpid) for dpid in sorted(self.dps)}
            if self.budget_log is None:
                continue
            self.budget_log.write(
                'sample', interval_s=self.sample_s, k_used=k_used, k_limit=self.K,
                pin_rx=c['pin_rx'], pin_delivered=c['pin_delivered'],
                pin_dropped=c['pin_dropped'],
                pin_queue=self.pin_q.qsize() if self.pin_q is not None else 0,
                u_used=c['u_used'], bootstrap=self.in_bootstrap,
                rejected=c['rejected'], bumps=c['bumps'],
                restores=c['restores'], packet_out=c['packet_out'],
                stats_req=c['stats_req'], team_events_dropped=c['team_events_dropped'],
                send_failed=c['send_failed'],
                reject_lines_suppressed=c['reject_lines_suppressed'])
