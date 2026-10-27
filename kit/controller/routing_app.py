"""Kit baseline routing app (docs/kit/openflow-surface.md "Pipeline").

    osken-manager --lab2-config configs/default.yaml kit.controller.routing_app controller/app.py

Pipeline per switch:
  tables 0..N-1   team tables (pipeline.team_tables). The base layer
                  (base_app.py) installs a default table-miss in each (goto
                  the routing table); reserved, outside K, teams may override.
  routing table   pipeline.routing_table, owned by this app. Shortest-path
                  entries for every destination: the last hop sets eth_dst,
                  each writes its out port to metadata and goes to the hairpin
                  table. A table-miss drops. It never sends Packet-In. Teams
                  never write to it.
  hairpin table   pipeline.hairpin_table, owned by this app. Per switch port p:
                  metadata = p and in_port = p -> output IN_PORT, else
                  metadata = p -> output p; both decrement the IPv4 TTL (a
                  loop dies within 64 hops; TTL 0 is dropped, no Packet-In).
                  A table-miss drops. Only the routing table goes here.

Kit messages are sent with kit_send() (no budget checks) and carry cookies in
the kit range (policy.KIT_COOKIE).

Team apps reach the routing API with get_routing() (or
lookup_service_brick('RoutingApp')). Routing changes (BGP moves, link
failures, TE) are applied here by NotifyApp and announced to team apps as
kit.controller.events.EventRoutingChanged.
"""

import ipaddress
import os
import threading

from os_ken import cfg as oscfg
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                       MAIN_DISPATCHER, set_ev_cls)
from os_ken.ofproto import ofproto_v1_3

from kit.config import load_config, load_topology_for, config_open_keys
from kit.controller.base_app import kit_barrier, kit_send, wait_barriers
from kit.controller.policy import ROUTING_COOKIE
from kit.routing import BaselineRouting

METADATA_MASK = 2**64 - 1      # the routing table owns all of metadata (out port)


def config_path():
    try:
        p = oscfg.CONF.lab2_config
    except (oscfg.NoSuchOptError, AttributeError):
        p = None
    return os.environ.get('LAB2_CONFIG') or p or 'configs/default.yaml'


def get_routing():
    """The running RoutingApp instance (None if it is not loaded)."""
    return app_manager.lookup_service_brick('RoutingApp')


class RoutingApp(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cfg = load_config(config_path())
        rcfg = self.cfg['topology']['routing']
        self.team_tables = self.cfg['pipeline']['team_tables']
        self.routing_table = self.cfg['pipeline']['routing_table']
        self.hairpin_table = self.cfg['pipeline']['hairpin_table']
        # LAB2_SCENARIO: the run's scenario.jsonl; its header adds the simulator's prefixes
        self.topo = load_topology_for(self.cfg, os.environ.get('LAB2_SCENARIO'))
        self.baseline = BaselineRouting(self.topo, rcfg['metric'], rcfg['priority_base'],
                                        rcfg['tie_break'])
        self.datapaths = {}
        self.lock = threading.RLock()      # baseline + table 200 writes (switch threads,
                                           #   NotifyApp's socket thread)
        unset = config_open_keys(self.cfg) + self.topo.open_keys
        if unset:
            self.logger.info('unset (null) config keys: %s', ', '.join(unset))
        self.logger.info('topology %s: %d switches, %d links, %d hosts, %d prefixes; '
                         'team tables 0..%d, routing table %d, %d routes per switch',
                         self.topo.name, len(self.topo.switches), len(self.topo.links),
                         len(self.topo.hosts), len(self.topo.prefixes),
                         self.team_tables - 1, self.routing_table,
                         len(self.topo.destinations()))

    # ---- routing API for team apps ------------------------------------
    def next_hop(self, switch, ip):
        """NextHop(out_port, kind, peer) of the baseline route, or None (dropped).
        kind is 'switch' (peer: switch id) or 'edge' (peer: edge port name, e.g. 'S3').

        `switch`: switch id or dpid. `ip`: destination IPv4 address.
        """
        with self.lock:
            return self.baseline.next_hop(switch, ip)

    def path(self, src, dst):
        """Switch ids along the baseline route. src/dst: switch id, dpid, edge port name or IP."""
        with self.lock:
            return self.baseline.path(src, dst)

    def lookup(self, ip):
        """(destination network, edge port name) that currently owns `ip`, or None."""
        with self.lock:
            return self.baseline.lookup(ip)

    # ---- flow-mods ----------------------------------------------------
    def _route_mod(self, dp, op, r):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        net = r.dst
        match = parser.OFPMatch(eth_type=0x0800,
                                ipv4_dst=(str(net.network_address), str(net.netmask)))
        if op == 'delete':
            return parser.OFPFlowMod(
                datapath=dp, table_id=self.routing_table, command=ofp.OFPFC_DELETE_STRICT,
                priority=r.priority, match=match, out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY, cookie=ROUTING_COOKIE, cookie_mask=2**64 - 1)
        inst = []
        if r.set_eth_dst:
            inst.append(parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS, [parser.OFPActionSetField(eth_dst=r.set_eth_dst)]))
        inst += [parser.OFPInstructionWriteMetadata(r.out_port, METADATA_MASK),
                 parser.OFPInstructionGotoTable(self.hairpin_table)]
        return parser.OFPFlowMod(
            datapath=dp, table_id=self.routing_table,
            command=ofp.OFPFC_ADD if op == 'add' else ofp.OFPFC_MODIFY_STRICT,
            priority=r.priority, match=match, cookie=ROUTING_COOKIE, instructions=inst)

    def _hairpin_mods(self, dp, ports):
        """Hairpin table: out port from metadata; IN_PORT when it is the arrival port."""
        ofp, parser = dp.ofproto, dp.ofproto_parser
        out = []
        for p in sorted(ports):
            for prio, match, port in (
                    (2, parser.OFPMatch(in_port=p, eth_type=0x0800, metadata=p), ofp.OFPP_IN_PORT),
                    (1, parser.OFPMatch(eth_type=0x0800, metadata=p), p)):
                out.append(parser.OFPFlowMod(
                    datapath=dp, table_id=self.hairpin_table, priority=prio, match=match,
                    cookie=ROUTING_COOKIE, instructions=[parser.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS,
                        [parser.OFPActionDecNwTtl(), parser.OFPActionOutput(port)])]))
        return out

    def _install_all(self, dp):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        # start from empty kit tables (e.g. after a controller restart); their
        # table-misses drop (no Packet-In); then the hairpin entries and all routes
        for table in (self.routing_table, self.hairpin_table):
            kit_send(dp, parser.OFPFlowMod(
                datapath=dp, table_id=table, command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=parser.OFPMatch()))
            kit_send(dp, parser.OFPFlowMod(
                datapath=dp, table_id=table, priority=0, match=parser.OFPMatch(),
                instructions=[], cookie=ROUTING_COOKIE))
        sw = self.topo.switch_by_dpid(dp.id)
        for m in self._hairpin_mods(dp, sw.ports):
            kit_send(dp, m)
        with self.lock:
            routes = list(self.baseline.routes.get(dp.id, {}).values())
        for r in routes:
            kit_send(dp, self._route_mod(dp, 'add', r))
        kit_barrier(dp)

    # ---- events -------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_features(self, ev):
        dp = ev.msg.datapath
        sw = self.topo.switch_by_dpid(dp.id)
        if sw is None:
            self.logger.warning('dpid %d is not in the topology; ignored', dp.id)
            return
        self._install_all(dp)
        self.logger.info('switch %s (dpid %d): %d routes installed in table %d',
                         sw.id, dp.id, len(self.baseline.routes.get(dp.id, {})),
                         self.routing_table)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def on_state(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif dp.id in self.datapaths:
            del self.datapaths[dp.id]

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def on_error(self, ev):
        m = ev.msg
        self.logger.error('OFP error from dpid %s: type=%d code=%d xid=%d',
                          m.datapath.id, m.type, m.code, m.xid)

    # ---- routing changes (called by NotifyApp) -------------------------
    def _push(self, ops, timeout):
        """Send ops to the switches, then barrier each changed switch.

        Returns (changed destinations, flow-mod count, dpids late or missing).
        Kit-internal: routing-table updates do not count toward U.
        """
        keys, missing = [], []
        for dpid in sorted({r.dpid for _, r in ops}):
            dp = self.datapaths.get(dpid)
            if dp is None:
                missing.append(dpid)
                continue
            for op, r in ops:
                if r.dpid == dpid:
                    kit_send(dp, self._route_mod(dp, op, r))
            keys.append(kit_barrier(dp))
        late = wait_barriers(keys, timeout)
        return sorted({r.dst for _, r in ops}), len(ops), sorted(missing + late)

    def relocate(self, cidr, host_id, timeout=2.0):
        """Move a destination prefix to another host (BGP exit change).

        The Mininet side moves the address on the hosts. Returns
        (old host, changed destinations, flow-mods, late dpids).
        """
        with self.lock:
            old_host, ops = self.baseline.relocate(cidr, host_id)
            changed, n, late = self._push(ops, timeout)
        self.logger.info('relocated %s: %s -> %s (%d routing flow-mods)',
                         cidr, old_host, host_id, n)
        return old_host, changed, n, late

    def apply_te(self, weights, timeout=2.0):
        """Traffic engineering: re-route with new link weights.
        Returns (changed destinations, flow-mods, late dpids)."""
        with self.lock:
            ops = self.baseline.set_weights(weights)
            changed, n, late = self._push(ops, timeout)
        self.logger.info('TE: %d link weights, %d routing flow-mods', len(weights), n)
        return changed, n, late

    def set_link(self, a, b, up, timeout=2.0):
        """Route around a link that went down, or use it again once it is up.
        Returns (changed destinations, flow-mods, late dpids)."""
        with self.lock:
            ops = self.baseline.set_link(a, b, up)
            changed, n, late = self._push(ops, timeout)
        self.logger.info('link %s-%s %s (%d routing flow-mods)', a, b,
                         'up' if up else 'down', n)
        return changed, n, late
