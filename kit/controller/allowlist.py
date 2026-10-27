"""OpenFlow surface allowed to team apps: only basic SDN elements.

The goal is that a switch's only team-controlled state is its flow tables
0..N-1, built from standard OpenFlow 1.3 pieces. Everything here is the single
source for the student-facing list in docs/kit/openflow-surface.md; keep the
two in sync.

Not allowed: groups, meters, port/table/switch config, async config, roles,
all experimenter (Nicira) messages and actions (learn, conjunction, ct,
resubmit, NX controller, ...), Write-Actions / Clear-Actions / Meter
instructions, reserved output ports other than those listed.
"""

from os_ken.ofproto import ofproto_v1_3 as ofp
from os_ken.ofproto import ofproto_v1_3_parser as parser

# Messages a team app may send. Hello / Echo / FeaturesRequest / PortDesc /
# ErrorMsg are also sent by os-ken itself.
ALLOWED_MESSAGES = (
    parser.OFPFlowMod,              # checked further (check_flow_mod + TeamPolicy)
    parser.OFPPacketOut,            # checked further (check_packet_out)
    parser.OFPBarrierRequest,
    parser.OFPEchoRequest, parser.OFPEchoReply, parser.OFPHello,
    parser.OFPFeaturesRequest, parser.OFPErrorMsg,
    # read-only statistics
    parser.OFPDescStatsRequest, parser.OFPFlowStatsRequest,
    parser.OFPAggregateStatsRequest, parser.OFPTableStatsRequest,
    parser.OFPPortStatsRequest, parser.OFPPortDescStatsRequest,
)

# Match fields (OXM). tcp_flags is an OVS extension in OF1.3 and is allowed
# on purpose (Host/SNI inspection).
MATCH_FIELDS = frozenset([
    'in_port', 'metadata',
    'eth_dst', 'eth_src', 'eth_type',
    'vlan_vid', 'mpls_label',
    'ip_proto', 'ipv4_src', 'ipv4_dst',
    'tcp_src', 'tcp_dst', 'tcp_flags',
    'udp_src', 'udp_dst',
    'icmpv4_type', 'icmpv4_code',
])

INSTRUCTIONS = (parser.OFPInstructionActions, parser.OFPInstructionGotoTable,
                parser.OFPInstructionWriteMetadata)
INSTRUCTION_ACTION_TYPES = (ofp.OFPIT_APPLY_ACTIONS,)

ACTIONS = (parser.OFPActionOutput, parser.OFPActionSetField,
           parser.OFPActionPushVlan, parser.OFPActionPopVlan,
           parser.OFPActionPushMpls, parser.OFPActionPopMpls)

SET_FIELDS = frozenset(['eth_dst', 'eth_src', 'vlan_vid', 'mpls_label',
                        'ipv4_src', 'ipv4_dst', 'tcp_src', 'tcp_dst',
                        'udp_src', 'udp_dst'])

STATS_REQUESTS = (parser.OFPDescStatsRequest, parser.OFPFlowStatsRequest,
                  parser.OFPAggregateStatsRequest, parser.OFPTableStatsRequest,
                  parser.OFPPortStatsRequest, parser.OFPPortDescStatsRequest)
# Stats that read flow entries: team tables only.
# Routing-table counters would be a free per-prefix traffic matrix.
TABLE_STATS_REQUESTS = (parser.OFPFlowStatsRequest, parser.OFPAggregateStatsRequest)

# Reserved output ports (physical ports 1..OFPP_MAX are always allowed).
FLOW_RESERVED_PORTS = frozenset([ofp.OFPP_IN_PORT, ofp.OFPP_CONTROLLER])
PACKET_OUT_RESERVED_PORTS = frozenset([ofp.OFPP_IN_PORT, ofp.OFPP_TABLE])


def _check_actions(actions, reserved_ports, where):
    for a in actions or []:
        if type(a) not in ACTIONS:
            return '%s: action %s is not allowed' % (where, type(a).__name__)
        if isinstance(a, parser.OFPActionOutput):
            if a.port > ofp.OFPP_MAX and a.port not in reserved_ports:
                return '%s: output to reserved port 0x%x is not allowed' % (where, a.port)
        elif isinstance(a, parser.OFPActionSetField):
            if a.key not in SET_FIELDS:
                return '%s: set_field %s is not allowed' % (where, a.key)
    return None


def check_flow_mod(mod, n_tables=None, routing_table=None):
    """None if the flow-mod only uses allowed pieces, else the reason.
    With n_tables and routing_table, Goto-Table must go to a later team table
    or to the routing table."""
    for name, _ in mod.match.items():
        if name not in MATCH_FIELDS:
            return 'match field %s is not allowed' % name
    for inst in mod.instructions or []:
        if type(inst) not in INSTRUCTIONS:
            return 'instruction %s is not allowed' % type(inst).__name__
        if isinstance(inst, parser.OFPInstructionGotoTable) and n_tables is not None:
            t = inst.table_id
            if t != routing_table and not mod.table_id < t < n_tables:
                return ('goto table %d from table %d: only a later team table '
                        '(..%d) or the routing table %s' % (t, mod.table_id, n_tables - 1,
                                                            routing_table))
        if isinstance(inst, parser.OFPInstructionActions):
            if inst.type not in INSTRUCTION_ACTION_TYPES:
                return 'only Apply-Actions is allowed (got instruction type %d)' % inst.type
            err = _check_actions(inst.actions, FLOW_RESERVED_PORTS, 'flow')
            if err:
                return err
    return None


def check_stats(msg, n_tables):
    """None if a stats request may be sent, else the reason. The per-switch
    rate cap is applied by the base layer."""
    if isinstance(msg, TABLE_STATS_REQUESTS) and not 0 <= msg.table_id < n_tables:
        return '%s: only team tables 0..%d can be read (got table %d)' % (
            type(msg).__name__, n_tables - 1, msg.table_id)
    return None


def check_packet_out(msg):
    return _check_actions(msg.actions, PACKET_OUT_RESERVED_PORTS, 'packet-out')
