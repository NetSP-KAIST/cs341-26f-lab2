# What your controller app may use

The kit keeps the SDN toolbox deliberately small: on every switch, the only
state your app controls is its **flow tables**, built from basic OpenFlow 1.3
pieces. Anything outside this list is refused by the kit.

## The one way to talk to a switch

Send OpenFlow messages only with `datapath.send_msg(...)`. Writing to the
switch any other way (`datapath.send(...)` with raw bytes, the socket, a
second OpenFlow connection, `ovs-ofctl`/`ovs-vsctl`, or reaching past the
kit's layer) is against the rules. Staff re-run every submission.

## How refusals work

Use the normal os-ken API (`datapath.send_msg(...)`, `@set_ev_cls(...)`). If a
message breaks a rule below or a budget:

- it is **not sent** to the switch, and `send_msg` returns `False`;
- the kit logs it (`runs/<run_id>/kit_events.jsonl`);
- your app receives `kit.controller.base_app.EventBudgetReject`
  (`dpid`, `msg`, `kind`, `reason`) if it subscribes with `@set_ev_cls`.

## Runtime notes

- `send_msg` returns `False` if the switch connection is gone. Nothing is
  recorded for that message; the switch is reset when it reconnects.
- If the switch itself refuses one of your flow-mods (you receive an
  `EventOFPErrorMsg`), the entry does not count toward K.
- os-ken runs each app's event handlers in its own thread, and `hub.spawn`
  starts real threads. An exception in a handler is logged and your app keeps
  running.
- A slow app does not stall the switches or the kit.

## Pipeline

| Tables | Owner | Notes |
|---|---|---|
| 0 … N-1 (N = 4) | your app | Each starts with a kit default table-miss: priority 0, match-all, goto the routing table. You may replace it. |
| 200 | kit | Shortest-path routing. You cannot write to it, but you can `goto` it. Unknown destinations are dropped. It never sends Packet-In. Each entry writes its output port to `metadata` (overwriting yours) and goes to table 201. |
| 201 | kit | Output. You cannot write to it or `goto` it; only table 200 leads here. It sends the packet out the port table 200 chose, also when that is the port it arrived on (no `IN_PORT` entry of yours needed), and decrements the IPv4 TTL, as a router does at every hop. A packet whose TTL runs out is dropped, with no Packet-In. |

A packet you steer off its baseline path and hand back to the routing table
(`goto 200`, or Packet-Out to `TABLE`) is routed onward from where it is, even
when that means going back the way it came. A loop you create ends when the
TTL runs out (64 hops from a client).

- **Packet-Out to `TABLE`** runs the packet through the pipeline from table 0,
  as in standard OpenFlow, so your own entries see it again. Its `in_port`
  is the one you put in the packet-out: the port it originally arrived on,
  or `CONTROLLER`. Entries that match `in_port` see that value.
- **TTL** goes down by 1 only in table 201. A packet you send out directly
  with `Output(port)`, from a packet-out or from one of your flow entries,
  skips table 201, so its TTL does not change on that switch.

## Kit events and lookups

What the kit tells your app about the world. Everything else has to be
observed in traffic. Scenario time `t` is in seconds; `docs/kit/simulator.md`
describes the events themselves.

| API | What |
|---|---|
| `kit.controller.routing_app.get_routing()` | `next_hop(switch, ip)` → `(out_port, kind, peer)`, kind `switch` or `edge` (an edge port such as `S3`); `path(src, dst)`; `lookup(ip)` → `(prefix, edge port)`; all on the current table 200 |
| `kit.controller.notify_app.get_blocklist()` | the blocklist in force: `[{'entry': {...}, 'order_id': ...}]` |
| `kit.controller.notify_app.ready()` | your rules for the t = 0 state are in place: ends bootstrap (below) |
| `kit.controller.events.EventRoutingChanged` | `cause` (`bgp`, `te`, `link_down`, `link_up`), `t`, `prefixes` (destinations whose route changed), `detail` |
| `kit.controller.events.EventTENotice` | `te_id`, `t`, `apply_at`: a TE change is coming |
| `kit.controller.events.EventBlocklistOrder` | `order_id`, `t`, `add`, `remove` |
| `kit.controller.events.EventBootstrap` | `t` (0), `timeout_s`: the t = 0 state is complete; call `ready()` when your rules for it are in |
| `kit.controller.base_app.EventBudgetReject` | see above |

- `EventRoutingChanged` arrives after every changed switch has confirmed the
  new table 200 entries. `get_routing()` already answers with the
  new routes at that point.
- `detail` by cause: bgp `{'prefix', 'from', 'to'}` (exits), te
  `{'te_id', 'weights'}`, link `{'link': 'B3-B9'}`.
- A blocklist order is in force from its `t`. `get_blocklist()` reflects it
  when the event arrives. Entry types and matching rules:
  `docs/kit/simulator.md`.
- **Bootstrap.** The network has been running before the scenario starts,
  so your rules for the orders already in force should be in place at
  t = 0. Before the scenario clock starts, the kit delivers the t = 0
  events (the initial `EventBlocklistOrder`, routing), then
  `EventBootstrap`. Install your rules, then call `ready()`; the clock
  starts right after. Without `ready()`, bootstrap ends after
  `controller.bootstrap_timeout_s`.
  - During bootstrap there is no traffic, **U is not enforced**, and
    everything else is (K, the allowed messages and tables).
  - A `ready()` before `EventBootstrap` is ignored.
  - Bootstrap tells you nothing about later events.

## Messages you may send

- **Flow-mod** (`OFPFlowMod`): add, modify, modify-strict, delete,
  delete-strict, only in tables 0 … N-1. A delete with `table_id=OFPTT_ALL`
  applies to tables 0 … N-1 only. Cookies whose top 16 bits are `0x4b49` are
  reserved for the kit.
- **Packet-out** (`OFPPacketOut`), e.g. to re-inject an inspected packet or send
  a crafted reply. Every packet-out uses P (see the budget rules below).
- **Barrier** and **echo**.
- **Read-only statistics**: description, flow, aggregate, table, port and port
  description, with two limits:
  - flow and aggregate stats can read only tables 0 … N-1 (not the routing
    table, and not `OFPTT_ALL`);
  - each switch accepts at most 1 stats request per second from your app.
    This is a fixed limit of the kit, not one of the budgets.

Not available: groups, meters, port / table / switch configuration, async
configuration, controller roles, and all OVS (Nicira) extension messages.

## Inside a flow entry

**Match fields:** `in_port`, `metadata`, `eth_src`, `eth_dst`, `eth_type`,
`vlan_vid`, `mpls_label`, `ip_proto`, `ipv4_src`, `ipv4_dst`, `tcp_src`,
`tcp_dst`, `tcp_flags`, `udp_src`, `udp_dst`, `icmpv4_type`, `icmpv4_code`.
Masks are allowed where OpenFlow allows them.

**Instructions:** Apply-Actions, Goto-Table, Write-Metadata. Goto-Table
must go forward: to a later team table, or to the routing table (200).
(No Write-Actions, Clear-Actions or Meter.)

**Actions:**

- `Output` to a switch port, to `IN_PORT`, or to `CONTROLLER`;
- `Set-Field` on `eth_src`, `eth_dst`, `vlan_vid`, `mpls_label`, `ipv4_src`,
  `ipv4_dst`, `tcp_src`, `tcp_dst`, `udp_src`, `udp_dst`;
- `Push-VLAN`, `Pop-VLAN`, `Push-MPLS`, `Pop-MPLS`.

An empty action list drops the packet.

**Packet-out actions:** the same `Output` and `Set-Field` actions. Output may go
to a port, `IN_PORT`, or `TABLE`, which runs the packet through the pipeline
from table 0.

`FLOOD`, `ALL`, `NORMAL`, `LOCAL`, groups and OVS extension actions such as
`learn`, `ct`, `conjunction` and `resubmit` are not available.

## Budget rules you will notice

- **K** (per switch): entries in tables 0 … N-1 count, except the one
  priority-0 match-all entry of each table. An add that would exceed K is
  refused.
- **Priority bump:** if you install a priority-0 match-all entry that outputs
  to `CONTROLLER`, the kit installs it at priority 1 instead (it then counts
  toward K). The kit logs this.
- **Restored table-miss:** if your deletes leave a table without a priority-0
  match-all entry, the kit puts its default table-miss back. This does not
  use any of your U budget.
- **Timeouts and FlowRemoved:** standard OpenFlow behavior. Your app gets
  `EventOFPFlowRemoved` only for entries where you set
  `OFPFF_SEND_FLOW_REM` yourself.
- **U** (network-wide): a flow-mod costs one unit for every entry it
  affects, minimum 1. An add costs 1. A modify or delete costs the number
  of entries it selects, so a wildcard delete over 50 entries costs 50. If
  the cost is more than what is left, the whole flow-mod is refused. U is
  not enforced during bootstrap (above) and starts with a full bucket at
  t = 0.
- **P** (network-wide) is your controller's message throughput. Each
  Packet-In delivered to your app and each packet-out you send costs one
  token, and the whole network shares P tokens per second.
  - Packet-Ins beyond that wait in a queue of 300 and reach your app as
    tokens allow; when the queue is full, new ones are dropped and counted.
  - A packet-out over the budget is refused (`send_msg` returns `False`,
    `EventBudgetReject` with kind `P`). It is never delayed.
  - Example: if your app inspects a packet and then re-injects it with a
    packet-out, each inspected packet costs 2 tokens, so at most P/2 packets
    per second take that path. Dropping it and installing a flow entry
    costs 1. Answering with a block page costs 1 token per packet of the
    page.
- **Pₛ** (per switch): the switch itself limits how fast it sends Packet-Ins.
- **Reconnects:** a switch that reconnects starts again from the default tables.
- Budget numbers are in the run config (`budgets:`).

## VLAN, MPLS and metadata notes

- The routing table forwards VLAN-tagged IPv4 by `ipv4_dst` as usual, but
  edge ports drop tagged frames: pop the tag before the last hop delivers it.
- Match a VLAN with `vlan_vid=(OFPVID_PRESENT | vid)`.
- The routing table cannot see inside MPLS. An MPLS packet that reaches it
  is dropped, so every switch on an MPLS path needs your own entry for the
  label (or pop it first with `Pop-MPLS(0x0800)`).
- Links between switches have MTU 1600, so a full 1500-byte packet still
  fits with a tag or label. Links to edge ports have MTU 1500.
- Write-Metadata plus Goto-Table to your next table works as in OpenFlow 1.3.
  Metadata is yours only within your tables: table 200 overwrites it.
