"""Baseline shortest-path routing: the kit's reserved entries (not counted in K).

Destination-based: every switch gets one entry per destination network
(host /32s and destination CIDR blocks), matching ipv4_dst. The last-hop switch
rewrites eth_dst to the host's MAC, because hosts send everything to a virtual
gateway MAC (no ARP in the network).

Tie-break (topology.routing.tie_break):
  link_order  path cost is (metric sum, sum of 2**link.index), i.e. among
              equal-cost paths the one whose set of link indices is lowest
              wins. Every shortest path is then unique, so the per-destination
              trees agree with each other and routing is symmetric (u->v is
              the reverse of v->u). Metric sums are exact (ints, or fractions
              for non-integer values) so float rounding cannot break that.
"""

import heapq
import ipaddress
from collections import namedtuple
from dataclasses import dataclass
from fractions import Fraction

from kit.topology import TopologyError

METRICS = ('hops', 'weight', 'delay')
TIE_BREAKS = ('link_order',)


@dataclass(frozen=True)
class Route:
    dpid: int
    dst: ipaddress.IPv4Network
    out_port: int
    set_eth_dst: object      # MAC string on the last hop, else None
    priority: int


def link_cost(link, metric):
    """Exact cost: an int where the value is one (cheaper, same order), else a Fraction."""
    if metric == 'hops':
        return 1
    v = link.weight if metric == 'weight' else link.delay_ms
    if v is None or v <= 0:
        raise TopologyError('link %s-%s: %s must be > 0 for metric %r'
                            % (link.a, link.b, 'weight' if metric == 'weight' else 'delay_ms',
                               metric))
    if isinstance(v, int) or isinstance(v, float) and v.is_integer():
        return int(v)
    return Fraction(str(v))


def shortest_path_tree(topo, root, metric='hops', tie_break='link_order'):
    """{switch: (next switch, link)} toward `root`, and {switch: cost}."""
    if metric not in METRICS:
        raise ValueError('metric must be one of %s' % (METRICS,))
    if tie_break not in TIE_BREAKS:
        raise ValueError('tie_break must be one of %s' % (TIE_BREAKS,))
    dist = {root: (0, 0)}
    next_hop = {}
    heap = [(dist[root], root)]
    while heap:
        d, u = heapq.heappop(heap)
        if d > dist[u]:
            continue
        for v, link in topo.neighbors(u):
            nd = (d[0] + link_cost(link, metric), d[1] + (1 << link.index))
            if v not in dist or nd < dist[v]:
                dist[v] = nd
                next_hop[v] = (u, link)
                heapq.heappush(heap, (nd, v))
    return next_hop, dist


def path(topo, src, dst, metric='hops', tie_break='link_order'):
    """Switch ids from src to dst along the baseline route."""
    next_hop, _ = shortest_path_tree(topo, dst, metric, tie_break)
    out = [src]
    while out[-1] != dst:
        out.append(next_hop[out[-1]][0])
    return out


def destination_routes(topo, net, host_id, metric='hops', priority_base=1000, trees=None,
                       tie_break='link_order'):
    """[Route] toward one destination network, one per switch that reaches it."""
    trees = {} if trees is None else trees
    host = topo.hosts[host_id]
    if host.switch not in trees:
        trees[host.switch] = shortest_path_tree(topo, host.switch, metric, tie_break)[0]
    next_hop = trees[host.switch]
    prio = priority_base + net.prefixlen
    out = []
    for sw in topo.switches.values():
        if sw.id == host.switch:
            out.append(Route(sw.dpid, net, host.port, host.mac, prio))
        elif sw.id in next_hop:          # else cut off (links down): table-miss drops
            _, link = next_hop[sw.id]
            out.append(Route(sw.dpid, net, topo.port_towards(sw.id, link), None, prio))
    return out


def compute_routes(topo, metric='hops', priority_base=1000, trees=None,
                   tie_break='link_order'):
    """{dpid: {dst network: Route}} for every switch and destination."""
    trees = {} if trees is None else trees
    routes = {s.dpid: {} for s in topo.switches.values()}
    for net, host_id in topo.destinations():
        for r in destination_routes(topo, net, host_id, metric, priority_base, trees,
                                    tie_break):
            routes[r.dpid][net] = r
    return routes


def _same(a, b):
    # Route fields that can differ for one (dpid, dst); cheaper than Route.__eq__
    return (a.out_port, a.set_eth_dst, a.priority) == (b.out_port, b.set_eth_dst, b.priority)


def diff_routes(old, new):
    """[(op, Route)] with op in add / modify / delete, to turn `old` into `new`.
    Ordered by dpid, then destination."""
    ops = []
    for dpid in sorted(set(old) | set(new)):
        o, n = old.get(dpid, {}), new.get(dpid, {})
        changed = [dst for dst in o.keys() - n.keys()] + [dst for dst in n.keys() - o.keys()]
        changed += [dst for dst, r in n.items() if dst in o and not _same(o[dst], r)]
        for dst in sorted(changed):
            if dst not in n:
                ops.append(('delete', o[dst]))
            elif dst not in o:
                ops.append(('add', n[dst]))
            else:
                ops.append(('modify', n[dst]))
    return ops


def move_prefix(topo, cidr, host_id):
    """Relocate a destination CIDR block to another server-side host.

    Returns the previous host id. The caller recomputes routes and applies
    diff_routes(). The controller is told through kit events (kit.controller.events).
    """
    cidr = ipaddress.IPv4Network(cidr)
    if cidr not in topo.prefixes:
        raise TopologyError('unknown prefix %s' % cidr)
    topo.check_prefix_host(host_id)
    old = topo.prefixes[cidr].host
    topo.prefixes[cidr].host = host_id
    return old


# kind: 'switch' (peer: switch id) | 'edge' (an edge port; peer: its name, e.g. 'S3')
NextHop = namedtuple('NextHop', 'out_port kind peer')


class BaselineRouting:
    """Current baseline routes plus lookups for controller apps.

    Nodes may be given as a switch id, a dpid (int), a host id, or an IPv4
    address (resolved to the host that currently owns it, longest prefix).
    """

    def __init__(self, topo, metric='hops', priority_base=1000, tie_break='link_order'):
        self.topo = topo
        self.metric = metric
        self.priority_base = priority_base
        self.tie_break = tie_break
        self.down_links = {}       # link index -> Link (taken out of topo.links)
        self._trees = {}
        self.routes = self._compute()

    def _compute(self):
        return compute_routes(self.topo, self.metric, self.priority_base, self._trees,
                              self.tie_break)

    def recompute(self):
        """Recompute after a topology change; returns diff_routes() ops."""
        self._trees = {}
        new = self._compute()
        ops = diff_routes(self.routes, new)
        self.routes = new
        return ops

    def relocate(self, cidr, host_id):
        """move_prefix() + routes for that prefix only (the graph and its trees
        stay); returns (old host id, ops), as recompute() would."""
        old = move_prefix(self.topo, cidr, host_id)
        net = ipaddress.IPv4Network(cidr)
        new = {r.dpid: r for r in destination_routes(self.topo, net, host_id, self.metric,
                                                     self.priority_base, self._trees,
                                                     self.tie_break)}
        ops = []
        routes = dict(self.routes)
        for dpid in sorted(routes):
            o, n = routes[dpid].get(net), new.get(dpid)
            if o is None and n is None or o is not None and n is not None and _same(o, n):
                continue
            rs = routes[dpid] = dict(routes[dpid])   # copies: callers may hold the old dicts
            if n is None:
                ops.append(('delete', rs.pop(net)))
            else:
                ops.append(('add' if o is None else 'modify', n))
                rs[net] = n
        self.routes = routes
        return old, ops

    def set_weights(self, weights):
        """Traffic engineering: new link weights {"B1-B2": w}; routes use the
        weight metric from now on. Returns recompute() ops.

        Links missing from `weights` keep their weight; down links take theirs
        when they come back.
        """
        for name, w in weights.items():
            a, b = name.split('-')
            if not (isinstance(w, (int, float)) and w > 0):
                raise TopologyError('TE weight for %s must be > 0' % name)
            self.find_link(a, b).weight = w
        self.metric = 'weight'
        return self.recompute()

    def find_link(self, a, b):
        """The Link between switches a and b, up or down (either order)."""
        for l in list(self.topo.links) + list(self.down_links.values()):
            if {l.a, l.b} == {a, b}:
                return l
        raise TopologyError('no link %s-%s' % (a, b))

    def set_link(self, a, b, up):
        """Take a link out of (or back into) the topology; returns recompute() ops.

        Ports and link indices stay as they are, so routes over other links
        and the tie-break do not change.
        """
        link = self.find_link(a, b)
        if up and link.index in self.down_links:
            del self.down_links[link.index]
            self.topo.links.append(link)
            self.topo.links.sort(key=lambda l: l.index)
        elif not up and link.index not in self.down_links:
            self.down_links[link.index] = link
            self.topo.links.remove(link)
        else:
            return []
        return self.recompute()

    # ---- lookups ------------------------------------------------------
    def lookup(self, ip):
        """(destination network, host id) currently owning `ip`, or None."""
        ip = ipaddress.IPv4Address(ip)
        best = None
        for net, host_id in self.topo.destinations():
            if ip in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, host_id)
        return best

    def switch_of(self, node):
        """Switch id for a switch id, dpid, host id or IPv4 address."""
        if isinstance(node, int):
            sw = self.topo.switch_by_dpid(node)
            if sw is None:
                raise KeyError('unknown dpid %d' % node)
            return sw.id
        if node in self.topo.switches:
            return node
        if node in self.topo.hosts:
            return self.topo.hosts[node].switch
        hit = self.lookup(node)
        if hit is None:
            raise KeyError('no destination owns %s' % node)
        return self.topo.hosts[hit[1]].switch

    def next_hop(self, switch, ip):
        """NextHop the baseline route takes at `switch` for `ip`, or None (dropped)."""
        sw = self.topo.switches[self.switch_of(switch)]
        hit = self.lookup(ip)
        if hit is None:
            return None
        r = self.routes[sw.dpid][hit[0]]
        kind, peer = sw.ports[r.out_port]
        return NextHop(r.out_port, 'edge' if kind == 'host' else kind, peer)

    def path(self, src, dst):
        """Switch ids from src to dst (any node form) along baseline routes."""
        a, b = self.switch_of(src), self.switch_of(dst)
        if b not in self._trees:
            self._trees[b] = shortest_path_tree(self.topo, b, self.metric, self.tie_break)[0]
        tree = self._trees[b]
        out = [a]
        while out[-1] != b:
            out.append(tree[out[-1]][0])
        return out
