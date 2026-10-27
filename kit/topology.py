"""Topology model loaded from topologies/*.yaml.

Pure Python (no Mininet / os-ken imports) so both the Mininet side and the
controller side build the same object from the same file. Port numbers, dpids,
host IPs and MACs are assigned deterministically here, never by Mininet.

Port numbering per switch: links in file order, then attached hosts in file
order, starting at 1.

Link parameters resolve as: the link's own keys, then its tier
(`tiers.<name>`), then `defaults.link`. A null tier value is unset:
it is reported in Topology.open_keys and treated as "not set" (no shaping,
zero delay).
"""

import ipaddress
import re
from dataclasses import dataclass, field

import yaml

SCHEMA_VERSION = 1
NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9]{0,7}$')   # keeps "<name>-eth<N>" < IFNAMSIZ
HOST_ROLES = ('client', 'server', 'resolver', 'external_resolver', 'encrypted_endpoint')
LINK_KEYS = ('bw_mbps', 'delay_ms', 'weight')


class TopologyError(ValueError):
    pass


@dataclass
class Switch:
    id: str
    role: str
    dpid: int
    ports: dict = field(default_factory=dict)   # port no -> ('switch'|'host', peer id)


@dataclass
class Link:
    a: str
    b: str
    a_port: int
    b_port: int
    bw_mbps: float
    delay_ms: float
    weight: float
    index: int
    tier: str = None


@dataclass
class Host:
    id: str
    role: str
    kind: str
    switch: str
    port: int
    ip: ipaddress.IPv4Address
    mac: str
    bw_mbps: float = None      # access link
    delay_ms: float = 0


@dataclass
class Prefix:
    cidr: ipaddress.IPv4Network
    host: str          # current location (changed by relocation)


@dataclass
class Topology:
    name: str
    switches: dict      # id -> Switch (file order)
    links: list         # [Link]
    hosts: dict         # id -> Host (file order)
    prefixes: dict      # IPv4Network -> Prefix
    host_pool: ipaddress.IPv4Network
    gateway_ip: ipaddress.IPv4Address
    gateway_mac: str
    open_keys: list = field(default_factory=list)   # null (unset) values in the file

    def switch_by_dpid(self, dpid):
        for s in self.switches.values():
            if s.dpid == dpid:
                return s
        return None

    def neighbors(self, sw_id):
        """[(neighbor switch id, link)] in link-index order."""
        out = []
        for link in self.links:
            if link.a == sw_id:
                out.append((link.b, link))
            elif link.b == sw_id:
                out.append((link.a, link))
        return out

    def port_towards(self, sw_id, link):
        return link.a_port if link.a == sw_id else link.b_port

    def destinations(self):
        """(network, host id) for every routed destination: host /32s, then prefixes."""
        out = [(ipaddress.IPv4Network(h.ip), h.id) for h in self.hosts.values()]
        out += [(p.cidr, p.host) for p in self.prefixes.values()]
        return out

    def check_prefix_host(self, host_id, allow_client=False):
        h = self.hosts.get(host_id)
        if h is None:
            raise TopologyError('unknown host %r' % host_id)
        roles = ('server', 'resolver', 'external_resolver', 'encrypted_endpoint')
        if h.role not in roles + (('client',) if allow_client else ()):
            raise TopologyError('prefix host %r must be a server-side host, not %s'
                                % (host_id, h.role))

    def add_prefix(self, cidr, host_id, allow_client=False):
        """Add a destination prefix after loading (the simulator's address plan).

        allow_client: a PoP's address block (10.i.0.0/16: its subscribers and the
        sites it hosts) lives at its PoP host (role client, kind pop).
        """
        net = ipaddress.IPv4Network(cidr)
        for other in list(self.prefixes) + [self.host_pool]:
            if net.overlaps(other):
                raise TopologyError('prefix %s overlaps %s' % (net, other))
        if any(h.ip in net for h in self.hosts.values()):
            raise TopologyError('prefix %s contains a host address' % net)
        self.check_prefix_host(host_id, allow_client)
        self.prefixes[net] = Prefix(net, host_id)


def _need(d, key, where):
    if key not in d:
        raise TopologyError('%s: missing %r' % (where, key))
    return d[key]


def _name(v, where):
    if not isinstance(v, str) or not NAME_RE.match(v):
        raise TopologyError('%s: id %r must match %s' % (where, v, NAME_RE.pattern))
    return v


def load_topology(path):
    with open(path) as f:
        return parse_topology(yaml.safe_load(f), str(path))


def parse_topology(doc, where='topology'):
    if not isinstance(doc, dict) or doc.get('version') != SCHEMA_VERSION:
        raise TopologyError('%s: version must be %d' % (where, SCHEMA_VERSION))
    link_defaults = dict(bw_mbps=None, delay_ms=0, weight=1)
    link_defaults.update((doc.get('defaults') or {}).get('link') or {})
    tiers = doc.get('tiers') or {}
    open_keys = ['%s.%s.%s' % (sec, t, k)
                 for sec in ('defaults', 'tiers')
                 for t, v in (doc.get(sec) or {}).items()
                 for k, x in (v or {}).items() if x is None]
    host_link_defaults = dict(bw_mbps=None, delay_ms=0)
    host_link_defaults.update((doc.get('defaults') or {}).get('host_link') or {})
    addressing = _need(doc, 'addressing', where)
    host_pool = ipaddress.IPv4Network(_need(addressing, 'host_pool', 'addressing'))
    gateway_ip = ipaddress.IPv4Address(_need(addressing, 'gateway_ip', 'addressing'))
    gateway_mac = str(_need(addressing, 'gateway_mac', 'addressing')).lower()

    # switches
    switches = {}
    used_dpids = set()
    for i, s in enumerate(_need(doc, 'switches', where)):
        sid = _name(_need(s, 'id', 'switch #%d' % i), 'switch #%d' % i)
        if sid in switches:
            raise TopologyError('duplicate switch id %r' % sid)
        dpid = int(s.get('dpid', i + 1))
        if dpid in used_dpids:
            raise TopologyError('duplicate dpid %d' % dpid)
        used_dpids.add(dpid)
        switches[sid] = Switch(sid, s.get('role', 'backbone'), dpid)

    def next_port(sid):
        return max(switches[sid].ports, default=0) + 1

    # links
    links = []
    seen = set()
    for i, l in enumerate(_need(doc, 'links', where)):
        w = 'link #%d' % i
        a, b = _need(l, 'a', w), _need(l, 'b', w)
        for n in (a, b):
            if n not in switches:
                raise TopologyError('%s: unknown switch %r' % (w, n))
        if a == b or frozenset((a, b)) in seen:
            raise TopologyError('%s: self-loop or duplicate link %s-%s' % (w, a, b))
        seen.add(frozenset((a, b)))
        tier = l.get('tier')
        if tier is not None and tier not in tiers:
            raise TopologyError('%s: unknown tier %r' % (w, tier))
        p = {}
        for k in LINK_KEYS:
            if k in l:
                p[k] = l[k]
            elif tier is not None and k in (tiers[tier] or {}):
                p[k] = tiers[tier][k]
            else:
                p[k] = link_defaults[k]
        if p['weight'] is None:
            p['weight'] = 1
        if p['delay_ms'] is None:
            p['delay_ms'] = 0
        if p['weight'] <= 0:
            raise TopologyError('%s: weight must be > 0' % w)
        ap = next_port(a)
        switches[a].ports[ap] = ('switch', b)
        bp = next_port(b)
        switches[b].ports[bp] = ('switch', a)
        links.append(Link(a, b, ap, bp, p['bw_mbps'], p['delay_ms'], p['weight'], i, tier))

    # hosts
    hosts = {}
    used_ips = {gateway_ip}
    used_macs = {gateway_mac}
    auto_ips = (ip for ip in host_pool.hosts())
    for i, h in enumerate(_need(doc, 'hosts', where)):
        w = 'host #%d' % i
        hid = _name(_need(h, 'id', w), w)
        if hid in hosts or hid in switches:
            raise TopologyError('duplicate node id %r' % hid)
        role = _need(h, 'role', w)
        if role not in HOST_ROLES:
            raise TopologyError('%s: role must be one of %s' % (w, HOST_ROLES))
        sid = _need(h, 'switch', w)
        if sid not in switches:
            raise TopologyError('%s: unknown switch %r' % (w, sid))
        if 'ip' in h:
            ip = ipaddress.IPv4Address(h['ip'])
        else:
            ip = next(a for a in auto_ips if a not in used_ips)
        if ip in used_ips:
            raise TopologyError('%s: duplicate ip %s' % (w, ip))
        used_ips.add(ip)
        port = next_port(sid)
        switches[sid].ports[port] = ('host', hid)
        mac = str(h.get('mac', '02:00:00:00:%02x:%02x' % ((i + 1) >> 8, (i + 1) & 0xff))).lower()
        if mac in used_macs:
            raise TopologyError('%s: duplicate mac %s (gateway or another host)' % (w, mac))
        used_macs.add(mac)
        hosts[hid] = Host(hid, role, h.get('kind', role), sid, port, ip, mac,
                          h.get('bw_mbps', host_link_defaults['bw_mbps']),
                          h.get('delay_ms', host_link_defaults['delay_ms']))

    # destination prefixes
    prefixes = {}
    for i, p in enumerate(doc.get('prefixes') or []):
        w = 'prefix #%d' % i
        net = ipaddress.IPv4Network(_need(p, 'cidr', w))
        for other in list(prefixes) + [host_pool]:
            if net.overlaps(other):
                raise TopologyError('%s: %s overlaps %s' % (w, net, other))
        if any(h.ip in net for h in hosts.values()):
            raise TopologyError('%s: %s contains a host address' % (w, net))
        topo_host = _need(p, 'host', w)
        prefixes[net] = Prefix(net, topo_host)

    topo = Topology(doc.get('name', where), switches, links, hosts, prefixes,
                    host_pool, gateway_ip, gateway_mac, open_keys)
    for p in prefixes.values():
        topo.check_prefix_host(p.host)
    _check_connected(topo)
    return topo


def _check_connected(topo):
    if not topo.switches:
        raise TopologyError('no switches')
    start = next(iter(topo.switches))
    seen, stack = {start}, [start]
    while stack:
        for n, _ in topo.neighbors(stack.pop()):
            if n not in seen:
                seen.add(n)
                stack.append(n)
    missing = set(topo.switches) - seen
    if missing:
        raise TopologyError('switch graph is not connected: %s unreachable'
                            % ', '.join(sorted(missing)))
