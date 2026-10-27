"""Host-side addressing inside Mininet namespaces.

Each host gets a /32 address and sends everything to the virtual gateway
(static, permanent neighbor entry), so there is no ARP in the network. A
destination CIDR block is "attached" to a server-side host as a local route,
so the host answers for every address in the block.

A PoP host (kind pop) is both its subscribers' client and the server of the
sites it hosts, all inside its one address block. Traffic between two of its
own addresses must still cross its switch port, so the controller sees it:
locally generated packets are routed out through the gateway before the
local table is consulted (only 127/8 stays on lo), and accept_local lets the
copy that comes back in, with a local source address, be delivered. The
switch sends it back out the same port (table 201, IN_PORT).
"""

SAME_HOST_TABLE = 100


def configure_host(node, host, topo):
    intf = node.defaultIntf().name
    gw = str(topo.gateway_ip)
    cmds = [
        'sysctl -qw net.ipv6.conf.all.disable_ipv6=1',
        'ip addr flush dev %s' % intf,
        'ip addr add %s/32 dev %s' % (host.ip, intf),
        'ip link set %s up' % intf,
        'ip route add %s dev %s' % (gw, intf),
        'ip route add default via %s dev %s' % (gw, intf),
        'ip neigh replace %s lladdr %s dev %s nud permanent' % (gw, topo.gateway_mac, intf),
    ]
    if host.kind == 'pop':
        cmds += [
            'ip route add default via %s dev %s onlink table %d' % (gw, intf, SAME_HOST_TABLE),
            'ip rule add pref 10 to 127.0.0.0/8 lookup local',
            'ip rule add pref 20 iif lo lookup %d' % SAME_HOST_TABLE,
            'ip rule add pref 30 lookup local',
            'ip rule del pref 0 lookup local',
            'sysctl -qw net.ipv4.conf.all.accept_local=1',
            'sysctl -qw net.ipv4.conf.%s.accept_local=1' % intf,
            'sysctl -qw net.ipv4.conf.all.rp_filter=0',
            'sysctl -qw net.ipv4.conf.%s.rp_filter=0' % intf,
        ]
    for c in cmds:
        out = node.cmd(c + ' 2>&1')
        if out.strip():
            raise RuntimeError('%s: %r failed: %s' % (host.id, c, out.strip()))


def attach_prefix(node, cidr):
    node.cmd('ip route replace local %s dev lo' % cidr)


def detach_prefix(node, cidr):
    node.cmd('ip route del local %s dev lo' % cidr)


def move_prefix(net, cidr, old_host, new_host):
    """Move the address block on the hosts. Routes are the controller's job."""
    detach_prefix(net.get(old_host), cidr)
    attach_prefix(net.get(new_host), cidr)


OFFLOAD_OFF = 'tso off gso off gro off'


def set_link_mtu(net, topo, mtu):
    """MTU on both ends of every switch-to-switch link; host links keep 1500
    (room for an MPLS label or VLAN tag on the backbone)."""
    for link in net.links:
        if any(i.node.name in topo.hosts for i in (link.intf1, link.intf2)):
            continue
        for i in (link.intf1, link.intf2):
            out = i.node.cmd('ip link set %s mtu %d 2>&1' % (i.name, mtu))
            if out.strip():
                raise RuntimeError('%s: mtu %d on %s failed: %s' % (i.node.name, mtu,
                                                                     i.name, out.strip()))


def disable_offload(net):
    """TSO / GSO / GRO off on both ends of every link, so
    switches see MSS-sized segments as in a real network."""
    for node in net.hosts + net.switches:
        for intf in node.intfList():
            if intf.name == 'lo' or intf.link is None:
                continue
            out = node.cmd('ethtool -K %s %s 2>&1' % (intf.name, OFFLOAD_OFF))
            if 'Cannot' in out or 'not found' in out:
                raise RuntimeError('%s: ethtool -K %s failed: %s' % (node.name, intf.name,
                                                                       out.strip()))
