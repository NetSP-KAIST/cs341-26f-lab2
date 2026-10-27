"""Build a Mininet network from a kit Topology (OVS, OpenFlow 1.3, remote controller)."""

from mininet.link import Link, TCIntf
from mininet.net import Mininet
from mininet.node import RemoteController

from kit.net.hosts import attach_prefix, configure_host, disable_offload, set_link_mtu
from kit.net.ovs import KitOVSSwitch, switch_budget_params


HTB_QUANTUM = 60000         # bytes; one class per link, so only the warning matters


class KitTCIntf(TCIntf):
    """TCIntf whose htb class sets its quantum. Mininet leaves it to r2q
    (rate / 10), which the kernel warns about above ~16 Mbit/s and below
    ~0.8 Mbit/s ("quantum of class 50001 is big/small")."""

    def bwCmds(self, *args, **kwargs):
        cmds, parent = super().bwCmds(*args, **kwargs)
        return [c.replace(' burst 15k', ' burst 15k quantum %d' % HTB_QUANTUM)
                if ' htb rate ' in c else c for c in cmds], parent


class KitTCLink(Link):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('cls1', KitTCIntf)
        kwargs.setdefault('cls2', KitTCIntf)
        super().__init__(*args, **kwargs)


def _link_params(bw_mbps, delay_ms):
    p = {}
    if bw_mbps:
        p['bw'] = bw_mbps
    if delay_ms:
        p['delay'] = '%gms' % delay_ms
    return p


def build_network(topo, cfg):
    ctl = cfg['controller']
    net = Mininet(switch=KitOVSSwitch, link=KitTCLink, controller=None, build=False,
                  autoSetMacs=False, autoStaticArp=False)
    net.addController(RemoteController('c0', ip=ctl['host'], port=ctl['port']))
    budget = switch_budget_params(cfg)
    for s in topo.switches.values():
        net.addSwitch(s.id, dpid='%016x' % s.dpid, protocols='OpenFlow13',
                      failMode='secure', **budget)
    for h in topo.hosts.values():
        net.addHost(h.id, ip='%s/32' % h.ip, mac=h.mac)
    for l in topo.links:
        net.addLink(l.a, l.b, port1=l.a_port, port2=l.b_port,
                    **_link_params(l.bw_mbps, l.delay_ms))
    for h in topo.hosts.values():
        net.addLink(h.id, h.switch, port2=h.port, **_link_params(h.bw_mbps, h.delay_ms))
    return net


def start_network(net, topo, cfg=None):
    net.build()
    net.start()
    disable_offload(net)
    mtu = ((cfg or {}).get('topology', {}).get('defaults') or {}).get('link_mtu')
    if mtu:
        set_link_mtu(net, topo, mtu)
    for h in topo.hosts.values():
        configure_host(net.get(h.id), h, topo)
    for p in topo.prefixes.values():
        attach_prefix(net.get(p.host), p.cidr)
