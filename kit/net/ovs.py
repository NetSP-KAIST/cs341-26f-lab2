"""OVS switch with the kit's budget settings applied at bridge creation.

Mininet creates each bridge, its controller rows and bridge options in one
ovs-vsctl transaction. KitOVSSwitch adds to that same transaction:

- K backstop: a Flow_Table with flow_limit = K + 1 (the free priority-0 slot)
  and overflow_policy on every team table 0..N-1. The kit's flow-mod layer is
  the primary K check; this only stops anything that slips past it.
- Pₛ: controller_rate_limit / controller_burst_limit on the Controller rows
  (OVSDB floor: rate >= 100, burst >= 25).

Both are in place before the switch first connects to the controller.
"""

from mininet.node import OVSSwitch

PS_MIN_RATE, PS_MIN_BURST = 100, 25


def switch_budget_params(cfg):
    """Keyword arguments for KitOVSSwitch from a run config (None = not set)."""
    b = cfg['budgets']
    enf = b.get('enforcement') or {}
    K = b.get('K_per_switch')
    n = cfg['pipeline']['team_tables']
    flow_limits = None
    if K is not None and enf.get('flow_limit_backstop', True):
        flow_limits = {t: K + 1 for t in range(n)}
    rate, burst = b.get('Ps_packet_in_per_s_per_switch'), b.get('Ps_burst_per_switch')
    if rate is not None and rate < PS_MIN_RATE:
        raise ValueError('Ps_packet_in_per_s_per_switch must be >= %d (OVSDB floor)'
                         % PS_MIN_RATE)
    if burst is not None and burst < PS_MIN_BURST:
        raise ValueError('Ps_burst_per_switch must be >= %d (OVSDB floor)' % PS_MIN_BURST)
    return dict(flow_limits=flow_limits, overflow_policy=enf.get('overflow_policy', 'refuse'),
                rate_limit=rate, burst_limit=burst)


class KitOVSSwitch(OVSSwitch):

    def __init__(self, name, flow_limits=None, overflow_policy='refuse',
                 rate_limit=None, burst_limit=None, **params):
        super().__init__(name, **params)
        self.flow_limits = flow_limits or {}
        self.overflow_policy = overflow_policy
        self.rate_limit = rate_limit
        self.burst_limit = burst_limit

    def _ref(self, t):
        return '%sft%d' % (self.name, t)

    def bridgeOpts(self):
        opts = super().bridgeOpts()
        for t in sorted(self.flow_limits):
            opts += ' flow_tables:%d=@%s' % (t, self._ref(t))
        return opts

    def start(self, controllers):
        """Mininet's OVSSwitch.start (2.3.1b4) plus Flow_Table rows and
        controller rate limits in the same ovs-vsctl transaction."""
        if self.inNamespace:
            raise Exception('OVS kernel switch does not work in a namespace')
        int(self.dpid, 16)
        intfs = ''.join(' -- add-port %s %s' % (self, intf) + self.intfOpts(intf)
                        for intf in self.intfList()
                        if self.ports[intf] and not intf.IP())
        clist = [(self.name + c.name, '%s:%s:%d' % (c.protocol, c.IP(), c.port))
                 for c in controllers]
        if self.listenPort:
            clist.append((self.name + '-listen', 'ptcp:%s' % self.listenPort))
        ccmd = '-- --id=@%s create Controller target=\\"%s\\"'
        if self.reconnectms:
            ccmd += ' max_backoff=%d' % self.reconnectms
        if self.rate_limit is not None:
            ccmd += ' controller_rate_limit=%d' % self.rate_limit
            if self.burst_limit is not None:
                ccmd += ' controller_burst_limit=%d' % self.burst_limit
        cargs = ' '.join(ccmd % (name, target) for name, target in clist)
        for t in sorted(self.flow_limits):
            cargs += (' -- --id=@%s create Flow_Table name=team%d flow_limit=%d '
                      'overflow_policy=%s' % (self._ref(t), t, self.flow_limits[t],
                                              self.overflow_policy))
        cids = ','.join('@%s' % name for name, _target in clist)
        if not self.isOldOVS():
            cargs += ' -- --if-exists del-br %s' % self
        self.vsctl(cargs +
                   ' -- add-br %s' % self +
                   ' -- set bridge %s controller=[%s]' % (self, cids) +
                   self.bridgeOpts() +
                   intfs)
        if not self.batch:
            for intf in self.intfList():
                self.TCReapply(intf)
