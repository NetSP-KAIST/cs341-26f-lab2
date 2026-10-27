"""Kit events for team apps (docs/kit/openflow-surface.md "Kit events and lookups").

    from kit.controller.events import (EventRoutingChanged, EventTENotice,
                                       EventBlocklistOrder, EventBootstrap)

    @set_ev_cls(EventRoutingChanged)
    def on_routing(self, ev): ...

All are emitted by the kit's NotifyApp when the run's orchestrator plays the
corresponding timeline event (EventBootstrap: once, before the clock starts). `t` is scenario time (seconds).
EventRoutingChanged comes only after every changed switch has acknowledged
the new routing-table entries with a barrier reply, so the change is already
in effect.
"""

from os_ken.controller import event


class EventRoutingChanged(event.EventBase):
    """The kit routing table (table 200) changed.

    cause     'bgp' | 'te' | 'link_down' | 'link_up'
    t         scenario time
    prefixes  [IPv4Network] destinations whose route changed on some switch
    detail    bgp: {'prefix', 'from', 'to'} (exit host ids); te: {'te_id',
              'weights'}; link_down / link_up: {'link': 'B3-B9'}
    """

    def __init__(self, cause, t, prefixes, detail):
        super().__init__()
        self.cause = cause
        self.t = t
        self.prefixes = prefixes
        self.detail = detail


class EventTENotice(event.EventBase):
    """A traffic-engineering re-optimization will be applied at `apply_at`."""

    def __init__(self, te_id, t, apply_at):
        super().__init__()
        self.te_id = te_id
        self.t = t
        self.apply_at = apply_at


class EventBlocklistOrder(event.EventBase):
    """A blocklist order, in force from `t` on.

    add / remove: lists of entries, as in get_blocklist():
      {'type': 'domain' | 'suffix', 'value': name}
      {'type': 'ip', 'value': address or CIDR}
      {'type': 'endpoint', 'kind': 'ext_resolver' | 'encrypted_dns', 'ip': ..., 'port': ...}
    """

    def __init__(self, order_id, t, add, remove):
        super().__init__()
        self.order_id = order_id
        self.t = t
        self.add = add
        self.remove = remove


class EventBootstrap(event.EventBase):
    """Bootstrap (kit.run, simulator.md §1): the state at t = 0 is in place.

    Sent once, before the scenario clock starts, after the t = 0 events
    (the initial EventBlocklistOrder, if any). get_blocklist() is the
    blocklist in force at t = 0. Install your rules for it, then call
    kit.controller.notify_app.ready(); until then (or `timeout_s`), U is
    not enforced and no traffic flows.
    """

    def __init__(self, timeout_s):
        super().__init__()
        self.t = 0
        self.timeout_s = timeout_s


TEAM_EVENTS = [EventRoutingChanged, EventTENotice, EventBlocklistOrder, EventBootstrap]
