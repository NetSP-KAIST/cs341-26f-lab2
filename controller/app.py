"""Skeleton team controller: it logs what the kit tells it and installs nothing.

    sudo .venv/bin/python -m kit.run --app controller/app.py

Every handler below only logs. The default tables route everything, so this
app blocks nothing. Your design goes where the handlers are.
"""

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3

from kit.controller.base_app import EventBudgetReject
from kit.controller.events import (EventBlocklistOrder, EventBootstrap,
                                   EventRoutingChanged, EventTENotice)
from kit.controller.notify_app import get_blocklist, ready
from kit.controller.routing_app import get_routing


class TeamApp(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    @set_ev_cls(EventBootstrap)
    def on_bootstrap(self, ev):
        # The state at t = 0 is complete. Install rules for it, then call ready().
        entries = get_blocklist() or []
        self.logger.info('bootstrap: %d entries in force', len(entries))
        ready()

    @set_ev_cls(EventBlocklistOrder)
    def on_order(self, ev):
        self.logger.info('order %s at t=%.1f: +%d -%d entries',
                         ev.order_id, ev.t, len(ev.add), len(ev.remove))

    @set_ev_cls(EventRoutingChanged)
    def on_routing(self, ev):
        self.logger.info('routing changed at t=%.1f (%s): %d prefixes',
                         ev.t, ev.cause, len(ev.prefixes))
        for net in list(ev.prefixes)[:3]:
            self.logger.info('  %s is now at %s', net,
                             get_routing().lookup(net.network_address))

    @set_ev_cls(EventTENotice)
    def on_te_notice(self, ev):
        self.logger.info('TE change %s announced at t=%.1f, applied at t=%.1f',
                         ev.te_id, ev.t, ev.apply_at)

    @set_ev_cls(EventBudgetReject)
    def on_reject(self, ev):
        self.logger.warning('refused on switch %s (kind %s): %s',
                            ev.dpid, ev.kind, ev.reason)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        msg = ev.msg
        self.logger.info('packet-in from switch %s, table %d, port %s, %d bytes',
                         msg.datapath.id, msg.table_id, msg.match.get('in_port'),
                         len(msg.data))
