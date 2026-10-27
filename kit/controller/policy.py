"""Team flow-mod policy of the kit base layer (docs/kit/openflow-surface.md).

Pure logic over os-ken message objects, so it can be unit-tested without a
switch. KitBase (base_app.py) calls:

  connect(dp)          -> kit messages for a newly connected switch
  flow_mod(dp, mod)    -> Decision: messages to send, or a rejection
  apply(dpid, mod)     -> update the shadow for a message actually sent
  missing_slots(dp)    -> default table-miss messages for emptied slots
  flow_removed(dpid, msg), rebuild_table(dpid, t, stats)

Which messages, match fields and actions are allowed at all is checked
before this, in allowlist.py (no groups, meters or OVS extensions).

Rules
- Team tables are 0..N-1. Writes elsewhere (routing table, other tables) are
  rejected. Deletes with OFPTT_ALL are split into one delete per team table.
- The kit cookie range (top 16 bits = KIT_COOKIE) is reserved.
- K: entries in team tables, minus the free priority-0 match-all slot of each
  table. An ADD that would exceed K is rejected.
- Priority bump: a team entry that is priority 0, match-all and outputs to
  CONTROLLER is raised to priority 1 (logged), so
  every team Packet-In has reason ACTION. A modify that would put such
  instructions into the slot becomes an ADD at priority 1 instead.
- U: a team flow-mod costs the number of entries it affects, minimum 1
  (an add is 1; a modify/delete costs every entry it selects, so wildcard
  deletes and non-strict modifies pay per entry). Network-wide bucket; the
  whole message is rejected if the cost exceeds the tokens left
  (budgets.enforcement.U_over_budget). Kit messages never use U.
- Entries with timeouts get OFPFF_SEND_FLOW_REM so expiries are counted. The
  kit remembers whether the team asked for the flag itself; only those
  FlowRemoved messages reach the team app (standard OpenFlow behavior).
"""

from dataclasses import dataclass, field

from kit.controller.flowtable import (SLOT_KEY, Entry, ShadowTables,
                                      analyze_instructions, match_key, norm_match)

KIT_COOKIE_MASK = 0xffff << 48
KIT_COOKIE = 0x4b49 << 48                 # "KI"
ROUTING_COOKIE = KIT_COOKIE | 0x1         # routing table entries
DEFAULT_MISS_COOKIE = KIT_COOKIE | 0x2    # default table-miss in team tables


@dataclass
class Decision:
    send: list = field(default_factory=list)
    reject: str = None
    notes: list = field(default_factory=list)       # [(event, {fields})]
    u_cost: int = 0


class TeamPolicy:
    def __init__(self, n_tables, routing_table, K=None, u_bucket=None,
                 restore_default_miss=True):
        self.n = n_tables
        self.routing_table = routing_table
        self.K = K
        self.u = u_bucket
        self.u_enforced = True      # False during bootstrap (base_app.py)
        self.restore = restore_default_miss
        self.shadow = {}            # dpid -> ShadowTables
        # entries with SEND_FLOW_REM removed by a delete we sent: their
        # FlowRemoved (reason DELETE) is still to come.
        # dpid -> {(table, key): team_flow_rem}
        self.deleted = {}

    # ---- helpers --------------------------------------------------------
    def _sh(self, dpid):
        if dpid not in self.shadow:
            self.shadow[dpid] = ShadowTables(self.n)
        return self.shadow[dpid]

    def k_used(self, dpid):
        return self._sh(dpid).k_count()

    def table_counts(self, dpid):
        sh = self._sh(dpid)
        return {t: sh.table_count(t) for t in range(self.n)}

    def default_miss(self, dp, t):
        parser = dp.ofproto_parser
        return parser.OFPFlowMod(
            datapath=dp, table_id=t, priority=0, match=parser.OFPMatch(),
            cookie=DEFAULT_MISS_COOKIE,
            instructions=[parser.OFPInstructionGotoTable(self.routing_table)])

    @staticmethod
    def _clone(dp, mod, **over):
        kw = dict(cookie=mod.cookie, cookie_mask=mod.cookie_mask, table_id=mod.table_id,
                  command=mod.command, idle_timeout=mod.idle_timeout,
                  hard_timeout=mod.hard_timeout, priority=mod.priority,
                  buffer_id=mod.buffer_id, out_port=mod.out_port, out_group=mod.out_group,
                  flags=mod.flags, match=mod.match, instructions=mod.instructions)
        kw.update(over)
        return dp.ofproto_parser.OFPFlowMod(datapath=dp, **kw)

    def _entry(self, dpid, ofp, mod, table=None, priority=None):
        nm = norm_match(mod.match, ofp)
        ports, groups, to_ctrl = analyze_instructions(mod.instructions, ofp)
        return Entry(table=mod.table_id if table is None else table,
                     priority=mod.priority if priority is None else priority,
                     match=nm, ofmatch=mod.match, cookie=mod.cookie, flags=mod.flags,
                     idle_timeout=mod.idle_timeout, hard_timeout=mod.hard_timeout,
                     out_ports=ports, groups=groups, to_controller=to_ctrl,
                     kit=(mod.cookie & KIT_COOKIE_MASK) == KIT_COOKIE,
                     team_flow_rem=bool(mod.flags & ofp.OFPFF_SEND_FLOW_REM)
                     and not getattr(mod, 'kit_forced_flow_rem', False))

    @staticmethod
    def _force_flow_rem(mod, ofp):
        """Entries with timeouts must report their expiry to the kit."""
        if (mod.idle_timeout or mod.hard_timeout) and not mod.flags & ofp.OFPFF_SEND_FLOW_REM:
            mod.flags |= ofp.OFPFF_SEND_FLOW_REM
            mod.kit_forced_flow_rem = True

    def _targets(self, sh, mod, ofp):
        """Shadow entries a modify/delete selects (OF1.3 semantics)."""
        tables = range(self.n) if mod.table_id == ofp.OFPTT_ALL else [mod.table_id]
        tables = [t for t in tables if t < self.n]
        strict = mod.command in (ofp.OFPFC_MODIFY_STRICT, ofp.OFPFC_DELETE_STRICT)
        if mod.command in (ofp.OFPFC_MODIFY, ofp.OFPFC_MODIFY_STRICT):
            return sh.find(tables, norm_match(mod.match, ofp), mod.priority, strict,
                           mod.cookie, mod.cookie_mask)
        return sh.find(
            tables, norm_match(mod.match, ofp), mod.priority, strict,
            mod.cookie, mod.cookie_mask,
            out_port=None if mod.out_port == ofp.OFPP_ANY else mod.out_port,
            out_group=None if mod.out_group == ofp.OFPG_ANY else mod.out_group)

    def _take_u(self, cost):
        return self.u is None or not self.u_enforced or self.u.take(cost)

    # ---- switch lifecycle -----------------------------------------------
    def connect(self, dp, dpid):
        """Fresh team tables: delete everything in them, then install the
        default table-miss in every team table."""
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.shadow[dpid] = ShadowTables(self.n)
        self.deleted[dpid] = {}
        msgs = [parser.OFPFlowMod(datapath=dp, table_id=t, command=ofp.OFPFC_DELETE,
                                  out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                  match=parser.OFPMatch())
                for t in range(self.n)]
        msgs += [self.default_miss(dp, t) for t in range(self.n)]
        return msgs

    def missing_slots(self, dp, dpid):
        if not self.restore:
            return []
        sh = self._sh(dpid)
        return [self.default_miss(dp, t) for t in range(self.n) if not sh.has(t, SLOT_KEY)]

    # ---- shadow update (OF1.3 semantics of a message that was sent) -------
    def apply(self, dpid, mod, ofp):
        sh = self._sh(dpid)
        if mod.command == ofp.OFPFC_ADD:
            sh.put(self._entry(dpid, ofp, mod))
            return
        targets = self._targets(sh, mod, ofp)
        if mod.command in (ofp.OFPFC_MODIFY, ofp.OFPFC_MODIFY_STRICT):
            ports, groups, to_ctrl = analyze_instructions(mod.instructions, ofp)
            for e in targets:
                e.out_ports, e.groups, e.to_controller = ports, groups, to_ctrl
        else:
            pend = self.deleted.setdefault(dpid, {})
            for e in targets:
                if e.flags & ofp.OFPFF_SEND_FLOW_REM:
                    pend[(e.table, e.key)] = e.team_flow_rem and not e.kit
            sh.remove(targets)

    # ---- team flow-mods -------------------------------------------------
    def flow_mod(self, dp, dpid, mod):
        ofp = dp.ofproto
        sh = self._sh(dpid)
        cmd = mod.command
        is_delete = cmd in (ofp.OFPFC_DELETE, ofp.OFPFC_DELETE_STRICT)
        is_modify = cmd in (ofp.OFPFC_MODIFY, ofp.OFPFC_MODIFY_STRICT)

        if mod.table_id == ofp.OFPTT_ALL and not is_delete:
            return Decision(reject='table_id OFPTT_ALL is only valid for deletes')
        if mod.table_id != ofp.OFPTT_ALL and not 0 <= mod.table_id < self.n:
            return Decision(reject='table %d is not a team table (0..%d)'
                            % (mod.table_id, self.n - 1))
        if not is_delete and (mod.cookie & KIT_COOKIE_MASK) == KIT_COOKIE:
            return Decision(reject='cookie 0x%x is in the reserved kit range' % mod.cookie)

        d = Decision()
        if cmd == ofp.OFPFC_ADD:
            e = self._entry(dpid, ofp, mod)
            if e.is_slot and e.to_controller:
                mod.priority = 1
                e = self._entry(dpid, ofp, mod)
                d.notes.append(('priority_bump', {'table': mod.table_id}))
            new = not sh.has(e.table, e.key) and not e.is_slot
            if new and self.K is not None and sh.k_count() + 1 > self.K:
                return Decision(reject='K: %d entries used of %d' % (sh.k_count(), self.K))
            self._force_flow_rem(mod, ofp)
            d.send = [mod]
            d.u_cost = 1

        elif is_modify:
            targets = self._targets(sh, mod, ofp)
            d.u_cost = max(1, len(targets))
            _, _, to_ctrl = analyze_instructions(mod.instructions, ofp)
            if to_ctrl and any(e.is_slot for e in targets):
                # the slot keeps its instructions; the new ones go to priority 1
                bump = self._clone(dp, mod, command=ofp.OFPFC_ADD, priority=1,
                                   match=dp.ofproto_parser.OFPMatch(), cookie=0)
                self._force_flow_rem(bump, ofp)
                if (not sh.has(mod.table_id, (1, ())) and self.K is not None
                        and sh.k_count() + 1 > self.K):
                    return Decision(reject='K: %d entries used of %d' % (sh.k_count(), self.K))
                d.send = [self._clone(dp, mod, command=ofp.OFPFC_MODIFY_STRICT,
                                      priority=e.priority, match=e.ofmatch)
                          for e in targets if not e.is_slot] + [bump]
                d.notes.append(('priority_bump', {'table': mod.table_id, 'via': 'modify'}))
            else:
                d.send = [mod]

        elif is_delete:
            d.u_cost = max(1, len(self._targets(sh, mod, ofp)))
            if mod.table_id == ofp.OFPTT_ALL:
                d.send = [self._clone(dp, mod, table_id=t) for t in range(self.n)]
            else:
                d.send = [mod]
        else:
            return Decision(reject='unknown flow-mod command %d' % cmd)

        if not self._take_u(d.u_cost):
            return Decision(reject='U: rule-change budget exceeded (this flow-mod affects '
                                   '%d entries)' % d.u_cost)
        return d

    # ---- switch-side changes --------------------------------------------
    def flow_removed(self, dpid, msg, ofp):
        """Update the shadow for an expired/deleted entry. Returns
        (known, notify_team): notify_team only if the team itself asked for
        OFPFF_SEND_FLOW_REM on that entry."""
        if msg.table_id >= self.n:
            return False, False
        e_key = (msg.priority, match_key(norm_match(msg.match, ofp)))
        if msg.reason == ofp.OFPRR_DELETE:
            pend = self.deleted.get(dpid, {})
            if (msg.table_id, e_key) in pend:
                return True, pend.pop((msg.table_id, e_key))
        e = self._sh(dpid).tables[msg.table_id].pop(e_key, None)
        if e is None:
            return False, False
        return True, e.team_flow_rem and not e.kit

    def rebuild_table(self, dpid, t, stats, ofp):
        """Replace the shadow of table t with flow stats from the switch."""
        sh = self._sh(dpid)
        old = sh.tables[t]
        sh.clear(t)
        for s in stats:
            ports, groups, to_ctrl = analyze_instructions(s.instructions, ofp)
            key = (s.priority, match_key(norm_match(s.match, ofp)))
            # whether the team asked for SEND_FLOW_REM is not in the stats
            team_rem = old[key].team_flow_rem if key in old else \
                bool(s.flags & ofp.OFPFF_SEND_FLOW_REM)
            sh.put(Entry(table=t, priority=s.priority, match=norm_match(s.match, ofp),
                         ofmatch=s.match, cookie=s.cookie, flags=s.flags,
                         idle_timeout=s.idle_timeout, hard_timeout=s.hard_timeout,
                         out_ports=ports, groups=groups, to_controller=to_ctrl,
                         kit=(s.cookie & KIT_COOKIE_MASK) == KIT_COOKIE,
                         team_flow_rem=team_rem))
