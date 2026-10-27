"""Shadow copy of the team tables with OpenFlow 1.3 flow-mod semantics.

Used by the base layer to count K exactly. Matches are
normalized with os-ken's oxm_from_user() to {field: (value & mask, mask)} so
strict equality and non-strict subsumption ("entry is at least as specific
as the request") are exact.

Counting rule: in each team table the one priority-0
match-all slot is free, whatever occupies it; every other entry counts.
"""

from dataclasses import dataclass, field

SLOT_KEY = (0, ())          # (priority, match key) of the free slot


def norm_match(match, ofproto):
    out = {}
    for name, user in match.items():
        _, value, mask = ofproto.oxm_from_user(name, user)
        full = (1 << (8 * len(value))) - 1
        m = int.from_bytes(mask, 'big') if mask is not None else full
        out[name] = (int.from_bytes(value, 'big') & m, m)
    return out


def match_key(nm):
    return tuple(sorted(nm.items()))


def subsumes(req, entry):
    """True if an entry with match `entry` is selected by request match `req`."""
    for f, (rv, rm) in req.items():
        if f not in entry:
            return False
        ev, em = entry[f]
        if em & rm != rm or ev & rm != rv:
            return False
    return True


def analyze_instructions(instructions, ofproto, controller_groups=frozenset()):
    """(output ports, group ids, outputs to CONTROLLER?) over apply/write actions."""
    ports, groups = set(), set()
    for inst in instructions or []:
        for act in getattr(inst, 'actions', None) or []:
            if act.cls_action_type == ofproto.OFPAT_OUTPUT:
                ports.add(act.port)
            elif act.cls_action_type == ofproto.OFPAT_GROUP:
                groups.add(act.group_id)
    to_ctrl = ofproto.OFPP_CONTROLLER in ports or bool(groups & set(controller_groups))
    return frozenset(ports), frozenset(groups), to_ctrl


@dataclass
class Entry:
    table: int
    priority: int
    match: dict                 # normalized
    ofmatch: object = None      # os-ken OFPMatch, to re-send
    cookie: int = 0
    flags: int = 0
    idle_timeout: int = 0
    hard_timeout: int = 0
    out_ports: frozenset = frozenset()
    groups: frozenset = frozenset()
    to_controller: bool = False
    kit: bool = False           # installed by the kit (default table-miss)
    team_flow_rem: bool = False # the team itself asked for OFPFF_SEND_FLOW_REM

    @property
    def key(self):
        return (self.priority, match_key(self.match))

    @property
    def is_slot(self):
        return self.key == SLOT_KEY


@dataclass
class ShadowTables:
    n_tables: int
    tables: dict = field(default_factory=dict)

    def __post_init__(self):
        for t in range(self.n_tables):
            self.tables.setdefault(t, {})

    def k_count(self):
        return sum(len(es) - (SLOT_KEY in es) for es in self.tables.values())

    def table_count(self, t):
        return len(self.tables[t])

    def has(self, t, key):
        return key in self.tables[t]

    def put(self, entry):
        self.tables[entry.table][entry.key] = entry

    def remove(self, entries):
        for e in entries:
            self.tables[e.table].pop(e.key, None)

    def clear(self, t=None):
        for tt in ([t] if t is not None else list(self.tables)):
            self.tables[tt] = {}

    def find(self, tables, match, priority=None, strict=False, cookie=0, cookie_mask=0,
             out_port=None, out_group=None):
        """Entries a modify/delete request selects (OF1.3 semantics)."""
        mk = match_key(match)
        out = []
        for t in tables:
            for e in self.tables[t].values():
                if strict:
                    if e.priority != priority or match_key(e.match) != mk:
                        continue
                elif not subsumes(match, e.match):
                    continue
                if cookie_mask and (e.cookie & cookie_mask) != (cookie & cookie_mask):
                    continue
                if out_port is not None and out_port not in e.out_ports:
                    continue
                if out_group is not None and out_group not in e.groups:
                    continue
                out.append(e)
        return out
