"""Blocklist entries and matching (docs/kit/simulator.md §4).

Shared by the generator, kit.sim.truth and the kit controller
(get_blocklist()), so every side matches the same way.

Entry types:
  domain    {"type": "domain", "value": "www.a.example"}    the name itself
  suffix    {"type": "suffix", "value": "a.example"}        the name or any
            name below it, on a label boundary (no leading dot)
  ip        {"type": "ip", "value": "198.18.4.10" | "198.18.4.0/24"}
  endpoint  {"type": "endpoint", "kind": "encrypted_dns", "ip": "198.18.3.10",
             "port": 443 (optional), "id": "edns1" (optional, truth only)}
"""

import ipaddress

TYPES = ('domain', 'suffix', 'ip', 'endpoint')
ENDPOINT_KINDS = ('ext_resolver', 'encrypted_dns')


class BlocklistError(ValueError):
    pass


def normalize_name(name):
    """Lower case, no trailing dot."""
    return str(name).strip().lower().rstrip('.')


def normalize_entry(e):
    """Validated copy of an entry, in canonical form."""
    if not isinstance(e, dict):
        raise BlocklistError('entry must be an object: %r' % (e,))
    t = e.get('type')
    if t in ('domain', 'suffix'):
        v = normalize_name(e.get('value', ''))
        if not v or v.startswith('.') or '..' in v:
            raise BlocklistError('bad %s value %r' % (t, e.get('value')))
        return {'type': t, 'value': v}
    if t == 'ip':
        try:
            net = ipaddress.IPv4Network(str(e.get('value')), strict=True)
        except ValueError as ex:
            raise BlocklistError('bad ip value %r: %s' % (e.get('value'), ex))
        v = str(net.network_address) if net.prefixlen == 32 else str(net)
        return {'type': 'ip', 'value': v}
    if t == 'endpoint':
        if e.get('kind') not in ENDPOINT_KINDS:
            raise BlocklistError('endpoint kind must be one of %s' % (ENDPOINT_KINDS,))
        try:
            ip = str(ipaddress.IPv4Address(str(e.get('ip'))))
        except ValueError:
            raise BlocklistError('bad endpoint ip %r' % (e.get('ip'),))
        out = {'type': 'endpoint', 'kind': e['kind'], 'ip': ip}
        if e.get('port') is not None:
            port = e['port']
            if not (isinstance(port, int) and 0 < port < 65536):
                raise BlocklistError('bad endpoint port %r' % (port,))
            out['port'] = port
        if e.get('id') is not None:
            out['id'] = str(e['id'])
        return out
    raise BlocklistError('entry type must be one of %s, not %r' % (TYPES, t))


def entry_key(e):
    """Identity of an entry: add/remove compare by this (id is not part of it)."""
    if e['type'] == 'endpoint':
        return ('endpoint', e['ip'], e.get('port'))
    return (e['type'], e['value'])


def name_suffixes(name):
    """'a.b.c' -> ['a.b.c', 'b.c', 'c']."""
    labels = name.split('.')
    return ['.'.join(labels[i:]) for i in range(len(labels))]


class Blocklist:
    """The blocklist in force: entries, and the order that added each."""

    def __init__(self):
        self._entries = {}      # key -> (entry, order_id)
        self._domains = {}
        self._suffixes = {}
        self._hosts = {}        # /32 ip entries: address -> key
        self._nets = {}         # wider ip entries: network -> key
        self._endpoints = {}    # (ip, port or None) -> key

    def __len__(self):
        return len(self._entries)

    def __contains__(self, entry):
        return entry_key(normalize_entry(entry)) in self._entries

    def apply_order(self, order_id, add=(), remove=()):
        """Removes first, then adds. Returns (added keys, removed keys)."""
        removed = []
        for e in remove:
            k = entry_key(normalize_entry(e))
            if self._drop(k):
                removed.append(k)
        added = []
        for e in add:
            e = normalize_entry(e)
            k = entry_key(e)
            if k not in self._entries:
                added.append(k)
                self._put(k, e)
            self._entries[k] = (e, order_id)
        return added, removed

    def _put(self, k, e):
        t = e['type']
        if t == 'domain':
            self._domains[e['value']] = k
        elif t == 'suffix':
            self._suffixes[e['value']] = k
        elif t == 'ip':
            net = ipaddress.IPv4Network(e['value'])
            if net.prefixlen == 32:
                self._hosts[net.network_address] = k
            else:
                self._nets[net] = k
        else:
            self._endpoints[(e['ip'], e.get('port'))] = k

    def _drop(self, k):
        if k not in self._entries:
            return False
        e, _ = self._entries.pop(k)
        t = e['type']
        if t == 'domain':
            del self._domains[e['value']]
        elif t == 'suffix':
            del self._suffixes[e['value']]
        elif t == 'ip':
            net = ipaddress.IPv4Network(e['value'])
            if net.prefixlen == 32:
                del self._hosts[net.network_address]
            else:
                del self._nets[net]
        else:
            del self._endpoints[(e['ip'], e.get('port'))]
        return True

    def entries(self):
        """[{"entry": ..., "order_id": ...}] in insertion order."""
        return [{'entry': dict(e), 'order_id': o} for e, o in self._entries.values()]

    def match(self, site=None, ips=(), endpoint=None):
        """First matching entry, or None.

        site: the Host name; ips: every IP the request contacts; endpoint:
        (ip, port) of the resolver endpoint the request used, if any.
        Checked in the order domain, suffix, ip, endpoint.
        """
        if site:
            name = normalize_name(site)
            k = self._domains.get(name)
            if k is None:
                for s in name_suffixes(name):
                    k = self._suffixes.get(s)
                    if k is not None:
                        break
            if k is not None:
                return dict(self._entries[k][0])
        for ip in ips:
            if ip is None:
                continue
            a = ipaddress.IPv4Address(ip)
            k = self._hosts.get(a)
            if k is None:
                k = next((v for n, v in self._nets.items() if a in n), None)
            if k is not None:
                return dict(self._entries[k][0])
        if endpoint is not None:
            ip, port = str(endpoint[0]), endpoint[1]
            k = self._endpoints.get((ip, port)) or self._endpoints.get((ip, None))
            if k is not None:
                return dict(self._entries[k][0])
        return None
