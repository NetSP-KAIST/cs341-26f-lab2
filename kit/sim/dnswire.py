"""Minimal DNS wire format: A queries and answers, EDNS0 with Client Subnet.

Enough for the simulator's agents (RFC 1035 header / question / A records,
RFC 6891 OPT, RFC 7871 ECS) and tolerant of other senders' messages, e.g. a
team controller's crafted answers (name compression is followed on parse).

The authoritative DNS also returns a private EDNS option (OPT_VIEW) with the
answer's view and scope, so the internal resolver can cache per view
(dnsmodel.ResolverCache). Only the resolver <-> authoritative leg carries it.
"""

import hashlib
import ipaddress
import json
import struct

TYPE_A, TYPE_OPT, CLASS_IN = 1, 41, 1
OPT_ECS = 8
OPT_VIEW = 65001                 # local/experimental option range (RFC 6891 §9)
RCODE_OK, RCODE_FORMERR, RCODE_SERVFAIL, RCODE_NXDOMAIN, RCODE_NOTIMP = 0, 1, 2, 3, 4
EDNS_SIZE = 1232


class DnsError(ValueError):
    pass


def _name(name):
    out = b''
    for label in name.rstrip('.').split('.'):
        b = label.encode('ascii')
        if not 0 < len(b) < 64:
            raise DnsError('bad label in %r' % name)
        out += bytes([len(b)]) + b
    return out + b'\0'


def _read_name(data, off):
    labels, jumped, end, hops = [], False, off, 0
    while True:
        if off >= len(data):
            raise DnsError('name runs past the message')
        n = data[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise DnsError('truncated pointer')
            if not jumped:
                end = off + 2
            off = ((n & 0x3F) << 8) | data[off + 1]
            jumped = True
            hops += 1
            if hops > 32:
                raise DnsError('pointer loop')
            continue
        if n == 0:
            if not jumped:
                end = off + 1
            return '.'.join(labels).lower(), end
        labels.append(data[off + 1:off + 1 + n].decode('ascii', 'replace'))
        off += 1 + n


def _opt(options):
    rdata = b''.join(struct.pack('!HH', c, len(v)) + v for c, v in options)
    return b'\0' + struct.pack('!HHIH', TYPE_OPT, EDNS_SIZE, 0, len(rdata)) + rdata


def ecs_option(net):
    """ECS option for an IPv4 network (source prefix = its length, scope 0)."""
    net = ipaddress.IPv4Network(net)
    nbytes = (net.prefixlen + 7) // 8
    return OPT_ECS, struct.pack('!HBB', 1, net.prefixlen, 0) + net.network_address.packed[:nbytes]


def encode_query(qid, name, ecs=None):
    opts = [ecs_option(ecs)] if ecs else None
    head = struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 1 if opts is not None else 0)
    q = _name(name) + struct.pack('!HH', TYPE_A, CLASS_IN)
    return head + q + (_opt(opts) if opts is not None else b'')


def encode_response(query, ips=(), ttl=0, rcode=RCODE_OK, ecs_scope=None, view=None):
    """Answer to a parsed query. ecs_scope: echo the query's ECS with this scope length."""
    opts = []
    if ecs_scope is not None and query.get('ecs'):
        net, _ = query['ecs']
        o = ecs_option(net)
        opts.append((OPT_ECS, o[1][:3] + bytes([ecs_scope]) + o[1][4:]))
    if view is not None:
        opts.append((OPT_VIEW, json.dumps(view, separators=(',', ':')).encode()))
    has_opt = bool(opts) or query.get('edns')
    flags = 0x8000 | 0x0400 | (query.get('flags', 0) & 0x0100) | 0x0080 | (rcode & 0xF)
    head = struct.pack('!HHHHHH', query['id'], flags, 1, len(ips), 0, 1 if has_opt else 0)
    q = _name(query['qname']) + struct.pack('!HH', query.get('qtype', TYPE_A), CLASS_IN)
    ans = b''.join(b'\xc0\x0c' + struct.pack('!HHIH', TYPE_A, CLASS_IN, max(0, int(ttl)), 4)
                   + ipaddress.IPv4Address(ip).packed for ip in ips)
    return head + q + ans + (_opt(opts) if has_opt else b'')


def parse(data):
    """dict: id, flags, qr, rcode, qname, qtype, answers [(ip, ttl)], edns, ecs, view."""
    if len(data) < 12:
        raise DnsError('short message')
    qid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', data[:12])
    msg = {'id': qid, 'flags': flags, 'qr': bool(flags & 0x8000), 'rcode': flags & 0xF,
           'qname': None, 'qtype': None, 'answers': [], 'edns': False, 'ecs': None,
           'view': None}
    off = 12
    for i in range(qd):
        name, off = _read_name(data, off)
        if off + 4 > len(data):
            raise DnsError('truncated question')
        qtype, _ = struct.unpack('!HH', data[off:off + 4])
        off += 4
        if i == 0:
            msg['qname'], msg['qtype'] = name, qtype
    for i in range(an + ns + ar):
        _, off = _read_name(data, off)
        if off + 10 > len(data):
            raise DnsError('truncated record')
        rtype, _, ttl, rdlen = struct.unpack('!HHIH', data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if i < an and rtype == TYPE_A and rdlen == 4:
            msg['answers'].append((str(ipaddress.IPv4Address(rdata)), ttl))
        elif rtype == TYPE_OPT:
            msg['edns'] = True
            p = 0
            while p + 4 <= len(rdata):
                code, olen = struct.unpack('!HH', rdata[p:p + 4])
                val = rdata[p + 4:p + 4 + olen]
                p += 4 + olen
                if code == OPT_ECS and len(val) >= 4:
                    fam, src, scope = struct.unpack('!HBB', val[:4])
                    if fam == 1 and src <= 32:
                        addr = (val[4:] + b'\0' * 4)[:4]
                        net = ipaddress.IPv4Network((ipaddress.IPv4Address(addr), src),
                                                    strict=False)
                        msg['ecs'] = (str(net), scope)
                elif code == OPT_VIEW:
                    try:
                        msg['view'] = json.loads(val)
                    except ValueError:
                        pass
    return msg


# ---- encrypted DNS (modeled) ------------------------------------------------
# Real encryption is out of scope. An encrypted-DNS session is a
# TCP connection that starts with a 16-byte random nonce from the client, then
# one frame each way: 2-byte length + a DNS message XORed with a key stream
# from SHA-256(nonce, direction, block). On the wire it carries no readable
# DNS: a switch sees only the endpoint's address and port.

NONCE_BYTES = 16


class Opaque:
    def __init__(self, nonce, direction):
        self.nonce, self.direction = nonce, direction
        self.block, self.buf = 0, b''

    def _stream(self, n):
        while len(self.buf) < n:
            self.buf += hashlib.sha256(self.nonce + self.direction +
                                       self.block.to_bytes(8, 'big')).digest()
            self.block += 1
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def apply(self, data):
        return bytes(a ^ b for a, b in zip(data, self._stream(len(data))))


def opaque_frame(opaque, msg):
    body = opaque.apply(msg)
    return struct.pack('!H', len(body)) + body
