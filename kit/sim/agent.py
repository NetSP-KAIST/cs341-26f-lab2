"""Simulator agents, one process per Mininet host.

    python -m kit.sim.agent location --host E1 --auth-dns --endpoints --scenario S --run-dir D
    python -m kit.sim.agent resolver --host DNS --scenario S --run-dir D
    python -m kit.sim.agent client   --host S3  --scenario S --run-dir D

Started by kit.sim.launch. Each agent plays its own slice of the timeline
against the shared scenario clock: it applies its t = 0 state (location
agents) and writes <run-dir>/agents/<host>.<role>.ready once its sockets are bound,
then waits for <run-dir>/clock.json (t0, wall seconds; written after the
controller's bootstrap) and treats time.time() - t0 as scenario time.

location  HTTP on :80 for every address routed to the host. A request is
          served (200, body starting "lab2-content <site>") when the
          server_content map says the site is served at the address it
          arrived on; otherwise 404. Every location agent plays the whole
          map, so it does not matter which host a prefix is at.
          --auth-dns: also the authoritative DNS, bound to its address with
          IP_FREEBIND, so it answers wherever that prefix is routed.
          --endpoints: also the external resolvers (UDP 53) and encrypted-DNS
          endpoints (opaque TCP, dnswire.Opaque), the same way. Each keeps its
          own cache (default view) per host.
resolver  The internal resolver at the DNS host's address: dnsmodel cache by
          (domain, view), the client's PoP sent upstream as ECS.
client    Performs the host's `request` events and logs them to
          <run-dir>/requests/<host>.jsonl.
"""

import argparse
import asyncio
import ipaddress
import json
import os
import random
import socket
import sys
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from kit.sim import dnswire, timeline
from kit.sim.dnsmodel import DEFAULT_VIEW, Answer, DnsState, ResolverCache

IP_FREEBIND = getattr(socket, 'IP_FREEBIND', 15)
HTTP_PORT, DNS_PORT = 80, 53
MARKER = 'lab2-content '
MAX_SIZE = 50_000_000
CONNECT_TIMEOUT_S = 3.0
REQUEST_TIMEOUT_S = 10.0
DNS_TIMEOUT_S = 1.0
DNS_TRIES = 2
UPSTREAM_TIMEOUT_S = 0.8
SPLIT_GAP_S = 0.05
COOKIE_BYTES = 2000         # large_header: pushes the header past one MSS
DRAIN_S = REQUEST_TIMEOUT_S + 2 * DNS_TIMEOUT_S * DNS_TRIES


class Clock:
    def __init__(self, t0):
        self.t0 = t0

    def now(self):
        return time.time() - self.t0

    async def until(self, t):
        d = self.t0 + t - time.time()
        if d > 0:
            await asyncio.sleep(d)


async def wait_clock(run_dir):
    p = Path(run_dir) / 'clock.json'
    while not p.exists():
        await asyncio.sleep(0.02)
    return Clock(json.loads(p.read_text())['t0'])


class Log:
    def __init__(self, path, clock=None):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.f = open(path, 'a', buffering=1)
        self.clock = clock

    def write(self, rec):
        rec = dict(rec)
        rec.setdefault('wall', round(time.time(), 6))
        if self.clock is not None:
            rec.setdefault('t', round(self.clock.now(), 3))
        self.f.write(json.dumps(rec) + '\n')


def ready(args):
    """agents/<host>.<role>.ready: a PoP host runs a client and a location agent."""
    d = Path(args.run_dir) / 'agents'
    d.mkdir(parents=True, exist_ok=True)
    (d / ('%s.%s.ready' % (args.host, args.role))).write_text(str(os.getpid()))


async def play(clock, events, apply):
    for e in events:
        await clock.until(e['t'])
        apply(e)


class PopMap:
    """Client address -> PoP name, from the header's pops."""

    def __init__(self, header):
        self.pops = [(ipaddress.IPv4Network(p['prefix']), p['pop']) for p in header['pops']]
        self.prefix = {pop: str(net) for net, pop in self.pops}

    def of(self, ip):
        a = ipaddress.IPv4Address(ip)
        return next((pop for net, pop in self.pops if a in net), None)


def udp_socket(ip, port, freebind=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if freebind:
        s.setsockopt(socket.SOL_IP, IP_FREEBIND, 1)
    s.bind((ip, port))
    s.setblocking(False)
    return s


class Datagram(asyncio.DatagramProtocol):
    def __init__(self, handler):
        self.handler = handler
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.handler(data, addr, self.transport)


# ---- location: HTTP server (+ authoritative DNS) ---------------------------

class Location:
    def __init__(self, args, header):
        self.args, self.header = args, header
        self.serving = defaultdict(set)          # site -> {ip}
        self.dns = DnsState()
        self.popmap = PopMap(header)
        auth = [e for e in header['endpoints'] if e['kind'] == 'authoritative_dns']
        self.auth = auth[0] if auth else None
        self.clock = None
        self.log = None

    def apply_content(self, e):
        (self.serving[e['site']].add if e['op'] == 'serve'
         else self.serving[e['site']].discard)(e['ip'])

    async def handle(self, reader, writer):
        local_ip = writer.get_extra_info('sockname')[0]
        peer = writer.get_extra_info('peername')
        status, site, rid = 0, None, None
        try:
            head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), REQUEST_TIMEOUT_S)
            lines = head.decode('latin-1').split('\r\n')
            parts = lines[0].split()
            headers = {}
            for l in lines[1:]:
                if ':' in l:
                    k, v = l.split(':', 1)
                    headers[k.strip().lower()] = v.strip()
            site = headers.get('host', '').split(':')[0].lower().rstrip('.')
            url = urlsplit(parts[1] if len(parts) > 1 else '/')
            rid = url.path.rsplit('/', 1)[-1]
            try:
                size = int(parse_qs(url.query).get('size', ['0'])[0])
            except ValueError:
                size = 0
            size = max(0, min(size, MAX_SIZE))
            if local_ip in self.serving.get(site, ()):
                status = 200
                first = (MARKER + site + '\n').encode()
                size = max(size, len(first))
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n'
                             b'Content-Length: %d\r\nConnection: close\r\n\r\n' % size + first)
                left = size - len(first)
                chunk = b'x' * 65536
                while left > 0:
                    n = min(left, len(chunk))
                    writer.write(chunk[:n])
                    left -= n
                    await writer.drain()
            else:
                status = 404
                body = b'lab2-not-served\n'
                writer.write(b'HTTP/1.1 404 Not Found\r\nContent-Length: %d\r\n'
                             b'Connection: close\r\n\r\n%s' % (len(body), body))
            await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError,
                ConnectionError, OSError) as ex:
            status = status or -1
            site = site or type(ex).__name__
        finally:
            self.log.write({'ev': 'http', 'ip': local_ip, 'peer': peer and peer[0],
                            'site': site, 'id': rid, 'status': status})
            try:
                writer.close()
            except Exception:
                pass

    def on_dns(self, data, addr, transport):
        try:
            q = dnswire.parse(data)
        except dnswire.DnsError:
            return
        if q['qr'] or not q['qname']:
            return
        pop = self.popmap.of(q['ecs'][0].split('/')[0]) if q['ecs'] else None
        a = self.dns.answer(q['qname'], pop) if q['qtype'] == dnswire.TYPE_A else None
        if a is None:
            rcode = dnswire.RCODE_NXDOMAIN if q['qname'] not in self.dns.records else 0
            resp = dnswire.encode_response(q, (), 0, rcode)
        else:
            resp = dnswire.encode_response(
                q, a.ips, a.ttl, ecs_scope=16 if q['ecs'] else None,
                view={'view': a.view, 'pops': sorted(a.pops), 'excluded': sorted(a.excluded)})
        transport.sendto(resp, addr)
        self.log.write({'ev': 'dns', 'peer': addr[0], 'qname': q['qname'], 'pop': pop,
                        'ips': list(a.ips) if a else None})

    # ---- endpoints (ext_resolver, encrypted_dns) ---------------------------
    def on_ext_query(self, res, ep):
        def handler(data, addr, transport):
            try:
                q = dnswire.parse(data)
            except dnswire.DnsError:
                return
            if not q['qr'] and q['qname']:
                asyncio.ensure_future(self.ext_answer(res, ep, q, addr, transport))
        return handler

    async def ext_answer(self, res, ep, q, addr, transport):
        if q['qtype'] != dnswire.TYPE_A:
            transport.sendto(dnswire.encode_response(q, (), 0, dnswire.RCODE_NOTIMP), addr)
            return
        ips, ttl, rcode, src = await res.resolve(q['qname'], self.clock.now())
        transport.sendto(dnswire.encode_response(q, ips, ttl, rcode), addr)
        self.log.write({'ev': 'ext_resolve', 'endpoint': ep['id'], 'peer': addr[0],
                        'qname': q['qname'], 'src': src, 'ips': list(ips) or None})

    def edns_handler(self, res, ep):
        async def handle(reader, writer):
            peer = writer.get_extra_info('peername')
            qname = None
            try:
                nonce = await asyncio.wait_for(reader.readexactly(dnswire.NONCE_BYTES),
                                               DNS_TIMEOUT_S * DNS_TRIES)
                n = int.from_bytes(await reader.readexactly(2), 'big')
                body = await reader.readexactly(n)
                q = dnswire.parse(dnswire.Opaque(nonce, b'C').apply(body))
                qname = q['qname']
                ips, ttl, rcode, src = await res.resolve(qname, self.clock.now())
                resp = dnswire.encode_response(q, ips, ttl, rcode)
                writer.write(dnswire.opaque_frame(dnswire.Opaque(nonce, b'S'), resp))
                await writer.drain()
                self.log.write({'ev': 'edns_resolve', 'endpoint': ep['id'],
                                'peer': peer and peer[0], 'qname': qname, 'src': src,
                                'ips': list(ips) or None})
            except (asyncio.IncompleteReadError, asyncio.TimeoutError, dnswire.DnsError,
                    ConnectionError, OSError):
                pass
            finally:
                writer.close()
        return handle

    async def start_endpoints(self, loop):
        auth = (self.auth['ip'], self.auth.get('port', DNS_PORT))
        for ep in self.header['endpoints']:
            if ep['kind'] not in ('ext_resolver', 'encrypted_dns'):
                continue
            _, up = await loop.create_datagram_endpoint(
                Upstream, sock=udp_socket(ep['ip'], 0, freebind=True))
            res = CachingResolver(up, auth, use_pop=False)
            if ep['kind'] == 'ext_resolver':
                await loop.create_datagram_endpoint(
                    lambda h=self.on_ext_query(res, ep): Datagram(h),
                    sock=udp_socket(ep['ip'], ep.get('port', DNS_PORT), freebind=True))
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.setsockopt(socket.SOL_IP, IP_FREEBIND, 1)
                s.bind((ep['ip'], ep['port']))
                s.listen(256)
                s.setblocking(False)
                await asyncio.start_server(self.edns_handler(res, ep), sock=s)

    async def run(self):
        loop = asyncio.get_running_loop()
        srv = await asyncio.start_server(self.handle, '0.0.0.0', HTTP_PORT,
                                         reuse_address=True, backlog=1024)
        if self.args.auth_dns and self.auth:
            sock = udp_socket(self.auth['ip'], self.auth.get('port', DNS_PORT), freebind=True)
            await loop.create_datagram_endpoint(lambda: Datagram(self.on_dns), sock=sock)
        if self.args.endpoints and self.auth:
            await self.start_endpoints(loop)
        sc = self.args.scenario
        streams = [(list(timeline.iter_events(sc, ['server_content'])), self.apply_content)]
        if self.args.auth_dns:
            streams.append((list(timeline.iter_events(sc, ['dns_record'])), self.dns.apply))
        # the t = 0 state is in place before bootstrap (simulator.md §1)
        for events, apply in streams:
            for e in events:
                if e['t'] <= 0:
                    apply(e)
        ready(self.args)
        clock = await wait_clock(self.args.run_dir)
        self.clock = clock
        self.log = Log(Path(self.args.run_dir) / 'agents' / ('%s.jsonl' % self.args.host),
                       clock)
        await asyncio.gather(*[play(clock, [e for e in events if e['t'] > 0], apply)
                               for events, apply in streams])
        async with srv:
            await srv.serve_forever()


# ---- internal resolver -------------------------------------------------------

class Upstream(asyncio.DatagramProtocol):
    """Queries to the authoritative DNS, matched by id."""

    def __init__(self):
        self.pending = {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            m = dnswire.parse(data)
        except dnswire.DnsError:
            return
        fut = self.pending.pop(m['id'], None)
        if fut is not None and not fut.done():
            fut.set_result(m)

    async def query(self, server, name, ecs):
        for _ in range(DNS_TRIES):
            qid = random.randrange(65536)
            while qid in self.pending:
                qid = random.randrange(65536)
            fut = asyncio.get_running_loop().create_future()
            self.pending[qid] = fut
            self.transport.sendto(dnswire.encode_query(qid, name, ecs), server)
            try:
                return await asyncio.wait_for(fut, UPSTREAM_TIMEOUT_S)
            except asyncio.TimeoutError:
                self.pending.pop(qid, None)
        return None


class CachingResolver:
    """dnsmodel.ResolverCache in front of the authoritative DNS (async upstream)."""

    def __init__(self, upstream, auth, use_pop, popmap=None):
        self.up, self.auth = upstream, auth
        self.cache = ResolverCache(use_pop=use_pop)
        self.popmap = popmap

    async def resolve(self, name, t, pop=None):
        """(ips tuple, ttl left, rcode, 'cache' | 'upstream')."""
        hit = self.cache.lookup(name, t, pop)
        if hit is not None:
            ans, expires = hit
            return ans.ips, expires - t, dnswire.RCODE_OK, 'cache'
        ecs = self.popmap.prefix.get(pop) if (self.cache.use_pop and self.popmap
                                               and pop) else None
        m = await self.up.query(self.auth, name, ecs)
        if m is None:
            return (), 0, dnswire.RCODE_SERVFAIL, 'upstream'
        if m['rcode'] != 0 or not m['answers']:
            return (), 0, m['rcode'] or dnswire.RCODE_NXDOMAIN, 'upstream'
        v = m['view'] or {'view': DEFAULT_VIEW, 'pops': [], 'excluded': []}
        ttl = min(x[1] for x in m['answers'])
        ans = Answer(tuple(ip for ip, _ in m['answers']), ttl, v.get('view', DEFAULT_VIEW),
                     frozenset(v.get('pops') or ()), frozenset(v.get('excluded') or ()))
        self.cache.store(name, t, ans)
        return ans.ips, ttl, dnswire.RCODE_OK, 'upstream'


class Resolver:
    def __init__(self, args, header):
        self.args, self.header = args, header
        self.popmap = PopMap(header)
        self.ip = header['resolver']['ip']
        auth = next(e for e in header['endpoints'] if e['kind'] == 'authoritative_dns')
        self.auth = (auth['ip'], auth.get('port', DNS_PORT))

    def on_query(self, data, addr, transport):
        try:
            q = dnswire.parse(data)
        except dnswire.DnsError:
            return
        if not q['qr'] and q['qname']:
            asyncio.ensure_future(self.answer(q, addr, transport))

    async def answer(self, q, addr, transport):
        t = self.clock.now()
        pop = self.popmap.of(addr[0])
        if q['qtype'] != dnswire.TYPE_A:
            transport.sendto(dnswire.encode_response(q, (), 0, dnswire.RCODE_NOTIMP), addr)
            return
        ips, ttl, rcode, src = await self.res.resolve(q['qname'], t, pop)
        transport.sendto(dnswire.encode_response(q, ips, ttl, rcode), addr)
        self.log.write({'ev': 'resolve', 'peer': addr[0], 'pop': pop, 'qname': q['qname'],
                        'src': src, 'ips': list(ips) or None, 'rcode': rcode})

    async def run(self):
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(lambda: Datagram(self.on_query),
                                            sock=udp_socket(self.ip, DNS_PORT))
        _, up = await loop.create_datagram_endpoint(Upstream, sock=udp_socket(self.ip, 0))
        self.res = CachingResolver(up, self.auth, use_pop=True, popmap=self.popmap)
        ready(self.args)
        self.clock = await wait_clock(self.args.run_dir)
        self.log = Log(Path(self.args.run_dir) / 'agents' / ('%s.jsonl' % self.args.host),
                       self.clock)
        while True:
            await asyncio.sleep(60)
            self.res.cache.expire(self.clock.now())


# ---- client ----------------------------------------------------------------------

class Client:
    def __init__(self, args, header):
        self.args, self.header = args, header
        self.resolver = (header['resolver']['ip'], DNS_PORT)
        self.ports = {e['ip']: e.get('port') for e in header['endpoints']}
        self.last = {}               # site -> last answer (stale_cache)

    async def edns(self, src_ip, endpoint, name):
        """Lookup through an encrypted-DNS endpoint: (ips, error)."""
        port = self.ports.get(endpoint) or 443
        nonce = os.urandom(dnswire.NONCE_BYTES)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(endpoint, port, local_addr=(src_ip, 0)),
                CONNECT_TIMEOUT_S)
        except asyncio.TimeoutError:
            return None, 'timeout'
        except OSError:
            return None, 'reset'
        try:
            q = dnswire.encode_query(random.randrange(65536), name)
            writer.write(nonce + dnswire.opaque_frame(dnswire.Opaque(nonce, b'C'), q))
            await writer.drain()
            n = int.from_bytes(await asyncio.wait_for(reader.readexactly(2),
                                                      DNS_TIMEOUT_S * DNS_TRIES), 'big')
            body = await asyncio.wait_for(reader.readexactly(n), DNS_TIMEOUT_S * DNS_TRIES)
            m = dnswire.parse(dnswire.Opaque(nonce, b'S').apply(body))
        except asyncio.TimeoutError:
            return None, 'timeout'
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            return None, 'reset'
        except dnswire.DnsError:
            return None, 'malformed'
        finally:
            writer.close()
        if m['rcode'] != 0 or not m['answers']:
            return None, 'rcode%d' % m['rcode']
        return [ip for ip, _ in m['answers']], None

    async def dns(self, src_ip, name, server=None):
        """(ips, error): error is None, 'timeout', or 'rcode<N>'."""
        loop = asyncio.get_running_loop()
        fut = loop.create_future()

        class P(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                if not fut.done():
                    fut.set_result(data)
        tr, _ = await loop.create_datagram_endpoint(P, local_addr=(src_ip, 0),
                                                    remote_addr=server or self.resolver)
        try:
            for _ in range(DNS_TRIES):
                qid = random.randrange(65536)
                tr.sendto(dnswire.encode_query(qid, name))
                try:
                    data = await asyncio.wait_for(asyncio.shield(fut), DNS_TIMEOUT_S)
                except asyncio.TimeoutError:
                    continue
                try:
                    m = dnswire.parse(data)
                except dnswire.DnsError:
                    return None, 'malformed'
                if m['rcode'] != 0 or not m['answers']:
                    return None, 'rcode%d' % m['rcode']
                return [ip for ip, _ in m['answers']], None
            return None, 'timeout'
        finally:
            tr.close()

    async def http(self, e, ip, rec):
        site, src = e['site'], e['src_ip']
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, HTTP_PORT, local_addr=(src, 0)), CONNECT_TIMEOUT_S)
        try:
            sock = writer.get_extra_info('socket')
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            line = 'GET /r/%s?size=%d HTTP/1.1\r\n' % (e['id'], e.get('size', 0))
            host = 'Host: %s\r\n' % site
            cookie = 'Cookie: s=%s\r\n' % ('x' * COOKIE_BYTES) if e.get('large_header') else ''
            rest = 'User-Agent: lab2-client\r\nAccept: */*\r\nConnection: close\r\n'
            if e.get('split_host'):
                writer.write((line + rest).encode())
                await writer.drain()
                await asyncio.sleep(SPLIT_GAP_S)
                writer.write((host + cookie + '\r\n').encode())
            else:
                writer.write((line + host + cookie + rest + '\r\n').encode())
            await writer.drain()
            head = await reader.readuntil(b'\r\n\r\n')
            lines = head.decode('latin-1').split('\r\n')
            status = int(lines[0].split()[1])
            length = None
            for l in lines[1:]:
                if l.lower().startswith('content-length:'):
                    length = int(l.split(':', 1)[1])
            first = await reader.readline()
            got = len(first)
            while length is None or got < length:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                got += len(chunk)
            rec['http_status'] = status
            rec['bytes'] = got
            rec['content_ok'] = (status == 200 and
                                 first.decode('latin-1').rstrip('\n') == MARKER + site)
            if rec['content_ok']:
                return 'ok'
            return 'wrong_content' if status == 200 else 'http_status'
        finally:
            writer.close()

    async def one(self, e):
        rec = {'id': e['id'], 't_sched': e['t'], 't_start': round(self.clock.now(), 3),
               'client': e['client'], 'src_ip': e['src_ip'], 'site': e['site']}
        method = e['method']
        if e.get('fallback_from'):
            rec['fallback_from'] = e['fallback_from']
        try:
            ip = None
            if method == 'stale_cache':
                ip = self.last.get(e['site'])
                if ip is None:            # our own cache is empty (e.g. an earlier failure)
                    method, rec['fallback_from'] = 'dns', 'stale_cache'
            if method == 'direct_ip':
                ip = e.get('expect_ip')
            elif method in ('dns', 'ext_resolver', 'encrypted_dns'):
                if method == 'dns':
                    ips, err = await self.dns(e['src_ip'], e['site'])
                elif method == 'ext_resolver':
                    rec['endpoint'] = e['endpoint']
                    ips, err = await self.dns(e['src_ip'], e['site'],
                                              (e['endpoint'], self.ports.get(e['endpoint'])
                                               or DNS_PORT))
                else:
                    rec['endpoint'] = e['endpoint']
                    ips, err = await self.edns(e['src_ip'], e['endpoint'], e['site'])
                if err:
                    rec.update(method=method, result='dns_fail', dns_error=err)
                    return
                ip = ips[0]
                self.last[e['site']] = ip
            rec['method'] = method
            rec['resolved_ip'] = ip
            if ip is None:
                rec['result'] = 'dns_fail'
                rec['dns_error'] = 'no_address'
                return
            rec['result'] = await asyncio.wait_for(self.http(e, ip, rec), REQUEST_TIMEOUT_S)
        except asyncio.TimeoutError:
            rec['result'] = 'timeout'
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError,
                asyncio.IncompleteReadError):
            rec['result'] = 'reset'
        except (OSError, ValueError, IndexError, KeyError, TypeError) as ex:
            # a malformed request (e.g. no endpoint) fails alone, not the agent
            rec['result'] = 'error'
            rec['error'] = '%s: %s' % (type(ex).__name__, ex)
        finally:
            rec.setdefault('method', method)
            rec['t_end'] = round(self.clock.now(), 3)
            self.log.write(rec)

    async def run(self):
        reqs = [e for e in timeline.iter_events(self.args.scenario, ['request'])
                if e['client'] == self.args.host]
        ready(self.args)
        self.clock = await wait_clock(self.args.run_dir)
        self.log = Log(Path(self.args.run_dir) / 'requests' / ('%s.jsonl' % self.args.host))
        tasks = []
        for e in reqs:
            await self.clock.until(e['t'])
            tasks.append(asyncio.ensure_future(self.one(e)))
        if tasks:
            await asyncio.gather(*tasks)
        (Path(self.args.run_dir) / 'agents' / ('%s.done' % self.args.host)).write_text(
            str(len(tasks)))


ROLES = {'location': Location, 'resolver': Resolver, 'client': Client}


def main(argv=None):
    ap = argparse.ArgumentParser(prog='python -m kit.sim.agent')
    ap.add_argument('role', choices=sorted(ROLES))
    ap.add_argument('--host', required=True)
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--run-dir', required=True)
    ap.add_argument('--auth-dns', action='store_true')
    ap.add_argument('--endpoints', action='store_true')
    args = ap.parse_args(argv)
    header = timeline.read_header(args.scenario)
    agent = ROLES[args.role](args, header)
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    sys.exit(main())
