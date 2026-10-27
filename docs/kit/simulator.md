# The scenario simulator

The simulator drives everything that happens in a run except your controller:
client requests, servers and DNS, routing changes inside and outside the
ISP, and the government's blocklist orders. It also produces the ground truth
your results are compared against.

## 1. How a run is made

1. **Scenario config** (YAML, `simulator:` section of the run config): the
   knobs in §7, as random processes or scripted events.
2. **Generator** (offline), in two steps:
   - `python -m kit.sim.write -c <config> -o scenario.hl.yaml` runs the
     config's random processes and writes down every outcome: a
     **high-level scenario** (§8) with an explicit world, a demand model,
     and events at fixed times. `--seed N` and `--duration S` override the
     config.
   - `python -m kit.sim.compile scenario.hl.yaml -o scenario.jsonl`
     compiles it into a **timeline** of low-level events (§3), sampling the
     requests from the demand model. It checks the result (§8.5): errors
     stop it, warnings are printed. Both go to `scenario.check.json`.
     `--seed N` overrides the file's request-sampling seed.
   - `python -m kit.sim.generate -c <config> -o scenario.jsonl` does both
     at once.
   - The same config and seed always give the same HL file, and the same HL
     file and seed the same timeline.
   - You can edit an HL file, or write one by hand, before compiling it.
3. **Run** (`kit.run`): the kit plays the timeline once in the Mininet
   network, on a shared clock, with your controller. Scenario time `t = 0` is
   the start of playback.

       sudo .venv/bin/python -m kit.run -c configs/default.yaml \
           --scenario scenario.hl.yaml --app controller/app.py

   - `-c` / `--config` selects the run config (default:
     `configs/default.yaml`).
   - `--scenario` takes an HL file (`.hl.yaml`), which is compiled first as
     in step 2, or an already compiled `scenario.jsonl`, which is played as
     is. A scenario that does not compile stops the run; the report is in
     the run directory. With an HL file, `--seed N` overrides its
     request-sampling seed.
   - `--controller kit` (the default) starts the kit controller with your
     app(s), as your user rather than root. `--app` accepts a Python file
     or module and can be repeated. Without it, the kit uses `controller.app`
     in the config, or runs only kit apps if that is unset.
   - Then it starts the network with the scenario's prefixes and the
     simulator behind every edge port.
   - **Bootstrap**, before the clock starts: the network is taken to have
     been running already, so your rules for the orders in force at t = 0
     should be in place at t = 0.
     - The kit applies the t = 0 state (prefixes, DNS records, content) and
       delivers the t = 0 events to your controller: the initial
       `EventBlocklistOrder` (`get_blocklist()` shows it), then
       `EventBootstrap`.
     - Your app installs its rules and calls
       `kit.controller.notify_app.ready()`. If it does not,
       bootstrap ends after `controller.bootstrap_timeout_s` (default
       60 s). Which one ended it is logged.
     - During bootstrap there is no traffic and U is not enforced; K and
       the rest are (`openflow-surface.md`). You learn nothing about later
       events.
     - Bootstrap time is not part of `duration_s`. Its flow-mod count is
       logged (`bootstrap_end` in `kit_events.jsonl`).
   - Then the scenario clock starts at t = 0, with U enforced from a full
     bucket, and the rest of the timeline plays.
   - When playback ends it stops the network, agents and any controller it
     started, then writes the outcomes (step 4). Files go to
     `<logging.out_dir>/<run_id>/` (default: `runs/<run_id>/`, §5).
     `--run-id` names the run; the default is a timestamp. An existing run
     directory is refused.
   - The scenario's topology must be the one in the config.
   - `--controller external`: start the controller yourself, e.g. under a
     debugger. The command prints the exact line to run, with the
     environment it needs, and waits for the controller.
   - Without `--scenario`, step 2 runs first from the config's `simulator:`
     section; `--seed N` and `--duration S` override the config. A compiled
     `scenario.jsonl` takes neither, and an HL file takes no `--duration`.
   - Only one run at a time, and no other controller on the controller
     port. The run refuses to start if something already listens there.
   - At start the kit runs Mininet's cleanup, which deletes `/tmp/*.log`
     and `/tmp/*.out`. Keep your own files elsewhere.
4. **Ground truth** (offline): the run writes `runs/<run_id>/outcomes.jsonl`
   itself. To redo it, e.g. after re-reading logs:
   `python -m kit.sim.truth runs/<run_id>/scenario.jsonl --requests
   runs/<run_id>/requests -o outcomes.jsonl`. It labels every request (§5).

Rule: your controller must not read the timeline, the generator's output or
the run's logs while the run is going on. It learns about the world only
from kit events (`openflow-surface.md`, "Kit events and lookups") and from
traffic. Before and after a run you may read anything.

## 2. The world

### Address plan

| What | Addresses | Where |
|---|---|---|
| internal resolver | 10.0.0.53 | `DNS` |
| PoP i: subscribers and the sites it serves | 10.i.0.0/16 | `S<i>` |
| caches | 100.64.1.0/24, 100.64.2.0/24 | `C1`, `C2` |
| external | 198.18.k.0/24, k = 0 … M-1 | behind exits `E1`, `E2`, `E3` |

- An **edge port** is a switch port that leads out of the network: `E1`–`E3`
  (exits), `C1`, `C2` (caches), `DNS`, and one `S<i>` per PoP. Every
  address lies behind exactly one edge port.
- Each prefix is a destination in the kit routing table (200). The edge
  port it lies behind answers for every address in it.
- A PoP is named after its switch (`P3`). It has one edge port (`S3`) and
  one address block. Its subscribers send every request from an address in
  the block (`src_ip`), and the sites the PoP serves use other addresses in
  the same block. Nothing in an address tells the two apart.
- A request from a PoP's subscriber to a site served at the same PoP still
  goes through that PoP's switch: in through `S3` and back out the same
  port.
- The timeline header lists every prefix with its edge port at `t = 0`, the
  PoPs, and the endpoints.
- Location comes only from the prefix: an address is wherever its prefix is
  routed. External prefixes change exits through BGP moves. Every other
  prefix stays where it is for the whole run.

### Sites, DNS and content

- A **site** is a name, the `Host` a server sees. Sites belong to orgs
  (registrable domains such as `portal1.example`). An org has 1–4 site
  names: `www.<org>`, other labels, sometimes the org name itself.
- Some orgs are **targeted**: their content is what orders go after. The
  controller is never told which; it only sees orders.
- Each site is served:
  - externally (an address in an external prefix);
  - from the caches: one address per cache, plus an external origin;
  - domestically (an address in a PoP's block).
- Two separate pieces of state decide whether a request works:
  - `dns_record`: name → addresses, a TTL, and optional per-PoP views.
    One authoritative DNS (in the first external prefix) serves all names.
  - `server_content`: which sites each server address serves. One address
    can serve many sites (shared IPs).

  They are changed by separate events, so they can disagree for a while:
  - an old address keeps serving after DNS moved;
  - a mirror is served before its name is in DNS;
  - a direct-IP request goes to an address DNS no longer gives;
  - a record is still cached after the server stopped serving.
- **Per-PoP views** (sites served from the caches): the record gives each PoP the
  address of the cache nearest to it (shortest path), and everyone else the
  default address.
- **Internal resolver**: a cache in front of the authoritative DNS.
  - It sends the client's PoP upstream (EDNS Client Subnet) and caches each
    answer per (name, view) for its TTL.
  - Within a TTL it keeps giving the old answer, even if the record changed.
  - A missing name is asked again every time; there is no negative caching.
- **External resolvers** (plain DNS over UDP, port 53) and **encrypted
  DNS** endpoints (TCP, port 443; §3) live at addresses in external
  prefixes. They always get the default view. Each has one cache per exit
  its prefix is reached at: after a BGP move the endpoint answers from
  an empty cache, and after a move back from the old one. Caches are never
  flushed.
- Clients have no DNS cache of their own except the `stale_cache` method
  (§3).

### What the controller is told

| Notified (kit event) | Silent (observe it or not at all) |
|---|---|
| BGP exit change (`EventRoutingChanged`, cause `bgp`) | DNS record changes |
| link down / up (`EventRoutingChanged`) | server content changes, mirrors, shared IPs |
| TE re-optimization: notice ahead, then the change (`EventTENotice`, `EventRoutingChanged`, cause `te`) | client requests and how they resolve |
| blocklist orders (`EventBlocklistOrder`, `get_blocklist()`) | domestic sites starting or stopping |

## 3. The timeline (`scenario.jsonl`)

One JSON object per line. Line 1 is the header. The rest are events sorted
by `(t, seq)`. Events at the same `t` keep the generator's order. `origin`,
on generated events, names the process or scripted item that made the
event; playback ignores it.

Header: `format`, `seed`, `duration_s`, `topology`, `config_sha256`,
`generator`, `pops` (`pop`, `client`, `prefix`), `resolver` (`host`, `ip`),
`prefixes` (`cidr`, `host`, `kind`: clients | cache | external). In the
header, `host` and `client` name an edge port (`S3`, `E1`, `DNS`, …).
`endpoints` (`id`, `kind`: authoritative_dns | ext_resolver | encrypted_dns,
`ip`, `port`).

| `ev` | Fields | Effect |
|---|---|---|
| `route_change` | `prefix`, `to` | the prefix moves to exit `to` |
| `te_notice` | `te_id`, `apply_at` | announces a TE change |
| `te_reoptimize` | `te_id`, `weights` {"B1-B2": w, …} | routing recomputed with these link weights |
| `link_down`, `link_up` | `link` ("B3-B9") | link fails / recovers, routing recomputed |
| `dns_record` | `op` set / remove, `domain`, `ips`, `ttl`, `views` [{`view`, `pops`, `ips`}] | authoritative answer changes |
| `server_content` | `op` serve / unserve, `site`, `ip` | the address starts / stops serving the site |
| `blocklist_order` | `order_id`, `add`, `remove` (lists of entries, §4) | the blocklist changes |
| `request` | below | a client request |

The initial state (records, content, the first order) is a set of events at
`t = 0`.

### Requests

Fields: `id`, `client`, `src_ip`, `site`, `method`, `size` (response
body, bytes), `split_host`, `large_header`, `expect_ip`, and for some
methods `endpoint` or `fallback_from`.

| `method` | What the client does |
|---|---|
| `dns` | asks the internal resolver, then fetches from the first address |
| `stale_cache` | reuses the last address it got for the site, past its TTL, with no DNS query. With no earlier answer it does `dns` instead and logs `fallback_from: "stale_cache"`. |
| `direct_ip` | fetches from `expect_ip` with `Host` = site, no DNS |
| `ext_resolver` | asks the external resolver at `endpoint` (UDP 53), then fetches |
| `encrypted_dns` | resolves through the encrypted endpoint at `endpoint` over TCP port 443, then fetches. The lookup is encrypted: a switch sees only the endpoint's address and port |

- Every fetch is HTTP/1.1 in clear text to port 80:
  `GET /r/<id>?size=<n>` with a `Host` header.
- `split_host`: the request header is sent in two TCP segments, with `Host`
  in the second.
- `large_header`: `Host` comes first, followed by a long `Cookie`, so the
  header spans several segments and `Host` is not in the last one (the
  one with PSH).
- `expect_ip`: the address an undisturbed resolution gives at that moment,
  per the generator's DNS model (for `direct_ip`, the address used).

## 4. Ground truth

A request **should be blocked** if, with the blocklist in force at its `t`
(an order at the same `t` counts, no grace period), any of these holds:

- its site name matches a `domain` or `suffix` entry;
- an address it contacts matches an `ip` entry. The contacted addresses are
  `expect_ip`, plus the `endpoint` for `ext_resolver` and `encrypted_dns`;
- it used a listed endpoint.

It is **servable** if `expect_ip` serves the site at `t` (`server_content`).

`ip` entries are judged by the address an undisturbed resolution gives
(`expect_ip`), not by the address the client reached (`resolved_ip`, §5).
The reference is the same however a controller handles DNS.

Entries:

| `type` | Fields | Matches |
|---|---|---|
| `domain` | `value` | the site name, exactly |
| `suffix` | `value` (no leading dot) | the name itself or any name ending in `"." + value`: `example.com` matches `example.com` and `a.example.com`, not `badexample.com` |
| `ip` | `value`: address or CIDR | a contacted address inside it |
| `endpoint` | `kind`, `ip`, optional `port` | a request through an endpoint at that address, and at that port if the entry gives one. `kind` is required but is not compared |

- Names are compared in lower case, without a trailing dot.
- Entries are identified by (type, value). Endpoint entries are identified
  by (ip, port), so `kind` (and an optional `id`) are not part of the
  identity, and an entry without `port` is a different entry from one with
  a port. Removing an entry that is not in force does nothing.

What the generator guarantees. The compiler checks the same rules on
every HL file, hand-written ones included (§8.5); the rule is in brackets.

- An `ip` entry never lists an address that serves an allowed (untargeted)
  site, and no allowed site is ever moved onto such an address later. A
  shared address therefore only ever appears in orders as names (error E7).
- Sites the caches serve are listed by name, never by address. Endpoints are
  listed only by `endpoint` entries, never covered by an `ip` entry (W6).
- When content moves (a DNS change, a move to a domestic address, an allowed
  site joining a shared address), the old address keeps serving for the
  record's TTL + 5 s. Fast-flux sites keep the old address for `overlap_s`
  (W3).
- Orders may include entries that no traffic ever matches. They look like
  the other entries, and nothing later in the run makes them match.
- A site that stops serving gets no more requests (W5).
- No request comes less than 50 ms after a change it depends on: a record
  or serving change for its site or one of its addresses, an order, a BGP
  move of its address's prefix (W12). The `t = 0` state is in place before
  the clock starts (bootstrap, §1), so it does not count, and requests come
  strictly after `t = 0`.

## 5. Logs and outcomes

Under `<logging.out_dir>/<run_id>/` (default: `runs/<run_id>/`):

| File | Contents |
|---|---|
| `scenario.hl.yaml` | the HL scenario (§8): a copy of `--scenario`, or written from the config when it is omitted; absent when `--scenario` is a `.jsonl` |
| `scenario.jsonl` | the timeline played: compiled from `scenario.hl.yaml`, or a copy of a `.jsonl` `--scenario` |
| `scenario.check.json` | the compile report (§8.5, format `lab2-check/1`); absent when `--scenario` is a `.jsonl` |
| `config.yaml` | the run config (a copy) |
| `kit.json` | `kit_commit`: the kit commit you ran, marked `-dirty` if files outside `controller/` were changed; `controller_dirty`: whether `controller/` differs from that commit |
| `controller.log` | the controller's output (kit apps and yours), with `--controller kit`; with `external`, capture its output yourself |
| `agents/<name>.<role>.out` | each simulator agent's output, per edge port (`S<i>` runs a `client` and a `location` agent) |
| `clock.json` | shared playback start time (`t0`, wall seconds) |
| `requests/<client>.jsonl` | one line per request: `id`, `t_sched`, `t_start`, `t_end`, `client`, `src_ip`, `site`, `method`, `fallback_from`, `endpoint`, `resolved_ip`, `http_status`, `bytes`, `content_ok`, `result`, and `dns_error` or `error` when they apply |
| `outcomes.jsonl` | from `kit.sim.truth`: the request, its client log fields, `should_block`, `reason` (the matching entry), `servable`, `ip_mismatch`, `outcome` |
| `budgets.jsonl` | when `logging.streams.budgets` is enabled, every `logging.sample_interval_s`: `interval_s`, `k_used` per switch, `k_limit`, `pin_rx`, `pin_delivered`, `pin_dropped`, `pin_queue`, `u_used`, `bootstrap` (sample taken during bootstrap), `rejected` by kind, `packet_out`, `stats_req`, `bumps`, `restores`, `team_events_dropped` |
| `kit_events.jsonl` | kit events: `start`, `switch_connect` / `switch_disconnect`, `reject`, `ofp_error`, `priority_bump`, `default_miss_restored`, `team_event_dropped`, `notify` (each event delivered to the controller), `bootstrap_start`, `ready` / `ready_ignored`, `bootstrap_end` (`ended_by` ready / timeout / no_team_app, `bootstrap_s`, `wait_s`, `team_flow_mods`, `u_cost`, `k_used_total`, `k_used_max`) |
| `orchestrator.jsonl` | each routing / order event played: `t`, `lag_ms`, `ms`, `ok`, `bootstrap` (played before the clock: `lag_ms` is null); plus one `bootstrap` line with the controller's summary |

`result`:

| Value | Meaning |
|---|---|
| `ok` | HTTP 200, and the body starts with `lab2-content <the requested site>` (`content_ok`) |
| `wrong_content` | HTTP 200 without that marker line (another site's content, a block page) |
| `http_status` | any other HTTP status (`http_status` has it) |
| `reset` | connection refused or reset |
| `timeout` | no complete answer within 3 s (connect) / 10 s (request) |
| `dns_fail` | no address (`dns_error`: `timeout`, `rcode3` = NXDOMAIN, …) |
| `error` | anything else (`error` has it) |

`outcome` (from `kit.sim.truth`). "Obtained" means `result` is `ok`.

| Value | When |
|---|---|
| `failed_to_block` | should be blocked, and the content was obtained |
| `blocked` | should be blocked, not obtained |
| `failed_to_serve` | allowed, and the content was not obtained, for any reason: blocking, a routing change during the request, congestion, a timeout, nothing serving the address |
| `served` | allowed, obtained |
| `missing` | no client log line |

There are only these two failure kinds. The raw `result` (and
`http_status`, `dns_error`, `error`), `servable`, and the timeline stay in
`outcomes.jsonl`. They can be used to work out why a request failed.

A connection that is open while its prefix's route changes can be reset, even
with no team app: the rest of its packets reach the new exit, which has no
state for it (`result` `reset`). The same happens in real BGP moves. It
happens to connections opened just after the change as well as to ones still
running from before it.

`ip_mismatch`: the client's `resolved_ip` differs from `expect_ip` (§4).

## 6. Random processes

- Every random process is Poisson with the given mean interval unless noted.
  `null` turns it off. TE (`te.interval_s`) and fast-flux rotation
  (`fast_flux.rotate_s`) are fixed periods instead.
- The same config and seed always give the same scenario.
- Changing one process's knobs, or turning it off, does not change the
  random draws of the others. Choices that depend on the world (which site,
  which address) can still change, because the world they see differs.
- Demand and flash crowds run per PoP.
- All of the above run in `kit.sim.write`, and their outcomes are written
  into the HL file. The compiler's only randomness is request sampling,
  seeded by the HL file's `seed`.

## 7. Scenario config

Under `simulator:` in the run config. All values below are the current
defaults. Unknown keys are errors. Mixes (`methods`, `hosting`,
`entry_mix`, `endpoints`) and maps (`exit_weights`, `pop_weights`) replace
the default as a whole; everything else merges key by key.

`preset:` names a YAML file (`presets/…`, below) of the same keys. The
order is: defaults, then the preset, then the keys you set under
`simulator:`. `configs/default.yaml` sets only `preset: null` and lists
the defaults as comments.

The default scenario is a busy but healthy network: 150 s, about 220
requests/s on isp_v2 (about 270–370 at the diurnal peak with a flash crowd),
and about 160–190 entries in force at the peak, a third of them addresses.
About 30 % of requests should be blocked (20–40 % depending on the seed).
Time constants are short to match the short run, TTLs included.

| Key | Default | Meaning |
|---|---|---|
| `duration_s` | 150 | run length (s), not counting bootstrap (§1) |
| `timeline` | null | a ready `scenario.jsonl` to play instead of generating |
| **world** | | |
| `external_prefixes` | 60 | M, number of external /24s (≤ 512) |
| `exit_weights` | E1 6, E2 3, E3 1 | share of external prefixes per exit at `t = 0`, and the weights BGP moves draw new exits from |
| `orgs` | 200 | registrable domains |
| `sites_per_org` | [1, 4] | site names per org (inclusive) |
| `targeted_orgs` | 0.25 | fraction of orgs whose content orders go after |
| `initially_listed` | 0.7 | fraction of targeted sites (or orgs, for suffix entries) the `t = 0` order lists |
| `initial_listing_bias` | 1.0 | 0: every targeted site has that chance. b > 0: a site's chance goes as popularity^-b, so the popular targets are left to later orders |
| `shared_ip` | 0.2 | fraction of targeted sites placed on an allowed site's address |
| `hosting` | external 0.7, cache 0.1, domestic 0.2 | hosting mix |
| `ttl_s` | normal 60, short 10 | record TTLs (short: fast-flux sites) |
| `endpoints` | ext_resolver 2, encrypted_dns 1 | number of each |
| `endpoints_initially_listed` | 0.5 | chance each endpoint is in the `t = 0` order |
| **demand** | | |
| `requests_per_s_per_pop` | 10.0 | base request rate per PoP |
| `pop_weights` | P1 2.0, P2 1.6, P3 1.6, P4 1.3, P5 1.3, P6 1.2, P17 0.5, P18 0.5, P19 0.4, P20 0.3 | rate multiplier per PoP (missing = 1; PoPs the topology lacks are ignored) |
| `subscribers_per_pop` | 200 | distinct `src_ip`s per PoP |
| `popularity` | zipf, s 1.0, targeted_share 0.50 | site popularity over a random ranking (`uniform` also allowed); mirrors share their original's popularity. `targeted_share`: the share of request weight on targeted content, with the distribution kept within each class (the HL file then gets `dist: weights`); null = one ranking over all. 0.50 makes about 30 % of requests should-block (fewer early in the run, more later, as the popular targets get listed), on purpose more than is realistic, so short windows after an order or route change get enough samples |
| `diurnal` | period 150, amplitude 0.25 | rate × (1 + amplitude · sin(2πt / period)) |
| `flash_crowd` | mean 1000, factor 5, duration 15, pop_weights null | per PoP; mean interval / that PoP's weight. One event multiplies that PoP's rate by `factor` for `duration_s`, all of the extra to one site |
| `size_bytes` | median 20000, sigma 1.0, max 2000000 | lognormal response size |
| `methods` | dns 0.87, stale_cache 0.05, direct_ip 0.03, ext_resolver 0.03, encrypted_dns 0.02 | access-method mix |
| `split_host` | 0.02 | fraction with `split_host` |
| `large_header` | 0.02 | fraction with `large_header` (request header beyond one MSS) |
| **external** | | |
| `bgp_change.mean_interval_s` | 15 | a random external prefix moves to another exit |
| `dns_change.mean_interval_s` | 7.5 | a site moves to a new address (same hosting kind) |
| `fast_flux` | sites 2, rotate_s 7.5, overlap_s 15 | targeted sites that rotate address every `rotate_s` (a fixed period; each site starts at a random point in it) |
| `mirror` | mean 22.5, dns_delay_s 2.5 | a new name (new org) with a targeted site's content, served at once, in DNS after `dns_delay_s` |
| `shared_ip_join.mean_interval_s` | 50 | an allowed site moves onto the address of a site blocked by name |
| **blocklist** | | |
| `add` | mean 11.25, entries {median 3, sigma 1.0, max 40}, filler 0.2, prefer_mirrors 0.6, popular_targets 0.5 | an order listing unlisted targets / endpoints (mirrors first with that chance). Each target is drawn with weight popularity ** `popular_targets` (0 or null: uniform), as real lists go after what people use; endpoints are drawn uniformly. Its size is `entries`: a `[min, max]` range or a lognormal `{median, sigma, max}`. When too few targets are unlisted, the order is smaller |
| `remove.mean_interval_s` | 75 | an order removing one entry in force |
| `entry_mix` | domain 0.45, suffix 0.1, ip 0.35, endpoint 0.1 | entry types in orders |
| **hosting_customers** | | |
| `start_blocked.mean_interval_s` | 75 | a targeted site moves to a domestic address (served at a PoP) |
| `stop.mean_interval_s` | 75 | a domestic targeted site stops serving (record removed) |
| **isp** | | |
| `te` | interval_s 30, notice_s 5 | TE at a fixed period of `interval_s` (first at `t = interval_s`), announced `notice_s` ahead (the notice is not shortened with the run). Link weights are 1 + round(4 × load / max load), with the demand model's expected load on the baseline paths (not measured traffic) |
| `failure` | mean null, duration_s 15 | Poisson with mean interval `mean`; one link at a time goes down for `duration_s`; never a link whose loss splits the network |

### Presets

Each changes one side of the default; measured on isp_v2 over 3 seeds.

| `preset:` | What it changes | Requests/s | Entries in force at the peak (addresses) |
|---|---|---|---|
| `presets/quiet.yaml` | 90 s at about 40 requests/s, a smaller world, no flash crowds, diurnal swing or fast flux: for debugging | 42 | 60–75 (20–26) |
| `presets/evasion.yaml` | more fast flux, mirrors, shared addresses and endpoints; about a quarter of requests bypass the internal resolver | 220 | 140–165 (45–52) |
| `presets/crackdown.yaml` | a large targeted world and large orders, half of them addresses | 220 | 430–505 (205–255) |
| `presets/surge.yaml` | 300 requests/s, frequent flash crowds, BGP moves every 7.5 s, TE every 15 s, link failures | 300 | as the default |

### Scripted events

`scripted:` is a list of `{t: …, ev: …, …}`:

- high-level kinds:
  - `flash_crowd` (`pop`, `site`, `factor`, `duration_s`; without `pop`, one
    is drawn by `flash_crowd.pop_weights`);
  - `bgp_change` (`prefix`, `to`);
  - `mirror`;
  - `order` (`entries`: an order of about that many entries, like `add`);
  - `block` (`sites` and/or `entries`);
  - `unblock` (`entries`);
  - `link_failure` (`link`, `duration_s`).
- any timeline event (§3), passed through as written. A `request` without
  `expect_ip` gets one; one without `id` gets one. The guarantees in §4 do
  not cover hand-written events.

## 8. High-level scenarios (`scenario.hl.yaml`)

`kit.sim.write` writes one of these from a config, and `kit.sim.compile`
turns one into a timeline (§1 step 2). It is the place to read, edit or
write a scenario by hand. `docs/kit/scenario.hl.example.yaml` is a complete
annotated example on `isp_v2` that compiles with no findings.

An HL file has three parts:

- **world**: explicit lists of what exists at `t = 0`;
- **demand**: a model, which the compiler samples individual requests from;
- **events**: high-level events at fixed times, plus raw timeline events.

Everything the writer drew at random (which site, which new address, which
exit, which entries) is written out. The compiler adds no randomness except
request sampling. Unknown keys are errors everywhere.

### 8.1 Top level

| Key | Meaning |
|---|---|
| `format` | `lab2-hl/1` |
| `seed` | request-sampling seed (the writer copies the config's seed) |
| `duration_s` | run length (s) |
| `topology` | `{name, metric, tie_break}`; the routing parameters feed TE weights |
| `provenance` | free-form, ignored by the compiler |
| `world`, `demand`, `events` | below |

The same file and seed give the same timeline. Requests depend on the world
they see, so editing a site or an event can change requests elsewhere.
Changing one PoP's demand does not change the requests sampled at the
others.

### 8.2 world

| Key | Contents |
|---|---|
| `external_prefixes` | `[{cidr, exit}]`: external /24s and their exit at `t = 0`. PoP and cache prefixes follow from the topology (§2) and are not listed |
| `cache_views` | `{cache: [PoPs]}` (cache edge port `C1`, `C2`): which PoPs each cache answers for every record of a site the caches serve. A PoP in no view gets the default answer |
| `endpoints` | `[{id, kind, ip, port}]`: `kind` is `authoritative_dns` (exactly one, listed first), `ext_resolver` or `encrypted_dns` |
| `orgs` | `[{org, targeted, sites: [site]}]` in creation order (the order matters for sampling). `targeted` marks content the government goes after; `targeted: false` is an *allowed* org |
| `blocklist` | entries of the `t = 0` order (§4) |

A site has `name`, `hosting` (`external`, `cache` or `domestic`), `ip` (its
default-view answer) and `ttl`. Optional:

- `cache_ips` `{cache: ip}`, for `hosting: cache`;
- `flux`, a marker for fast-flux sites;
- `content`, the content identity, shared by mirrors (default: the name);
- `serve`, the addresses serving it at `t = 0` (default: `ip` and the cache
  IPs);
- `dns` `{ips, ttl, views}` (views as in `dns_record`, §3). The default is
  built from `ip`, `cache_ips` and `cache_views`. `null` means the site is
  not published at `t = 0`.

`hosting` must agree with the address (§2): for `domestic`, an address in a
PoP's block that no subscriber uses (E4 names one that collides); for
`external`, an external prefix; for `cache`, an external origin with
`cache_ips` in each cache's own prefix. At `t = 0` the compiler emits serve
then record for each site in file order, then the initial order (`origin:
initial`).

Entry sugar, in `blocklist` and in orders: `{site: <name>, by: domain |
suffix | ip}` becomes the entry for that site's name, its org, or its current
address, resolved at the order's `t`.

### 8.3 demand

| Key | Meaning |
|---|---|
| `subscribers_per_pop` | distinct `src_ip`s per PoP |
| `rate_per_s` | `{PoP: requests/s}`. A PoP left out gets no requests (W9) |
| `diurnal` | `{period_s, amplitude}`, as in §7 |
| `popularity` | `dist: zipf` with `s` and a `ranking` of contents (rank 1 first), `dist: uniform` with a `ranking`, or `dist: weights` with `weights {content: w}` |
| `methods`, `size_bytes`, `split_host`, `large_header` | as in §7 |
| `segments` | time segments, below |

A segment is `{from_s, to_s, pops?, …}` and overrides the base model in
`[from_s, to_s)` for the PoPs listed (default: all). It can set
`rate_scale` or `rate_per_s` (a number or `{PoP: rate}`), `methods`,
`size_bytes` (key by key), `split_host` and `large_header`. Later segments
win, and the diurnal curve still applies on top.

### 8.4 events

Each item has `t`, `ev` and an optional `origin`. The `origin` is copied into
every timeline event the item produces (default `hl[<index>]`). Items are
played in order of `t`; ties keep file order.

| `ev` | Fields | Timeline events |
|---|---|---|
| `bgp_change` | `prefix`, `to` | `route_change` |
| `dns_change` | `site`, `ip`, `unserve_after_s?` | serve the new `ip` and set the record now; unserve the old address after `unserve_after_s` (default TTL + 5 s). `ip` must be fresh and of the site's hosting kind |
| `shared_ip_join` | `site`, `onto`, `unserve_after_s?` | the same, onto `onto`'s current address. `site` is allowed; `onto` is targeted and blocked by name. The site's hosting becomes `onto`'s |
| `start_blocked` | `site`, `ip`, `unserve_after_s?` | the same, to `ip` in a PoP's block (not a subscriber address); the site's hosting becomes `domestic` |
| `fast_flux` | `site`, `rotate_s`, `overlap_s`, `ips?` | a new address now and every `rotate_s`; each old one serves `overlap_s` longer. Without `ips` (one per rotation) the compiler picks fresh external addresses, independent of the seed |
| `mirror` | `of`, `name`, `org`, `ip`, `dns_delay_s?` | a new targeted site with `of`'s content and TTL: served now, in DNS after the delay |
| `add_site` | `org`, `targeted`, `site {…}`, `weight?`, `dns_delay_s?` | a new site (keys as in §8.2). `weight` is its content's popularity weight |
| `stop` | `site` | unserve every address, remove the record; no more requests |
| `blocklist_order` | `add?`, `remove?`, `order_id?` | `blocklist_order` (entries or sugar) |
| `flash_crowd` | `pop`, `site?`, `factor`, `duration_s` | extra requests at that PoP; without `site`, one is drawn by popularity |
| `te` | `notice_s`, `weights?` | `te_notice` at `t − notice_s`, `te_reoptimize` at `t`. Weights come from the demand model (§7) unless given |
| `link_failure` | `link`, `duration_s` | `link_down`, then `link_up` |

**Raw events.** `{t, raw: {…}}` holds one timeline event as in §3, passed
through and checked like the rest. A `request` gets `id` and `expect_ip`
filled in when they are missing, and an order gets an `order_id`.

Work due at the same `t` runs in this order: delayed parts of earlier items
(an unserve, a `link_up`, a delayed record, a TE application), then items in
file order, then TE notices, then fast-flux rotations, then requests.

### 8.5 Checks

The compiler checks the compiled timeline, so raw and edited items are
covered too. **Errors** stop compilation: the timeline would break the
ground-truth definition or a world rule, or cannot be played. **Warnings**
mark something legal but probably unintended. `scenario.check.json`
(`format: lab2-check/1`) has the counts per rule, up to 20 findings per
rule (each with `where`, `t`, `origin`, `msg`), and the load estimate.

| # | Error |
|---|---|
| E1 | schema: unknown key, wrong type, missing field, unknown `ev`, bad `format`, out-of-range number |
| E2 | unknown reference (PoP, client, exit, cache, link, site, endpoint, content), or a duplicate (site, org, endpoint, external CIDR, `order_id`, `te_id`, request `id`) |
| E3 | `t < 0`, or a TE notice before 0 |
| E4 | an address outside the plan (§2), or `hosting` that disagrees with the address |
| E5 | a route change of a prefix that is not external, or to an edge port that is not an exit |
| E6 | not exactly one `authoritative_dns` listed first, or a request through an undeclared endpoint |
| E7 | an `ip` entry in force covers an address that serves an allowed site or is in its record (§4) |
| E8 | a record view with an unknown PoP, or a PoP in two views of one record |
| E9 | a request the agents cannot play (§3): wrong client or `src_ip` (outside the PoP's block, or an address that serves a site), bad site name, method, endpoint, `size`, flags or `id` |
| E10 | pinned TE weights on unknown links, or not integers ≥ 1 |
| E11 | a malformed blocklist entry |
| E12 | a link failure that splits the network |

| # | Warning |
|---|---|
| W1 | an item, or part of one, after `duration_s` (dropped) |
| W2 | a record set to an address that does not serve the site at that moment |
| W3 | an old address unserved before cached answers for it expire |
| W4 | a freed address reused by an unrelated site |
| W5 | a raw request for an unknown, stopped or unpublished site |
| W6 | a name entry that covers an allowed site, or an `ip` entry that covers a cache or endpoint address |
| W7 | a removal of an entry that is not in force |
| W8 | a flash crowd with `factor ≤ 1`, overlapping TE notices, or a link brought up while up (down while down) |
| W9 | a PoP with no rate, an unranked content, a fast-flux `ips` list that runs out, an endpoint address that also serves a site |
| W10 | a move of a stopped site (it comes back) |
| W11 | estimated peak load above 400 requests/s network-wide |
| W12 | a request less than 50 ms after a change it depends on (§4), a request at `t = 0`, or `size` above 10 MB (it may not arrive within the client's 10 s request timeout on a shaped link; the server clamps at 50 MB) |

An entry that matches nothing is not a finding: orders may contain such
entries (§4).
