# Design — Per-scope authorization gate (external breadth)

- **Date:** 2026-07-05
- **Status:** Approved (design); pending implementation plan
- **Scope:** external pipeline breadth (discovery → active scanning boundary). RoE enforcement.

## 1. Motivation

External discovery **harvests names it never verifies against the authorized scope**, then scans them.
`expand` (`tasks.py:1712`) pulls candidate names from three sources and writes them all to `scope_dns`
with **no apex/scope filter**: TLS-SAN via `tlsx -san -cn` (`:1736`), reverse DNS via `dnsx -ptr`
(`:1745`), and `subfinder`/`assetfinder` on wildcards (`:1749`). `resolve` (`:1764`) then resolves
everything to `subdomains.txt` and their A-records to `unique_ips.txt` / `domain_ip_map.txt` (`:1788`)
— again with **no filter**. So a TLS-SAN or PTR name belonging to a **third-party apex** (a shared cert,
a cloud provider's PTR), and any IP it resolves to, flows straight into the active stages
(`portscan`/`portscan_full`/`nuclei_scope`/`cluster`/loops). This is an RoE/legal problem, not cosmetic:
we scan infrastructure the engagement never authorized (observed live: Google `142.250.x`, AWS ALB `34.x`).

The **only** hygiene today is CDN-heuristic, not authorization-based: `naabu -exclude-cdn` (`:1806`,
`:1824`) skips CDN IPs in port scans, and `split_cdn_ip_records` at `httpx` (`:1855`) drops bare-IP
records flagged CDN/cloud/WAF while keeping hostnames and explicitly-in-scope IPs. A **non-CDN** third
party (an ALB not classified CDN, a third-party apex from a SAN) passes straight through. The missing
piece is an **authorization boundary** derived from the operator's scope file.

Two scenarios must both work:
- **Domain scope** (`acme.com`, `*.acme.com`, `192.0.2.0/24`): drop harvested names/IPs outside the
  authorized apexes/ranges.
- **IP-only scope** (client gives public IPs, no DNS — a common external PT): the operator must still
  **recover the domains living on those authorized IPs** (SAN/PTR/vhost) and attack them. A naive
  domain-only allowlist would be empty here and drop every recovered name — the opposite of what's needed.

## 2. Goals / Non-goals

**Goals:**
- A scope **allowlist** derived from the scope file, and a gate that keeps only authorized assets
  (names + IPs) at the discovery→active-scanning boundary, dropping third-party pull-in.
- Correct for both domain scope and IP-only scope (the IP→names recovery pivot).
- RoE-safe by construction and precision-first (when unauthorized, drop; never expand scope implicitly).
- Complements — does not replace — the existing CDN filters (`naabu -exclude-cdn`, `split_cdn_ip_records`).
- No new heavy dependency (the confirmed semantics need exact-match + suffix-match, **not** the Public
  Suffix List / `tldextract`).

**Non-goals (Roadmap):**
- Host-header/SNI pinning to scan a recovered name **against a specific authorized IP** when public DNS
  points the name elsewhere (v1 drops such names — see §3.1 rule/decision a).
- Auto-expanding a recovered host to its full apex (`www.acme.com` recovered from an IP does **not**
  authorize `*.acme.com` — decision b).
- A zero-traffic early `cdncheck` on `unique_ips.txt` (marginal: `naabu -exclude-cdn` already avoids
  port-scanning CDN IPs). Deferred.
- Full IPv6 discovery. The gate handles IPv6 membership via `ipaddress`; broadening the pipeline's IPv6
  discovery is separate.

## 3. Design

### 3.1 Scope semantics (confirmed with the operator)

An asset is **in scope** if ANY of these hold:
1. **name ∈ `exact_hosts`** — the exact normalized host of a `domain` or `url` scope entry. A bare
   domain is host-scope: `acme.com` authorizes `acme.com`, **not** `app.acme.com`.
2. **name matches a `wildcard_apex`** — from a `*.x` entry: `host == apex or host.endswith("." + apex)`,
   so `*.acme.com` authorizes `acme.com` **and every subdomain at any depth** (`a.b.acme.com`).
3. **IP ∈ a scope `net`** — from `ip` (as `/32`|`/128`) or `cidr` entries.
4. **the name's resolved IP ∈ a scope `net`** — the IP→names pivot: a SAN/PTR/vhost recovered from an
   authorized IP is in scope, because the operator authorized that IP. Makes the IP-only scenario work.

**domain → IP** (confirmed): a host matched by rule 1/2 has its resolved IP scanned (it enters the
authorized IP set), **except** CDN/cloud IPs — for a CDN-fronted domain the hostname is kept (scanned via
Host header) but the shared IP is not port-scanned. This CDN exclusion is **already delivered** by the
existing `naabu -exclude-cdn` + `split_cdn_ip_records`; the gate keeps domain-derived IPs in the set and
lets those tools drop the CDN ones. So the gate itself needs no CDN classification and stays offline.

**Confirmed decisions:**
- **(a)** A recovered name that public-DNS-resolves **off** the authorized IPs is **dropped** to the
  audit (v1: no Host-header pinning). A recovered name resolving **onto** an authorized IP is kept and
  scanned normally (the common, useful case: SAN `mail.acme.com` → the same in-scope IP).
- **(b)** Recovering a name does **not** auto-expand to its apex; the operator adds `*.apex` explicitly
  to widen.
- **Anti-transitivity:** rule 4 uses the **explicitly-listed** `nets` only. Domain-derived IPs (from the
  domain→IP behavior) are scanned but do **not** become a basis for authorizing further names — otherwise
  domain→IP→new-names→new-IPs would chain-expand scope.

No PSL: rule 1 is exact-match, rule 2 is suffix-match — both trivial and offline.

### 3.2 Pure helpers in `core/scope.py`

```python
@dataclass(frozen=True)
class Allowlist:
    exact_hosts: frozenset[str]        # domain + url entry hosts
    wildcard_apexes: frozenset[str]    # *.x → x
    nets: tuple[IPv4Network | IPv6Network, ...]  # ip (/32|/128) + cidr

def build_allowlist(targets: list[Target]) -> Allowlist: ...
def host_in_scope(host: str, allow: Allowlist) -> bool:   # rules 1,2
def ip_in_scope(ip: str, allow: Allowlist) -> bool:       # rule 3 (also used for rule 4)
def filter_assets(names_to_ips: dict[str, list[str]], scope_ips: list[str],
                  allow: Allowlist) -> ScopeVerdict: ...
```

`filter_assets` (pure, the heart of the gate) takes the resolved name→IPs map (from `domain_ip_map.txt`)
plus the raw resolved-IP list and returns a `ScopeVerdict` with: `kept_names`, `kept_ips`,
`dropped_names`, `dropped_ips` (each dropped record carries a reason for the RoE audit). Rules:
- a **name** is kept if `host_in_scope(name)` OR any of its resolved IPs satisfies `ip_in_scope` (rule 4);
- an **IP** is kept if `ip_in_scope(ip)` (rule 3, explicit) OR it is a resolved IP of a kept name
  (domain→IP; CDN exclusion left to the downstream tools).

`host` normalization: lower-case, strip a trailing dot, IDN→punycode (`str.encode("idna")`), so
comparisons are canonical.

### 3.3 The `scope_gate` stage

A new **activity-scope, offline (`net=False`)** stage that runs **after `resolve`, before `portscan`**.
It: reads `scope_init` → `build_allowlist`; reads `resolve`'s discovery outputs (`subdomains.txt`,
`tls_names.txt`, `unique_ips.txt`, `domain_ip_map.txt`); runs `filter_assets`; writes the **authorized**
asset set that the active stages consume, plus the RoE audit `excluded_out_of_scope.jsonl`
(`{asset, kind:name|ip, reason, resolved_ips?}` per dropped record).

**Write-once:** the gate is the **single writer** of the authorized asset files. To avoid two writers on
one path, the authorized set is written under distinct canonical names (`inscope_subdomains.txt`,
`inscope_names.txt`, `inscope_ips.txt`, `inscope_domain_ip_map.txt`), and the downstream active stages
are rewired to read those (the plan enumerates the exact read sites: `portscan`/`portscan_full` →
`inscope_ips`; `httpx_fingerprint` name inputs → `inscope_names`; `nuclei_scope` → the inscope name/webapp
set). `expand`/`resolve` keep writing their raw discovery outputs (they remain the discovery record and
are read by the gate); nothing downstream of the gate reads them directly. A logged summary reports how
many names/IPs were dropped (like the existing `excluded_cdn` log line).

**Degradation / empty allowlist safety:** an empty allowlist (a malformed/empty scope) drops everything
and logs a WARNING rather than silently scanning nothing or everything — the operator sees the misconfig.
A run with only IP scope keeps names via rule 4; a run with only domain scope keeps names via rules 1/2.

### 3.4 `classify`/`nets` — IPv6 + octet validation (targeted)

`core/scope.py`'s `classify` uses IPv4-only regexes (`_IP`/`_CIDR`) and carries a TODO that they don't
validate octet ranges. Since the gate parses IP/CIDR entries into `ipaddress` networks anyway, tighten
`classify` to recognize IP/CIDR via `ipaddress.ip_network(strict=False)` (accepting IPv6 and rejecting
`999.0.0.1`), closing the TODO and letting an IPv6 scope entry be treated as `ip`/`cidr` instead of
falling through to `domain`. Minimal, in-scope-of-the-work change; no behavior change for valid IPv4.

### 3.5 Placement in the DAG

`resolve` → **`scope_gate`** → `portscan` → `httpx` → `cluster` → loops; the spanning stages
(`portscan_full`, `nerva`, `nuclei_scope`) read the gated `inscope_*` set through their existing deps, so
they too only touch authorized assets. `scope_gate` `needs=("resolve",)`; `portscan` `needs=("scope_gate",)`.
Resolving a third-party name is a harmless DNS lookup (no attack traffic), so harvest-then-gate is safe —
the gate sits in front of the first **active** network stage.

## 4. Invariants / correctness

- **RoE:** only assets authorized by rules 1–4 survive; third-party names (SAN/PTR of an unlisted apex)
  and their IPs are dropped to the audit. No implicit scope expansion (decision b; anti-transitivity).
- **IP-only correctness:** rule 4 keeps SAN/PTR/vhost names on authorized IPs; decision (a) drops names
  that resolve off the authorized IPs.
- **Write-once:** `scope_gate` is the sole writer of the `inscope_*` authorized files + the audit; no
  path gets a second writer.
- **Complements existing CDN hygiene:** `naabu -exclude-cdn` and `split_cdn_ip_records` stay; the gate
  adds the authorization filter they lack. The gate stays offline (`net=False`).
- **Deterministic / --resume:** the filter is a pure function of scope + resolved assets; re-running
  recomputes the same authorized set (this is breadth asset filtering, not findings — no `--resume`
  deletion concern).

## 5. Edge cases

- **IP-only scope:** names recovered from in-scope IPs kept (rule 4); everything domain-based is empty.
- **CDN-fronted in-scope domain:** hostname kept (matches rule 1/2), shared CDN IP kept in the set but
  not port-scanned (existing `naabu -exclude-cdn`/`split_cdn_ip_records`).
- **Recovered name resolving off-scope:** dropped (decision a).
- **Explicit CDN IP in scope:** an IP the client explicitly listed is never CDN-excluded (rule 3 is
  authorization; CDN exclusion applies only to domain-derived IPs).
- **IPv6 scope entry:** classified as `ip`/`cidr`, membership via `ipaddress`.
- **IDN / trailing-dot / case:** normalized before comparison.
- **A name resolving to both an in-scope and an out-of-scope IP:** kept (rule 4 satisfied by the in-scope
  IP); scanned where DNS points — acceptable, the in-scope IP justifies it.
- **Empty/malformed scope:** drop-all + WARNING.

## 6. Testing

Pure/injectable, no network:
- `build_allowlist`: each entry kind → the right bucket (`domain`/`url`→exact_hosts, `*.x`→wildcard_apex,
  `ip`/`cidr`→nets incl. IPv6).
- `host_in_scope`: exact domain matches only itself (not its subdomains); `*.x` matches apex + multi-level
  subdomains; IDN/case/trailing-dot normalized; non-matching third-party name rejected.
- `ip_in_scope`: inside/outside a CIDR, IPv4 + IPv6, single-IP `/32`.
- `filter_assets`: (i) domain scope drops a third-party SAN name + its IP; (ii) **IP-only scope keeps a
  SAN/PTR name whose IP is in the scope CIDR** (rule 4) and drops one resolving off-scope (decision a);
  (iii) a domain's resolved IP is kept (domain→IP), a third-party IP is dropped; (iv) anti-transitivity: a
  name resolving only to a domain-derived (non-listed) IP is NOT kept; (v) empty allowlist → all dropped.
- `classify`: IPv6 IP/CIDR recognized; `999.0.0.1` not misclassified as `ip`.
- `scope_gate` stage: on-disk `scope_init` + fake `resolve` outputs → correct `inscope_*` files +
  `excluded_out_of_scope.jsonl`; downstream stages read the gated set (a small wiring assertion).

## 7. Roadmap (deferred)

- Host-header/SNI pinning: scan a recovered name against the authorized IP even when public DNS diverges
  (decision a's fuller form).
- Zero-traffic early `cdncheck` on `unique_ips.txt` (optimization over `naabu -exclude-cdn`).
- Opt-in apex auto-expansion for recovered hosts (decision b's inverse), if an engagement wants it.
- Broader IPv6 discovery across the pipeline.

## 8. Open questions

None — the four membership rules, the domain→IP CDN handling (delegated to existing tools), decisions (a)
and (b), anti-transitivity, and the no-PSL simplification are all resolved with the operator.
