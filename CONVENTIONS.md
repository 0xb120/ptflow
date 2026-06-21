# CONVENTIONS — pipt output & workspace contract

Inherits the toolkit contract (see /opt/custom-tools/CONVENTIONS.md). Files on disk
are the only state — there is no database. Rules for every new pipeline:

1. **Paths are a contract.** Only via `Activity` / `AppWorkspace`. No path literals.
2. **Write each tool's output exactly once — never duplicate raw into canonical.**
   - **Intermediate** step (its output only feeds later steps, e.g. `mapcidr`,
     PTR/TLS harvest): persist to `raw/<tool>/<label>.txt` as provenance.
   - **Terminal artifact** step (its output *is* a final, downstream-read file,
     e.g. `httpx_full_metadata.jsonl`, `subdomains.txt`, `domain_ip_map.txt`):
     write it **straight to its fixed canonical name** — do NOT also keep a
     byte-identical copy under `raw/`.
   - **Derived artifact** (merge/dedup/filter of in-memory results, e.g.
     `unique_ips.txt`, `honeypots.txt`, `unique_webapps.txt`): compute in memory
     and write only the canonical file.

   Rationale: a canonical file that is a verbatim copy of a `raw/` file is pure
   duplication (this is the standard introduced after that bug). `raw/` exists
   only for tool output that gets transformed/merged before a consumer sees it;
   if there is no transformation, the canonical file IS the record. Downstream
   stages always read fixed canonical names; **nothing downstream reads `raw/`.**
3. **Phases.** `asset_discovery` (BREADTH) expands the scope and discovers assets
   over the whole scope at once; a `cluster` step groups them into application
   groups under `scans/<app_hash>/`; `enum` (DEPTH) fans out per group.
4. **Stable app id.** `scans/<app_hash>/` is keyed on a hash of the cluster identity
   (a fabricated signature in the stub; `Title+ContentLength+Webserver` in a real
   recon pipeline) — never on a mutable string.
5. **Declarative stages.** Each stage declares `Mode.BREADTH` or `Mode.DEPTH`.
6. **Agent output is global.** The terminal agent stage reads the per-group
   `services.jsonl` and writes consolidated `findings/hypotheses.jsonl`.

## Checklist for a new pipeline

- [ ] Reads/writes only via `Activity` / `AppWorkspace`.
- [ ] Each tool output written ONCE: intermediate → `raw/<tool>/`; terminal artifact →
      its canonical name directly (no verbatim raw↔canonical copy); derived → canonical only.
- [ ] Stages declared with the right `Mode`; `cluster()` creates the app groups.
- [ ] A `HypothesisProvider` is returned by `provider()`.
- [ ] Registered in `load_pipeline`.
- [ ] Network tasks tagged `net`.
