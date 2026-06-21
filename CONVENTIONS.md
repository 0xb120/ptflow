# CONVENTIONS — pipt output & workspace contract

Inherits the toolkit contract (see /opt/custom-tools/CONVENTIONS.md). Files on disk
are the only state — there is no database. Rules for every new pipeline:

1. **Paths are a contract.** Only via `Activity` / `AppWorkspace`. No path literals.
2. **`raw/` holds raw tool dumps; nothing downstream reads `raw/`.** Each tool writes
   `raw/<tool>/`, then a normalize step promotes the result to a **fixed canonical
   filename** (e.g. `scope/scope_dns.txt`, `scans/asset_discovery/hosts.jsonl`,
   `scans/<app_hash>/services.jsonl`) that downstream stages read by name.
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
- [ ] Tools write `raw/<tool>/`, then promote to a fixed canonical filename.
- [ ] Stages declared with the right `Mode`; `cluster()` creates the app groups.
- [ ] A `HypothesisProvider` is returned by `provider()`.
- [ ] Registered in `load_pipeline`.
- [ ] Network tasks tagged `net`.
