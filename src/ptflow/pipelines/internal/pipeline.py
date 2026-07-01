"""The internal-network Pipeline object (IP/CIDR scope → per-subnet low-hanging-fruit sweep)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from ptflow.core.agent import HypothesisProvider, StubProvider
from ptflow.core.stage import Stage
from ptflow.pipelines.internal import tasks

if TYPE_CHECKING:
    from ptflow.core.flowmap import MapSpec
    from ptflow.core.paths import Activity
    from ptflow.core.requirements import Requirement
    from ptflow.core.stage import Followup


class InternalPipeline:
    name = "internal"
    stages: Sequence[Stage] = (
        # BREADTH (whole-scope, one rate-controlled pass) — barrier before cluster
        Stage("expand", tasks.expand, net=False),           # mapcidr: CIDR → candidate IPs (offline transform)
        Stage("discover", tasks.discover, needs=("expand",)),   # nmap -sn: live hosts
        Stage("portscan", tasks.portscan, needs=("discover",)),  # naabu: open internal-service ports
        # LOOP 1 — service inventory (per-subnet)
        Stage("fingerprint", tasks.fingerprint, per_app=True, phase=1),
        # LOOP 2 — low-hanging fruit (per-subnet), gated on the loop-1 service inventory. All ∥ (no
        # cross-needs): cve_lookup is OFFLINE (net=False); the rest are best-effort network checks.
        Stage("cve_lookup", tasks.cve_lookup, per_app=True, phase=2, net=False),
        Stage("smb_checks", tasks.smb_checks, per_app=True, phase=2),
        Stage("snmp_checks", tasks.snmp_checks, per_app=True, phase=2),
        Stage("ldap_checks", tasks.ldap_checks, per_app=True, phase=2),
        Stage("nuclei_net", tasks.nuclei_net, per_app=True, phase=2),
    )

    def cluster(self, activity: Activity) -> list[str]:
        return tasks.cluster(activity)

    def consolidate(self, activity: Activity) -> dict[str, int]:
        """Deterministic terminal fan-in: lift per-subnet findings → <activity>/findings/<type>.jsonl."""
        return tasks.consolidate(activity)

    def followups(self, activity: Activity) -> list[Followup]:
        """Pipeline composition: hand the aggregated web services to the `webscan` pipeline (opt-in)."""
        return tasks.followups(activity)

    def preflight(self) -> None:
        """Log present/missing external tools at run start (best-effort, never aborts)."""
        tasks.preflight()

    def requirements(self) -> list[Requirement]:
        """Host requirement manifest (its own toolset) that `ptflow doctor` checks. Duck-typed hook."""
        return tasks.requirements()

    def flowmap_spec(self) -> MapSpec:
        """Flow-map metadata for the doc generator (duck-typed hook; see core/flowdocs.py). Lazy
        import keeps the doc-only prose off the normal run's import path."""
        from ptflow.pipelines.internal.flowmeta import SPEC  # noqa: PLC0415

        return SPEC

    def provider(self) -> HypothesisProvider:
        return StubProvider()


PIPELINE = InternalPipeline()
