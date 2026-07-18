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
    resume_epoch = 1
    stages: Sequence[Stage] = (
        # BREADTH (whole-scope, one rate-controlled pass) — barrier before cluster
        Stage("expand", tasks.expand, net=False),           # mapcidr: CIDR → candidate IPs (offline transform)
        Stage("discover", tasks.discover, needs=("expand",)),   # nmap -sn: live hosts
        Stage("portscan", tasks.portscan, needs=("discover",)),  # naabu: fast curated internal-port set
        # full 65535-port scan + whole-scope full-template nuclei — SPANNING chain (∥ cluster + all
        # per-subnet loops, joined at the fan-in): off the critical path, gentler on fragile legacy/OT
        # gear. nuclei scans the FULL-port surface (portscan_full), not just the fast curated set.
        Stage("portscan_full", tasks.portscan_full, needs=("portscan",), spanning=True),
        Stage("nuclei_scope", tasks.nuclei_scope, needs=("portscan_full",), spanning=True),
        # full-port DELTA fingerprint + known-CVE correlation — SPANNING too (∥ cluster + loops, joined
        # at the fan-in). services_full.jsonl gives banners for non-standard-port services; cve_lookup_full
        # is the whole-scope, OFFLINE CVE gemini of the per-subnet cve_lookup (activity-level, like nuclei_scope).
        Stage("fingerprint_full", tasks.fingerprint_full, needs=("portscan_full",), spanning=True),
        Stage("cve_lookup_full", tasks.cve_lookup_full, needs=("fingerprint_full",), spanning=True, net=False),
        # LOOP 1 — service inventory (per-subnet)
        Stage("fingerprint", tasks.fingerprint, per_app=True, phase=1),
        # LOOP 2 — low-hanging fruit (per-subnet), gated on the ports found in the breadth scan. All ∥
        # (no cross-needs), best-effort, NON-destructive: cve_lookup is OFFLINE (net=False); the rest are
        # anonymous/no-auth checks + RDP/VNC screenshots (credentialed/brute-force checks are future).
        Stage("cve_lookup", tasks.cve_lookup, per_app=True, phase=2, net=False),
        Stage("smb_checks", tasks.smb_checks, per_app=True, phase=2),
        Stage("ad_enum", tasks.ad_enum, per_app=True, phase=2),          # null-session AD enumeration
        Stage("adcs_checks", tasks.adcs_checks, per_app=True, phase=2),   # ADCS CA discovery + ESC8 (no-cred)
        # AS-REP roasting reuses ad_enum's user list → intra-loop `needs` (same phase; NOT a cross-loop dep)
        Stage("kerberoast_asrep", tasks.kerberoast_asrep, needs=("ad_enum",), per_app=True, phase=2),
        Stage("datastore_checks", tasks.datastore_checks, per_app=True, phase=2),  # unauth Redis/Mongo/Memcached + MSSQL
        Stage("snmp_checks", tasks.snmp_checks, per_app=True, phase=2),
        Stage("ldap_checks", tasks.ldap_checks, per_app=True, phase=2),
        Stage("ftp_checks", tasks.ftp_checks, per_app=True, phase=2),
        Stage("telnet_checks", tasks.telnet_checks, per_app=True, phase=2),
        Stage("nfs_checks", tasks.nfs_checks, per_app=True, phase=2),
        Stage("rsync_checks", tasks.rsync_checks, per_app=True, phase=2),
        Stage("netbios_checks", tasks.netbios_checks, per_app=True, phase=2),  # NetBIOS identity (137/UDP)
        Stage("dns_checks", tasks.dns_checks, per_app=True, phase=2),     # DNS AXFR (reverse-zone map)
        Stage("remote_desktop", tasks.remote_desktop, per_app=True, phase=2),
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
