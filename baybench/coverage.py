from __future__ import annotations

from typing import Sequence

from .models import Case, ToolResult

TIER1 = "tier1_pairs"


def coverage_report(cases: Sequence[Case], catalog: dict) -> dict:
    catalog_families = list(catalog["families"])
    catalog_rules = catalog["rules"]
    family_set = set(catalog_families)
    rule_set = set(catalog_rules)

    families = {
        fam: {"n_cases": 0, "n_malicious": 0, "n_benign": 0} for fam in catalog_families
    }
    rules = {
        rule_id: {"family": info["family"], "n_cases": 0}
        for rule_id, info in catalog_rules.items()
    }
    unknown_rule_ids: set[str] = set()
    unknown_families: set[str] = set()
    per_tier: dict[str, int] = {}
    tier1_pairs = {rule_id: {"malicious": 0, "benign": 0} for rule_id in catalog_rules}
    unknown_dirs: set[str] = set()

    for case in cases:
        per_tier[case.tier] = per_tier.get(case.tier, 0) + 1

        for fam in case.expected_families:
            if fam not in family_set:
                unknown_families.add(fam)
                continue
            families[fam]["n_cases"] += 1
            if case.is_malicious:
                families[fam]["n_malicious"] += 1
            elif case.is_benign:
                families[fam]["n_benign"] += 1

        for rule_id in case.expected_rule_ids:
            if rule_id not in rule_set:
                unknown_rule_ids.add(rule_id)
                continue
            rules[rule_id]["n_cases"] += 1

        if case.tier == TIER1:
            rule_dir = case.dir.parent.name
            leaf = case.dir.name
            if rule_dir.startswith("_"):
                continue
            if rule_dir not in rule_set:
                unknown_dirs.add(rule_dir)
                continue
            if leaf == "mal":
                tier1_pairs[rule_dir]["malicious"] += 1
            elif leaf == "ben":
                tier1_pairs[rule_dir]["benign"] += 1

    families_zero_cases = sorted(fam for fam, info in families.items() if info["n_cases"] == 0)
    rules_zero_cases = sorted(rule_id for rule_id, info in rules.items() if info["n_cases"] == 0)
    rules_missing_pair = sorted(
        rule_id
        for rule_id, counts in tier1_pairs.items()
        if counts["malicious"] == 0 or counts["benign"] == 0
    )

    return {
        "families": families,
        "rules": rules,
        "families_zero_cases": families_zero_cases,
        "rules_zero_cases": rules_zero_cases,
        "unknown_rule_ids": sorted(unknown_rule_ids),
        "unknown_families": sorted(unknown_families),
        "tier1_pairs": tier1_pairs,
        "tier1_unknown_rule_dirs": sorted(unknown_dirs),
        "rules_missing_pair": rules_missing_pair,
        "n_cases": len(cases),
        "per_tier": per_tier,
    }


def tool_gaps(cases: Sequence[Case], tool_result: ToolResult) -> list[dict]:
    by_file = tool_result.by_file()
    gaps: list[dict] = []
    for case in cases:
        if not case.is_malicious:
            continue
        fr = by_file.get(case.staged_file)
        expected_rule_ids = list(case.expected_rule_ids)
        expected_families = list(case.expected_families)
        if fr is None:
            reason = "no_result"
            verdict = None
            fired_rule_ids: list[str] = []
            fired_families: list[str] = []
        else:
            fired_rule_ids = sorted({f.rule_id for f in fr.findings})
            fired_families = sorted({f.family for f in fr.findings})
            verdict = fr.verdict or None
            if expected_rule_ids:
                if any(f.rule_id in expected_rule_ids for f in fr.findings):
                    continue
                reason = "no_expected_rule"
            elif expected_families:
                if any(f.family in expected_families for f in fr.findings):
                    continue
                reason = "no_expected_family"
            else:
                continue
        gaps.append(
            {
                "id": case.id,
                "tier": case.tier,
                "reason": reason,
                "verdict": verdict,
                "expected_rule_ids": expected_rule_ids,
                "expected_families": expected_families,
                "fired_rule_ids": fired_rule_ids,
                "fired_families": fired_families,
            }
        )
    gaps.sort(key=lambda g: g["id"])
    return gaps


def format_gaps_md(gaps: list[dict]) -> str:
    if not gaps:
        return "(no gaps)\n"

    def _cell(values: list[str]) -> str:
        return ", ".join(values) if values else "-"

    lines = [
        "| case | verdict | reason | expected | fired |",
        "| --- | --- | --- | --- | --- |",
    ]
    for gap in gaps:
        expected = gap["expected_rule_ids"] if gap["expected_rule_ids"] else gap["expected_families"]
        fired = gap["fired_rule_ids"] if gap["fired_rule_ids"] else gap["fired_families"]
        verdict = gap["verdict"] if gap["verdict"] else "-"
        lines.append(
            f"| {gap['id']} | {verdict} | {gap['reason']} | {_cell(expected)} | {_cell(fired)} |"
        )
    return "\n".join(lines) + "\n"
