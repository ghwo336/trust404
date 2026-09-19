"""summary.md renderer: judge-facing, deterministic, a pure function of results (DT-11)."""

from __future__ import annotations

import random
import re

import pytest
import yaml

from detector import describe
from detector.model import FileResult, Finding
from detector.summary import compress_lines, explain_verdict, render_summary
from tests.detector.conftest import REPO_ROOT

META = {"name": "detector", "version": "0.1.0"}


def _finding(**kwargs) -> Finding:
    defaults = {
        "rule_id": "EXIT_ADDR_GATE",
        "family": "A",
        "severity": "HIGH",
        "contract": "Token",
        "function": "_transfer",
        "lines": (47,),
        "reasoning": "setBots writes blacklist; impact _transfer require",
        "base_severity": "HIGH",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def _priv_role(fn: str, var: str, kind: str = "eq_state_address", line: int = 10) -> Finding:
    return _finding(
        rule_id="PRIV_ROLE",
        family="A",
        severity="INFO",
        base_severity="INFO",
        function=fn,
        lines=(line,),
        reasoning=f"{fn} gated by {var} ({kind})",
    )


def _catalog_ids() -> list[str]:
    data = yaml.safe_load((REPO_ROOT / "baybench" / "catalog.yaml").read_text(encoding="utf-8"))
    return list(data["rules"].keys())


def _sample_results() -> list[FileResult]:
    return [
        FileResult(file="z_benign.sol", verdict="Benign", findings=()),
        FileResult(
            file="gate.sol",
            verdict="Malicious",
            findings=(
                _finding(function="setBots", lines=(23,)),
                _finding(),
                _priv_role("setBots", "owner", line=12),
            ),
        ),
        FileResult(
            file="usdc.sol",
            verdict="Malicious",
            findings=(
                _finding(
                    rule_id="BAL_PRIV_MINT",
                    family="B",
                    severity="HIGH",
                    contract="FiatTokenV1",
                    function="mint",
                    lines=tuple(range(741, 758)),
                    reasoning="mint increases bound balance or supply",
                    discriminators=("managed_role",),
                ),
                _finding(
                    contract="FiatTokenV1",
                    function="notBlacklisted",
                    lines=(518, 519, 520, 521),
                    reasoning="blacklist writes _deprecatedBlacklisted; impact notBlacklisted require",
                    discriminators=("managed_role",),
                ),
            ),
        ),
        FileResult(file="broken.sol", verdict="Uncertain", reason="compile_failed", findings=()),
        FileResult(
            file="a_hidden.sol",
            verdict="Malicious",
            findings=(
                _finding(
                    rule_id="OWN_HIDDEN_ROLE",
                    family="D",
                    contract="HiddenRole",
                    function="setBlacklist",
                    lines=(15,),
                    reasoning="_dev gates setBlacklist and is not exposed",
                ),
                _priv_role("setBlacklist", "_dev", line=15),
            ),
        ),
    ]


# --- helpers --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("lines", "expected"),
    [
        ((), "—"),
        ((5,), "5"),
        (tuple(range(741, 758)), "741-757"),
        ((12, 47, 48, 49), "12, 47-49"),
        ((49, 47, 12, 48, 12), "12, 47-49"),
        ((1, 3, 5), "1, 3, 5"),
        ((1, 2), "1-2"),
    ],
)
def test_compress_lines(lines: tuple[int, ...], expected: str) -> None:
    assert compress_lines(lines) == expected


def test_explain_verdict_sentences() -> None:
    high = _finding()
    hidden = _finding(rule_id="OWN_HIDDEN_ROLE", family="D")
    info = _priv_role("setBots", "owner")

    assert explain_verdict("Malicious", "", [high, high, info]) == (
        "HIGH: Settable address gate on transfers"
    )
    # distinct titles, canonical (rule id) order
    assert explain_verdict("Malicious", "", [hidden, high]) == (
        "HIGH: Settable address gate on transfers, Undisclosed privileged role"
    )
    # overlay exploit-shape is a counting finding (HIGH) under decisive mode
    overlay_high = _finding(
        rule_id="SLITHER_HIGH_OVERLAY",
        family="C",
        severity="HIGH",
        base_severity="INFO",
        reasoning="arbitrary-send-eth: Vault.sweep() sends eth to arbitrary user",
    )
    assert explain_verdict("Malicious", "", [overlay_high, info]) == (
        "HIGH: Slither high-impact check"
    )
    assert explain_verdict("Uncertain", "external_dependency", []) == (
        "transfer behaviour depends on a contract at a settable address"
    )
    assert explain_verdict("Uncertain", "budget_exhausted", []) == (
        "global time budget exhausted before this file was analysed"
    )
    assert explain_verdict("Uncertain", "compile_failed", []) == (
        "source did not compile with any pinned solc — not analysed"
    )
    assert explain_verdict("Uncertain", "timeout", []) == (
        "analysis exceeded the per-file time limit — not analysed"
    )
    assert explain_verdict("Uncertain", "analysis_error", []) == (
        "analysis raised an internal error — not analysed"
    )
    assert explain_verdict("Benign", "", []) == "no privileged control over user funds found"
    assert explain_verdict("Benign", "", [info]) == "only informational role evidence"
    assert explain_verdict("Uncertain", "", []) == "manual review required"
    assert explain_verdict("Uncertain", "something_new", []) == "reason: something_new"


# --- structure -------------------------------------------------------------------------------


def test_header_legend_counts_and_footer() -> None:
    text = render_summary(_sample_results(), META)
    assert text.startswith("# detector 0.1.0 — offline static analysis report\n")
    assert "**Malicious** = a counting (HIGH) finding" in text
    assert "**Uncertain** = compile failure, timeout, analysis error, or external dependency only" in text
    assert "**Benign** = no counting finding" in text
    assert "**HIGH** drives Malicious" in text
    assert "**MED** = external dependency → Uncertain" in text
    assert "**INFO** is evidence only, including bounded controls and governance notes" in text
    assert "Files: 5 · Malicious 3 · Uncertain 1 · Benign 1" in text
    assert text.rstrip("\n").endswith(
        "Analysis is static (Slither IR), name-agnostic and offline; verdict rules: see README."
    )


def test_overview_table_sorted_by_verdict_then_path() -> None:
    text = render_summary(_sample_results(), META)
    assert "| file | verdict | why | HIGH | MED | INFO |" in text
    rows = [
        "| a_hidden.sol | Malicious | HIGH: Undisclosed privileged role | 1 | 0 | 1 |",
        "| gate.sol | Malicious | HIGH: Settable address gate on transfers | 2 | 0 | 1 |",
        "| usdc.sol | Malicious | HIGH: Privileged mint, Settable address gate on transfers | 2 | 0 | 0 |",
        "| broken.sol | Uncertain | source did not compile with any pinned solc — not analysed | 0 | 0 | 0 |",
        "| z_benign.sol | Benign | no privileged control over user funds found | 0 | 0 | 0 |",
    ]
    positions = [text.index(row) for row in rows]
    assert positions == sorted(positions)
    # per-file sections follow the same order and come after the overview
    sections = [text.index(f"### {name}") for name in ("a_hidden.sol", "gate.sol", "usdc.sol", "broken.sol", "z_benign.sol")]
    assert sections == sorted(sections)
    assert positions[-1] < sections[0]


def test_per_file_section_groups_by_severity_with_titles_and_ranges() -> None:
    text = render_summary(_sample_results(), META)
    section = text[text.index("### usdc.sol") : text.index("### broken.sol")]
    assert "Verdict: **Malicious** — HIGH: Privileged mint, Settable address gate on transfers" in section
    assert "| rule | title | where | lines | evidence |" in section
    assert (
        "| BAL_PRIV_MINT | Privileged mint | FiatTokenV1.mint | 741-757 | mint increases bound balance or supply |"
    ) in section
    assert "| EXIT_ADDR_GATE | Settable address gate on transfers | FiatTokenV1.notBlacklisted | 518-521 |" in section
    assert "**HIGH**" in section
    assert "**MED**" not in section

    gate = text[text.index("### gate.sol") : text.index("### usdc.sol")]
    assert "Verdict: **Malicious** — HIGH: Settable address gate on transfers" in gate
    assert gate.index("**HIGH**") < gate.index("**INFO**")
    assert "**MED**" not in gate
    # canonical order inside a group: (rule_id, contract, function, lines)
    assert gate.index("| Token._transfer |") < gate.index("| Token.setBots |")
    assert "| PRIV_ROLE | Role-gated function | Token.setBots | 12 | setBots gated by owner (eq_state_address) |" in gate


def test_zero_findings_and_not_analysed_sections() -> None:
    text = render_summary(_sample_results(), META)
    broken = text[text.index("### broken.sol") : text.index("### z_benign.sol")]
    assert "Verdict: **Uncertain** (`compile_failed`) — source did not compile with any pinned solc — not analysed" in broken
    assert "_no findings_" in broken
    benign = text[text.index("### z_benign.sol") :]
    assert "Verdict: **Benign** — no privileged control over user funds found" in benign
    assert "_no findings_" in benign


def test_empty_contract_function_and_lines_render_placeholders() -> None:
    results = [
        FileResult(
            file="odd.sol",
            verdict="Malicious",
            findings=(
                _finding(contract="", function="", lines=()),
                _finding(rule_id="STRUCT_SELFDESTRUCT", family="E", contract="Only", function="", lines=(3,)),
                _finding(rule_id="OWN_TX_ORIGIN", family="D", severity="MED", contract="", function="fn", lines=(9,)),
            ),
        )
    ]
    text = render_summary(results, META)
    assert "| EXIT_ADDR_GATE | Settable address gate on transfers | — | — |" in text
    assert "| STRUCT_SELFDESTRUCT | Reachable selfdestruct | Only | 3 |" in text
    assert "| OWN_TX_ORIGIN | tx.origin-based authorisation | fn | 9 |" in text


def test_info_priv_role_collapses_above_six() -> None:
    fns = [(f"fn{i}", var) for i, var in enumerate(["owner", "owner", "_admins", "pauser", "owner", "_admins", "owner", "pauser"])]
    findings = tuple(
        _priv_role(fn, var, kind="map_bool" if var.startswith("_") else "eq_state_address", line=i + 1)
        for i, (fn, var) in enumerate(fns)
    )
    text = render_summary([FileResult(file="many.sol", verdict="Benign", findings=findings)], META)
    assert "8 privileged functions gated by _admins, owner, pauser" in text
    assert "<details>" in text and "</details>" in text
    for fn, _var in fns:
        assert f"| Token.{fn} |" in text
    assert "| Benign | only informational role evidence | 0 | 0 | 8 |" in text

    six = findings[:6]
    text6 = render_summary([FileResult(file="six.sol", verdict="Benign", findings=six)], META)
    assert "<details>" not in text6
    assert "privileged functions gated by" not in text6
    assert text6.count("| PRIV_ROLE | Role-gated function |") == 6


def test_info_collapse_keeps_other_info_rows_visible() -> None:
    priv = tuple(_priv_role(f"f{i}", "owner", line=i + 1) for i in range(7))
    overlay = _finding(
        rule_id="SLITHER_HIGH_OVERLAY",
        family="C",
        severity="INFO",
        base_severity="INFO",
        function="sweep",
        lines=(30, 31),
        reasoning="unchecked-transfer: ignores return value",
        discriminators=("evidence_only",),
    )
    text = render_summary([FileResult(file="x.sol", verdict="Benign", findings=priv + (overlay,))], META)
    assert "7 privileged functions gated by owner" in text
    details_start = text.index("<details>")
    overlay_row = text.index("| SLITHER_HIGH_OVERLAY | Slither high-impact check | Token.sweep | 30-31 |")
    assert overlay_row < details_start


def test_severity_change_note_only_when_severity_moved() -> None:
    raised = _finding(
        rule_id="EXIT_TIME_GATE",
        family="A",
        severity="HIGH",
        base_severity="MED",
        discriminators=("no_expiry",),
        reasoning="setUntil writes until; impact _transfer require",
    )
    unchanged = _finding(reasoning="plain")
    bare = _finding(rule_id="OWN_TX_ORIGIN", family="D", severity="MED", base_severity="", reasoning="")
    text = render_summary(
        [FileResult(file="t.sol", verdict="Malicious", findings=(raised, unchanged, bare))], META
    )
    assert "setUntil writes until; impact _transfer require · raised MED→HIGH: no writer bounds the gate in time |" in text
    assert "| plain |" in text
    assert "| OWN_TX_ORIGIN | tx.origin-based authorisation | Token._transfer | 47 | — |" in text


def test_severity_note_uses_catalog_base_when_finding_came_from_json() -> None:
    # engine rebuilds Findings from the worker's JSON payload: schema fields only
    from_json = Finding(
        rule_id="BAL_PRIV_MINT",
        family="B",
        severity="MED",
        contract="FiatTokenV1",
        function="mint",
        lines=(741,),
        reasoning="mint increases bound balance or supply",
    )
    text = render_summary([FileResult(file="u.sol", verdict="Benign", findings=(from_json,))], META)
    assert "| mint increases bound balance or supply · downgraded HIGH→MED |" in text


def test_table_cells_are_escaped() -> None:
    results = [
        FileResult(
            file="pipe.sol",
            verdict="Malicious",
            findings=(_finding(reasoning="a | b\nsecond line"),),
        )
    ]
    text = render_summary(results, META)
    assert "a \\| b second line" in text


def test_no_paths_or_timestamps_leak() -> None:
    text = render_summary(_sample_results(), META)
    assert "/Users" not in text
    assert "/tmp" not in text
    assert "/input" not in text
    assert re.search(r"\d{4}-\d{2}-\d{2}", text) is None


def test_render_is_deterministic_under_shuffling() -> None:
    base = _sample_results()
    reference = render_summary(base, META)
    rng = random.Random(7)
    for _ in range(5):
        shuffled = list(base)
        rng.shuffle(shuffled)
        shuffled = [
            FileResult(
                file=item.file,
                verdict=item.verdict,
                reason=item.reason,
                findings=tuple(rng.sample(item.findings, len(item.findings))),
            )
            for item in shuffled
        ]
        assert render_summary(shuffled, META) == reference
    assert render_summary(base, META) == reference


def test_meta_falls_back_to_package_constants() -> None:
    text = render_summary([], {})
    assert text.startswith("# detector 0.1.0 — offline static analysis report\n")
    assert "Files: 0 · Malicious 0 · Uncertain 0 · Benign 0" in text


def test_skipped_dependency_files_header_only_when_positive() -> None:
    text = render_summary(_sample_results(), {**META, "skipped_dependency_files": 4})
    assert (
        "- Skipped 4 dependency file(s) under node_modules/ or lib/<pkg>/ "
        "(analysed as imports only)."
    ) in text
    assert "Skipped" not in render_summary(_sample_results(), META)
    assert "Skipped" not in render_summary(_sample_results(), {**META, "skipped_dependency_files": 0})


# --- describe.py <-> catalog <-> README ------------------------------------------------------


def test_describe_covers_exactly_the_catalog() -> None:
    ids = _catalog_ids()
    assert len(ids) == 29
    assert set(describe.RULE_TITLES) == set(ids)
    assert set(describe.RULE_EXPLANATIONS) == set(ids)
    assert set(describe.FAMILY_TITLES) == {"A", "B", "C", "D", "E", "F", "G"}
    assert describe.discriminator_title("managed_role") != "managed_role"
    assert describe.discriminator_title("never_heard_of") == "never_heard_of"
    assert set(describe.GOVERNANCE_NOTE) == {"managed_role", "issuer_token", "role_separated_cap"}
    assert set(describe.BOUNDING_NOTE) >= {
        "constant_cap",
        "fee_cap",
        "constant_floor",
        "bounded_window",
        "ungate_exists",
        "no_custody",
        "foreign_only",
        "two_step_handoff",
        "one_shot_initializer",
        "representation_switch",
    }
    assert "budget_exhausted" in describe.REASON_SENTENCES
    assert "external_dependency" in describe.REASON_SENTENCES
    for rule_id in ids:
        assert describe.rule_title(rule_id) == describe.RULE_TITLES[rule_id]
        assert describe.RULE_TITLES[rule_id].strip()
        assert "," not in describe.RULE_TITLES[rule_id]
        assert "|" not in describe.RULE_TITLES[rule_id]
    assert describe.rule_title("UNKNOWN_RULE") == "UNKNOWN_RULE"


def test_readme_lists_every_catalog_rule_with_its_title() -> None:
    readme = (REPO_ROOT / "detector" / "README.md").read_text(encoding="utf-8")
    data = yaml.safe_load((REPO_ROOT / "baybench" / "catalog.yaml").read_text(encoding="utf-8"))
    for rule_id, meta in data["rules"].items():
        row = f"| `{rule_id}` | {describe.RULE_TITLES[rule_id]} | {meta['severity']} |"
        assert row in readme, f"README rule table is missing or mismatched for {rule_id}"
    for family, title in describe.FAMILY_TITLES.items():
        assert f"Family {family} — {title}" in readme
    assert "docker run --rm --network none" in readme
    assert "python -m detector.cli" in readme
    assert "<!-- BENCH NUMBERS: filled by orchestrator -->" in readme
