"""summary.md renderer is a pure function of results."""

from __future__ import annotations

from detector.model import FileResult, Finding
from detector.summary import render_summary


def _finding(**kwargs) -> Finding:
    defaults = {
        "rule_id": "EXIT_ADDR_GATE",
        "family": "A",
        "severity": "HIGH",
        "contract": "Token",
        "function": "transfer",
        "lines": (10, 12),
        "reasoning": "addr gate",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def test_render_summary_header_table_and_empty() -> None:
    results = [
        FileResult(
            file="b.sol",
            verdict="Benign",
            findings=(),
        ),
        FileResult(
            file="a.sol",
            verdict="Malicious",
            reason="",
            findings=(
                _finding(rule_id="PRIV_ROLE", family="A", severity="INFO", function="owner", lines=(3,)),
                _finding(),
            ),
        ),
        FileResult(
            file="c.sol",
            verdict="Uncertain",
            reason="compile_failed",
            findings=(),
        ),
    ]
    meta = {"name": "detector", "version": "0.1.0"}
    first = render_summary(results, meta)
    second = render_summary(list(reversed(results)), meta)
    assert first == second
    assert first.startswith("# detector 0.1.0\n")
    assert "files: 3\n" in first
    assert "Malicious: 1\n" in first
    assert "Uncertain: 1\n" in first
    assert "Benign: 1\n" in first
    assert first.index("## a.sol") < first.index("## b.sol") < first.index("## c.sol")
    assert "verdict: Malicious" in first
    assert "verdict: Benign" in first
    assert "verdict: Uncertain" in first
    assert "reason: compile_failed" in first
    assert "| rule_id | severity | contract.function | lines | reasoning |" in first
    assert "| EXIT_ADDR_GATE | HIGH | Token.transfer | 10, 12 | addr gate |" in first
    assert "| PRIV_ROLE | INFO | Token.owner | 3 | addr gate |" in first
    # canonical finding order: EXIT after PRIV? EXIT_ADDR_GATE < PRIV_ROLE
    exit_pos = first.index("| EXIT_ADDR_GATE |")
    priv_pos = first.index("| PRIV_ROLE |")
    assert exit_pos < priv_pos
    assert first.count("_no findings_") == 2


def test_render_summary_omits_empty_reason() -> None:
    text = render_summary(
        [FileResult(file="x.sol", verdict="Benign")],
        {"name": "detector", "version": "0.1.0"},
    )
    assert "reason:" not in text
    assert "_no findings_" in text
