from __future__ import annotations

import json
from pathlib import Path

import click
import yaml

from .catalog import load_catalog
from .coverage import coverage_report, format_gaps_md, tool_gaps
from .ingest import ingest_discord, ingest_paper
from .models import SchemaError, load_cases
from .report import build_report, write_report
from .runner import RunnerError, run
from .validate import compile_fixtures

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = REPO_ROOT / "cases"
DEFAULT_REPORTS = REPO_ROOT / "reports"
TOOLS_YAML = Path(__file__).with_name("tools.yaml")


def _tier_list(tiers: tuple[str, ...]) -> list[str] | None:
    return list(tiers) if tiers else None


def _load_tools() -> dict[str, dict]:
    data = yaml.safe_load(TOOLS_YAML.read_text(encoding="utf-8")) or {}
    tools = data.get("tools") or []
    return {tool["name"]: tool for tool in tools}


def _find_tool(name: str) -> dict:
    tools = _load_tools()
    tool_cfg = tools.get(name)
    if tool_cfg is None:
        known = ", ".join(sorted(tools)) or "(none)"
        raise click.ClickException(f"unknown tool {name!r}; registered: {known}")
    return tool_cfg


def _fmt_det(value: bool | None) -> str:
    if value is True:
        return "pass"
    if value is False:
        return "fail"
    return "-"


def _print_coverage_summary(cov: dict) -> None:
    zero_rules = cov.get("rules_zero_cases") or []
    missing_pair = cov.get("rules_missing_pair") or []
    click.echo(f"n_cases: {cov.get('n_cases', 0)}")
    click.echo(f"per_tier: {cov.get('per_tier') or {}}")
    click.echo(f"families_zero_cases: {cov.get('families_zero_cases') or []}")
    click.echo(f"rules_zero_cases: {len(zero_rules)}")
    click.echo(f"rules_missing_pair: {missing_pair}")


@click.group()
def cli() -> None:
    """BAYBENCH — offline harness for TRUST404 Track 1 detectors."""


@cli.command("run")
@click.argument("tool")
@click.option("--cases", type=click.Path(path_type=Path), default=DEFAULT_CASES, show_default=True)
@click.option("--tier", "tiers", multiple=True, help="Tier filter (repeatable; e.g. 1 or tier1_pairs).")
@click.option("--no-docker", is_flag=True, help="Run the tool's cmd instead of its Docker image.")
@click.option("--repeat", default=2, show_default=True, type=int, help="Determinism repeats.")
@click.option(
    "--timeout",
    default=600,
    show_default=True,
    type=int,
    help="Per-run wall-clock limit in seconds for the tool process.",
)
@click.option(
    "--reports",
    type=click.Path(path_type=Path),
    default=DEFAULT_REPORTS,
    show_default=True,
)
def run_cmd(
    tool: str,
    cases: Path,
    tiers: tuple[str, ...],
    no_docker: bool,
    repeat: int,
    timeout: int,
    reports: Path,
) -> None:
    """Run a registered tool and write reports/<tool>/report.{md,json}."""
    if repeat < 1:
        raise click.ClickException("--repeat must be >= 1")
    if timeout < 1:
        raise click.ClickException("--timeout must be >= 1")
    tool_cfg = _find_tool(tool)
    tier_list = _tier_list(tiers)
    loaded_cases = load_cases(cases, tier_list)
    catalog = load_catalog()
    runs: list[dict] = []
    try:
        for i in range(repeat):
            work_dir = REPO_ROOT / ".bench_work" / tool_cfg["name"] / f"run{i}"
            runs.append(
                run(
                    tool_cfg,
                    cases,
                    tier_list,
                    use_docker=not no_docker,
                    work_dir=work_dir,
                    timeout=timeout,
                )
            )
    except (RunnerError, SchemaError) as exc:
        raise click.ClickException(str(exc)) from exc
    rep = build_report(
        tool_cfg["name"],
        loaded_cases,
        runs[0],
        catalog,
        all_run_results=runs,
    )
    md_path, _json_path = write_report(reports, rep)
    scoring = rep["scoring"]
    click.echo(
        f"{tool_cfg['name']} weighted_score={scoring.get('weighted_score')} "
        f"determinism={_fmt_det(rep['determinism'].get('deterministic'))} "
        f"compile_fail_count={scoring['overall'].get('compile_fail_count')} "
        f"reports={md_path.parent}"
    )


@cli.command("coverage")
@click.argument("tool", required=False)
@click.option("--cases", type=click.Path(path_type=Path), default=DEFAULT_CASES, show_default=True)
@click.option("--tier", "tiers", multiple=True, help="Tier filter (repeatable).")
@click.option("--no-docker", is_flag=True, help="When TOOL is given, run its cmd instead of Docker.")
def coverage_cmd(
    tool: str | None,
    cases: Path,
    tiers: tuple[str, ...],
    no_docker: bool,
) -> None:
    """Print corpus coverage; with TOOL, also print that tool's gap list."""
    catalog = load_catalog()
    loaded_cases = load_cases(cases, _tier_list(tiers))
    cov = coverage_report(loaded_cases, catalog)
    _print_coverage_summary(cov)
    if tool is None:
        return
    tool_cfg = _find_tool(tool)
    work_dir = REPO_ROOT / ".bench_work" / tool_cfg["name"] / "coverage"
    try:
        run_result = run(
            tool_cfg,
            cases,
            _tier_list(tiers),
            use_docker=not no_docker,
            work_dir=work_dir,
        )
    except (RunnerError, SchemaError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(format_gaps_md(tool_gaps(loaded_cases, run_result["result"])), nl=False)


@cli.command("validate")
@click.option("--cases", type=click.Path(path_type=Path), default=DEFAULT_CASES, show_default=True)
@click.option("--tier", "tiers", multiple=True, help="Tier filter (repeatable).")
def validate_cmd(cases: Path, tiers: tuple[str, ...]) -> None:
    """Compile corpus fixtures with the pinned solc versions (BB-11)."""
    loaded = load_cases(cases, _tier_list(tiers))
    results = compile_fixtures(loaded, REPO_ROOT)
    ok_n = 0
    for case_id, ok, log in results:
        if ok:
            ok_n += 1
        else:
            click.echo(f"{case_id}: {log}")
    click.echo(f"{ok_n}/{len(results)} compiled")
    if ok_n != len(results):
        raise SystemExit(1)


@cli.command("report")
@click.option("--cases", type=click.Path(path_type=Path), default=DEFAULT_CASES, show_default=True)
@click.option(
    "--reports",
    type=click.Path(path_type=Path),
    default=DEFAULT_REPORTS,
    show_default=True,
)
def report_cmd(cases: Path, reports: Path) -> None:
    """Print a summary table of reports/*/report.json."""
    del cases
    rows = []
    for path in sorted(reports.glob("*/report.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        scoring = data.get("scoring") or {}
        overall = scoring.get("overall") or {}
        det = (data.get("determinism") or {}).get("deterministic")
        rows.append(
            (
                data.get("tool") or path.parent.name,
                scoring.get("weighted_score"),
                overall.get("mean_verdict_score"),
                _fmt_det(det),
                overall.get("compile_fail_count"),
            )
        )
    click.echo("| tool | weighted_score | mean_score | determinism | compile_fail |")
    click.echo("| --- | --- | --- | --- | --- |")
    if not rows:
        return
    for tool, weighted, mean, det, compile_fail in rows:
        weighted_s = "-" if weighted is None else str(weighted)
        mean_s = "-" if mean is None else str(mean)
        fail_s = "-" if compile_fail is None else str(compile_fail)
        click.echo(
            f"| {tool} | {weighted_s} | {mean_s} | {det} | {fail_s} |"
        )


def _ingest_not_implemented(name: str, exc: NotImplementedError) -> None:
    click.echo(f"{name} is not yet implemented ({exc})")
    raise SystemExit(2)


@cli.command("ingest-discord")
@click.argument("src", type=click.Path(path_type=Path))
@click.option("--cases", type=click.Path(path_type=Path), default=DEFAULT_CASES, show_default=True)
def ingest_discord_cmd(src: Path, cases: Path) -> None:
    """Ingest Discord public samples into cases/tier0_judge (BB-8)."""
    try:
        created = ingest_discord(src, cases / "tier0_judge")
    except NotImplementedError as exc:
        _ingest_not_implemented("ingest-discord", exc)
        return
    for case_id in created:
        click.echo(case_id)


@cli.command("ingest-paper")
@click.argument("source")
@click.argument("src", type=click.Path(path_type=Path))
@click.option("--cases", type=click.Path(path_type=Path), default=DEFAULT_CASES, show_default=True)
def ingest_paper_cmd(source: str, src: Path, cases: Path) -> None:
    """Ingest a paper corpus into cases/tier2_realworld (BB-9)."""
    try:
        created = ingest_paper(source, src, cases / "tier2_realworld")
    except NotImplementedError as exc:
        _ingest_not_implemented("ingest-paper", exc)
        return
    for case_id in created:
        click.echo(case_id)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
