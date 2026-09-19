# BAYBENCH — Spec (SSOT)

Offline benchmark harness for TRUST404 Track 1 detectors. This document is the single source of truth for scope. Patterns/rule IDs come from [../research/track1-malice-patterns.md](../research/track1-malice-patterns.md) (§3 families A–G, §6 lookalikes, §7 rule table).

## Purpose

Score any teammate's Track 1 tool identically and offline, then drive detector iteration from misses. A tool is a black box that reads a directory of `.sol` and writes one `results.json`.

## Non-negotiable constraints

- Grading parity = `docker run --rm --network none`. Network-dependent tools score zero by construction.
- Tool integration is by registry entry (Docker image or shell command), never by importing tool code.
- Deterministic: same input → same output.

## Contracts (schemas)

### Tool output — `baybench/schema/result.schema.json` (JSON Schema draft 2020-12)

Top-level object, `additionalProperties: false`:
- `tool` (required): object `{ name: string (required, minLength 1), version: string }`, `additionalProperties: false`.
- `results` (required): array of result objects.

result object, `additionalProperties: false`:
- `file` (required): string, path relative to the staged input root.
- `verdict` (required): enum `Benign | Malicious | Uncertain`.
- `reason`: string (free text; conventional values `compile_failed`, `external_dependency`, `timeout`).
- `findings`: array of finding objects.

finding object, `additionalProperties: false`:
- `rule_id` (required): string.
- `family` (required): enum `A|B|C|D|E|F|G`.
- `severity` (required): enum `HIGH|MED|INFO`.
- `contract`: string. `function`: string. `lines`: array of integers. `reasoning`: string.

This same schema is the Track 1 submission format.

### Case labels — `baybench/schema/case.schema.json`

One `labels.yaml` per case directory, `additionalProperties: false`:
- `id` (required): string, unique, e.g. `tier1/EXIT_ADDR_GATE/mal`.
- `file` (required): string, `.sol` filename relative to the case dir.
- `preferred_verdict` (required): enum `Benign|Malicious|Uncertain`.
- `accepted_verdicts` (required): non-empty array of the verdict enum; must contain `preferred_verdict`.
- `expected_families`: array of `A..G`.
- `expected_rule_ids`: array of strings (any-of semantics).
- `expected_functions`: array of strings (evidence-hit check).
- `source`: string. `solc`: string (pragma version to compile with, e.g. `0.8.20`).

### Rule catalog — `baybench/catalog.yaml`

Authoritative list of families and rule IDs (from §7). Coverage is computed against this.

```yaml
families: [A, B, C, D, E, F, G]
rules:
  PRIV_ROLE:                    {family: A, severity: INFO}   # meta, feeds others
  EXIT_ADDR_GATE:               {family: A, severity: HIGH}
  EXIT_GLOBAL_SWITCH:           {family: A, severity: HIGH}
  EXIT_AMOUNT_LIMIT:            {family: A, severity: HIGH}
  EXIT_TIME_GATE:               {family: A, severity: MED}
  EXIT_SELL_ONLY:               {family: A, severity: HIGH}
  EXIT_CALLBACK_CYCLE:          {family: A, severity: HIGH}
  FEE_UNBOUNDED:                {family: A, severity: HIGH}
  FEE_ADDR_MUTABLE:             {family: C, severity: MED}
  BAL_PRIV_MINT:                {family: B, severity: HIGH}
  BAL_PRIV_BURN_OTHER:          {family: B, severity: HIGH}
  BAL_DIRECT_SET:               {family: B, severity: HIGH}
  BAL_TRANSFER_HIDDEN_MINT:     {family: B, severity: HIGH}
  VIEW_CALLER_DEPENDENT:        {family: B, severity: HIGH}
  LEAK_ARBITRARY_TRANSFERFROM:  {family: C, severity: HIGH}
  LEAK_EXEMPT_PATH:             {family: C, severity: HIGH}
  LEAK_PRIV_SWEEP:              {family: C, severity: HIGH}
  OWN_HIDDEN_ROLE:              {family: D, severity: HIGH}
  OWN_FAKE_RENOUNCE:            {family: D, severity: HIGH}
  OWN_REASSIGN_NONSTD:          {family: D, severity: HIGH}
  OWN_TX_ORIGIN:                {family: D, severity: MED}
  STRUCT_EXTERNAL_GATE:         {family: E, severity: MED}    # -> Uncertain w/ reason
  STRUCT_DELEGATECALL_SETTABLE: {family: E, severity: HIGH}
  STRUCT_SELFDESTRUCT:          {family: E, severity: HIGH}
  STRUCT_PROXY_EOA_ADMIN:       {family: E, severity: MED}
  DRAIN_APPROVAL_PULL:          {family: F, severity: HIGH}
  HONEYPOT_LEGACY:              {family: F, severity: MED}
  PONZI_SHAPE:                  {family: G, severity: MED}
  SLITHER_HIGH_OVERLAY:         {family: C, severity: INFO}   # overlay only
```

## Module interfaces (`baybench/` package)

- `catalog.py`: `load_catalog(path=None) -> dict` → `{"families": [...], "rules": {id: {"family","severity"}}}`.
- `models.py`: dataclasses `Case`, `Finding`, `FileResult`, `ToolResult`; `load_cases(cases_root, tiers=None) -> list[Case]` (walks `labels.yaml`); `parse_result(obj|path) -> ToolResult`.
- `scoring.py`:
  - `verdict_score(actual, preferred, accepted) -> float`:
    - `actual == preferred` → `1.0`
    - `actual in accepted` → `0.75`
    - `actual == "Uncertain"` → `0.5`
    - else → `0.0`
  - `score_run(cases, tool_result, catalog, timings=None) -> dict` with, per tier and overall: `mean_verdict_score`, `family_recall` (malicious cases with expected_families: share with ≥1 finding whose family ∈ expected_families), `high_fp_rate` (Benign-preferred cases with any HIGH finding / Benign cases), `evidence_hit_rate` (cases with expected_functions where a finding.function ∈ expected_functions), `uncertain_rate`, `compile_fail_count` (results whose `reason` contains `compile_failed`), `runtime_p50`/`runtime_p95` (from timings). Also per-family mean score.
- `coverage.py`:
  - `coverage_report(cases, catalog) -> dict`: `families_zero_cases`, `rules_zero_cases` (rule IDs never referenced by any case's `expected_rule_ids`), plus per-family/per-rule case counts.
  - `tool_gaps(cases, tool_result) -> list[str]`: ids of malicious cases where no finding matches any `expected_rule_ids` (fallback `expected_families`). This list is the iterate worklist.
- `determinism.py`: `canonical(tool_result_dict) -> dict` (sort results by `file`, findings by `(rule_id, function, lines)`); `is_deterministic(run_a, run_b) -> (bool, diff_str)`.
- `runner.py`:
  - `stage_tiers(cases_root, tiers, dest) -> dict` copies each case directory (all files except `labels.yaml`) to `dest/<case.id>/`; the tool must report `file` as `<case.id>/<case.file>` (`Case.staged_file`) relative to the input root. Returns map `staged_file → Case`. Tool-reported paths are normalized with `models.normalize_result_file` (strips `./`, `/input/`).
  - `run_tool(tool_cfg, input_dir, out_dir, use_docker=True, timeout=600) -> dict` → `{ "result": ToolResult, "wall_s": float, "stdout","stderr","returncode" }`. Docker mode: `docker run --rm --network none -v {input}:/input:ro -v {out}:/output {image}`. Command mode: substitute `{input}`/`{output}` in `cmd`. Validate `results.json` against `result.schema.json`; raise `ResultSchemaError` with a clear message on failure.
- `validate.py`: `compile_fixtures(cases) -> list[(case_id, ok, log)]` using `solc-select use <case.solc>` then `solc --bin`; import remapping `@openzeppelin/=<vendored>/` supported. Backs `bench validate` (BB-11).
- `cli.py` (`bench` entry point): `run <tool> [--tier N ...] [--no-docker] [--repeat 2] [--timeout 600]`, `coverage <tool>`, `validate [--tier N]`, `report`, `ingest-discord <dir>`, `ingest-paper <source> <dir>`. `--timeout` (seconds, added 2026-09-20) is the per-run wall-clock limit passed to `runner.run(..., timeout=)`; the all-tier corpus (~850 files) needs more than the 600 s default in Docker, and a run that exceeds it fails with the existing `RunnerError` message rather than producing a partial report.

## Registry — `baybench/tools.yaml`

```yaml
tools:
  - name: baseline_keyword
    image: baybench/baseline_keyword:latest      # docker mode
  - name: my_local_tool
    cmd: "python /path/tool.py --in {input} --out {output}/results.json"   # --no-docker mode
  - name: teammate_tool
    cmd: "node ${T404_DIR}/dist/baybench.js {input} {output}/results.json"  # env-relative
```

`cmd` (amended 2026-09-20, teammate portability): after `{input}`/`{output}` substitution the string goes through `os.path.expandvars`, so a registry entry may point at a teammate's checkout via an environment variable instead of an absolute local path. An unresolved `${VAR}` / `$VAR` is a `RunnerError` that names the variable and the tool (no silent literal path). The command runs with `cwd` = repo root, so `../sibling` relative paths are the other portable form. The registry is committed; machine-specific absolute paths are not.

## Report

`bench report` writes, per tool, `reports/<tool>/report.md` + `report.json`: scoring (per tier, per family), coverage (zero-case families/rules, gap list), determinism pass/fail, runtime p50/p95, compile-fail count, and (2026-09-20) a `tier0 exact: k/n` gate line next to the weighted score.

## Corpus tiers

- Tier 0 `cases/tier0_judge/` — organizers' public samples (`challenge_public/`, ingested 2026-09-20, labels from the file comments). Weight **1.0** (amended 2026-09-20 from 4.0: five samples must not be 44% of the score); the report prints a separate gate line `tier0 exact: k/n` so 5/5 stays visible.
- Tier 1 `cases/tier1_pairs/<RULE_ID>/` — hand-written malicious + benign twin per rule ID (≤80 lines, pinned pragma). Twins per plan Phase 2. Under decisive mode (2026-09-20, `detector.md` §policy) the `mal` twins of `HONEYPOT_LEGACY`, `PONZI_SHAPE`, `STRUCT_PROXY_EOA_ADMIN`, `OWN_TX_ORIGIN`, `SLITHER_HIGH_OVERLAY` carry `preferred_verdict: Malicious`; `FEE_ADDR_MUTABLE/mal` carries `preferred_verdict: Benign, accepted: [Benign, Uncertain]` (the rule fires as INFO; `expected_rule_ids` unchanged); `STRUCT_EXTERNAL_GATE/mal` stays Uncertain; `PRIV_ROLE/ben` is re-shaped so its admin role gates a setter off the transfer path (its former shape duplicated `_harness/oz_ownable_rug`, which is Malicious).
- Tier 2 `cases/tier2_realworld/` — Pied-Piper (200 injected + real), CRPWarner (69), HoneyBadger Table 5 (24). Paper label → family mapping.
- Tier 3 `cases/tier3_benign_risky/` — real/OZ contracts that look risky. Two classes since 2026-09-20: **bounded** (`oz_erc20_pausable_ownable`, `oz_erc20capped_accesscontrol`, `oz_erc20permit`, `reflection_token`, `erc20_foreign_rescue`) keep `preferred: Benign, accepted: [Benign, Uncertain]` and are the false-MALICIOUS brake; **governance-only** (`usdc_fiattoken`, `bancor_smarttoken`, `lido_ldo_minime` — blacklist / burn-other / uncapped mint under a managed role, no code bound) carry `preferred: Malicious` per the organizers' rules 1–2 read literally; `usdc`/`bancor` accept `[Malicious, Benign]` (either decisive answer is defensible, abstaining is not), `lido` accepts `[Malicious, Uncertain]` (its transfer path calls the settable `controller`, so `Uncertain(external_dependency)` is the sanctioned abstain; Benign is not defensible while `generateTokens` is uncapped). Governance-only `expected_families` list the families whose rules carry the verdict (usdc `[A, B]`, bancor `[B, C]`, lido `[B, E]`). The `_harness/oz_accesscontrol_blacklist` fixture (admin-role blacklist on `transfer`) is the same shape as `_harness/oz_ownable_rug` and carries `preferred: Malicious, accepted: [Malicious]`.

## Baselines

- `baseline_keyword` — name regex → Malicious if any. Tier 1 benign twins must defeat it.
- `baseline_slither` — raw Slither High detectors → Malicious if any High.
- `probe_network` — attempts network egress; must fail under the runner (proves BB-2).

## Acceptance (BB-1 .. BB-11)

- **BB-1** Schemas exist; invalid tool output fails a run with a clear message.
- **BB-2** Runner executes a registered image under `--network none`; `probe_network` cannot reach the network.
- **BB-3** Scoring emits the per-tier and per-family metrics above.
- **BB-4** Coverage lists families and rule IDs with zero cases, plus per-tool gap list.
- **BB-5** Determinism double-run pass/fail per tool.
- **BB-6** Tier 1: every rule ID in the catalog has ≥1 malicious and ≥1 benign twin; `bench validate` compiles all.
- **BB-7** Tier 3: ≥8 risky fixtures; the bounded class carries `accepted: [Benign, Uncertain]`, the governance-only class `preferred: Malicious` with `accepted: [Malicious, Benign]` (`usdc`, `bancor`) or `[Malicious, Uncertain]` (`lido`, external-gate abstain) as listed under Corpus tiers (amended 2026-09-20; ≥5 bounded fixtures remain so the false-MALICIOUS brake keeps teeth).
- **BB-12** (2026-09-20) `TIER_WEIGHTS["tier0_judge"] == 1.0`; `report.md`/`report.json` carry `tier0_exact: k/n` (files whose verdict equals `preferred_verdict`) as its own line under the summary.
- **BB-8** Tier 0: ingest command + labels scaffold; populated when Discord samples arrive.
- **BB-9** Tier 2: ≥100 real malicious sources ingested with paper-derived family labels.
- **BB-10** Baseline tools run end-to-end and appear in the report.
- **BB-11** `bench validate` passes on the full corpus in the bench Docker image.

Notes: BB-8 ships the mechanism (no samples yet). BB-9 depends on external dataset availability; if a source is unreachable offline, the ingest command and mapping still ship and the shortfall is recorded here, not silently dropped.
