# Grok subagent guardrails

Binding rules for every implementation subagent spawned from this repository (Cursor `Task`
tool, `model: cursor-grok-4.6-xhigh-fast`). The orchestrating session embeds this file verbatim in
each wave prompt together with the wave's own owned-file list and acceptance tests. A wave report
that violates any line is rejected and the wave is resumed; the orchestrator does not patch the
work by hand.

Parent documents: `docs/specs/detector.md`, `docs/specs/baybench.md` (Acceptance tables are the
scope SSOT), `.cursor/rules/spec-scope-integrity.mdc`, `.cursor/rules/subagent-model-grok.mdc`.

## Spawn

- `model: cursor-grok-4.6-xhigh-fast`. Never `inherit`, never Fable, never Composer.
- One wave = one subagent = one owned file set. Waves that share a file run sequentially;
  disjoint waves run in parallel.
- Resume the same subagent for fixes; do not spawn a second one on the same files.

## Scope (hard)

- Edit only the files listed under "Owned files" in the prompt. A change needed in any other file
  is written into the report as `CROSS-WAVE: <path>: <what and why>` and left undone.
- Verdict behaviour is frozen unless the prompt says otherwise: no edits to `detector/policy.py`,
  `detector/rules/**`, `detector/analysis/**`, `baybench/scoring.py`, any `labels.yaml`, or
  `cases/**` beyond the fixtures the prompt assigns. If a Tier 0/1/3 verdict changes, the wave has a
  bug, not a finding.
- `docs/specs/detector.md`: append or edit only the sections and DT rows named in the prompt. Never
  delete, renumber, or move an Acceptance row; unfinished rows stay listed as OPEN.
- No drive-by refactors, renames, docstring rewrites, formatting passes, or dependency bumps
  (`slither-analyzer`, `solc-select`, `crytic-compile` pins stay). The diff is the minimum that turns
  the assigned RED tests GREEN.
- Do not touch another session's working-tree files: `public set/`, `reports/**`, `chartkit.py`,
  `scripts/plot_baybench_compare.py`, `docs/research/**`, `docs/main-session-handoff.md`,
  `tools/baseline_slither/tool.py`. Do not `git checkout --`, `git stash`, `git clean`, or
  `git restore` anything.

## Git and process

- No `git commit`, `git tag`, `git push`, branch creation, or `gh release` / `gh workflow run` from
  a subagent. The orchestrator commits after verification.
- Never run `bench run` (the shared `.bench_work/` re-stages mid-run and corrupts a concurrent
  iteration). Allowed: `pytest`, `python -m detector.cli`, `./run.sh`, `docker build`,
  `docker run`, `bench validate` on a copy of a fixture directory.
- Docker mounts use a directory under `$HOME` (for example `~/.dsmoke/<wave>`), not `/tmp`
  (colima cannot bind it). Local images build to `trust404/detector:wip-<wave>`; the orchestrator
  promotes to `:latest`.
- Background jobs longer than 15 minutes (qemu builds, full solc installs) are reported with the
  command, start time, and what will be checked when they finish; do not spin-wait or re-run them.
- Nothing installed outside `.venv`; `scripts/*.sh` must be idempotent and safe to re-run.

## Code rules

- TDD: write the failing test first, show it RED, then implement, then show it GREEN. A test that
  only passes with the fix in place is the definition of done for each bullet in the prompt.
- Imports at module top only; no inline imports.
- Every `match` over a finite string set ends in `case _ as unreachable: raise AssertionError(...)`.
- Determinism: any set or dict walk that can reach output (`results.json`, the stdout array,
  `summary.md`, `CompileResult.note`, the attempt log) is sorted with an explicit key. New env-var
  lookups are read once and passed down, not read inside loops.
- Line numbers are preserved by every rewrite rung.
- stdout hygiene: no `print()` in library code; logging only, to stderr. Submission mode must still
  emit exactly one JSON array on stdout even when a new code path raises.
- Runtime stays offline: no network call, `pip`, `solc-select install`, or download can execute
  after the container `ENTRYPOINT`; network is allowed only in `Dockerfile` build layers,
  `scripts/setup_local.sh`, and the CI workflow.
- Secrets: no tokens in files or logs. Workflows authenticate with `${{ secrets.GITHUB_TOKEN }}`
  and the minimum `permissions:` block; third-party actions limited to `actions/*` and `docker/*`
  pinned to a major version.
- Solidity fixtures: each new `.sol` compiles with the version `pick_solc` selects for it (prove
  with `python -m detector.cli <dir> out/results.json`), carries a `labels.yaml` valid against
  `baybench/schema/case.schema.json`, and the whole `cases/` tree still passes `bench validate`
  (the orchestrator runs it on the tree; the wave runs it on a copy).

## Stop-and-report conditions (do not guess)

- A test outside the owned files goes RED after the change.
- The prompt and `docs/specs/detector.md` disagree, or a needed behaviour is in neither.
- Fixing the assigned bullet requires changing a verdict, a label, a scoring weight, or an
  Acceptance row not named in the prompt.
- Docker or solc binaries behave differently on arm64 than the prompt expects (report the observed
  output; do not add arm64-only branches).

## Report format (mandatory, in this order)

- `FILES`: every path created or modified, one per line.
- `TESTS`: exact `pytest` command(s) run and the final pass/fail/skip counts; the RED-then-GREEN
  evidence for each new test (test name plus the assertion that failed before the fix).
- `SMOKE`: the exact `docker run` / `./run.sh` command lines executed and their stdout verdict
  summary.
- `SPEC`: which sections / DT rows of `docs/specs/detector.md` were touched, quoted.
- `OPEN`: prompt bullets not completed, each with the reason.
- `CROSS-WAVE`: changes needed outside the owned files.
- No prose summary beyond those six headings.
