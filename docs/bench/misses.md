# BAYBENCH — detector miss triage log (Phase 4)

The iterate worklist. Each row is a case the detector got wrong (from `bench coverage <tool>` gap list, or a verdict flip in the report). One-line triage per miss; the fix is a predicate change, then rerun `bench run`.

Triage buckets (why the miss happened):
- **placement** — the trigger sits somewhere the detector didn't model (pre-`_transfer` hook, modifier, helper).
- **naming** — name-specific matching missed a name-agnostic role/var (see research §5.1).
- **helper depth** — the gate is reached through N call hops the detector didn't follow (Tokeer-style transfer-path set).
- **external gate** — behavior depends on an unresolved external call → should be `Uncertain(external_dependency)`, not Benign.
- **policy** — finding fired but verdict policy mapped it wrong (e.g. HIGH on a benign OZ-Pausable-with-unpause shape → false positive; needs the §6 discriminator).

| date | tool | case id | expected | got | bucket | fix | status |
|---|---|---|---|---|---|---|---|
| _(populated after the first detector run)_ | | | | | | | |

Source of the gap list: `coverage.tool_gaps` / `coverage.format_gaps_md`. Tier 3 rows drive verdict-policy tuning (false positives); Tier 0/1/2 rows drive recall.
