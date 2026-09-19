# BAYBENCH — detector miss triage log (Phase 4)

The iterate worklist. Each row is a case the detector got wrong (from `bench coverage <tool>` gap list, or a verdict flip in the report). One-line triage per miss; the fix is a predicate change, then rerun `bench run`.

Triage buckets (why the miss happened):
- **placement** — the trigger sits somewhere the detector didn't model (pre-`_transfer` hook, modifier, helper).
- **naming** — name-specific matching missed a name-agnostic role/var (see research §5.1).
- **helper depth** — the gate is reached through N call hops the detector didn't follow (Tokeer-style transfer-path set).
- **external gate** — behavior depends on an unresolved external call → should be `Uncertain(external_dependency)`, not Benign.
- **policy** — finding fired but verdict policy mapped it wrong (e.g. HIGH on a benign OZ-Pausable-with-unpause shape → false positive; needs the §6 discriminator).
- **reporting** — verdict right, output wrong (non-deterministic text, missing evidence fields).
- **compile** — file did not compile with the picked solc; see the retry ladder in `detector/compile.py`.
- **doctrine** — verdict differs from the label's *preferred* value but is inside `accepted_verdicts` by design (concealment doctrine: disclosed/bounded privilege → `Uncertain`). Recorded, not fixed.

Run 1 — 2026-09-19, `bench run detector --no-docker --tier 1 --tier 3` (Tier 0 empty, Tier 2 pending compile ladder): weighted 0.8919, Tier 1 rule recall 1.0, HIGH-FP 0.0 on Tier 1 and Tier 3, evidence hit 1.0, determinism **fail**.

| date | tool | case id | expected | got | bucket | fix | status |
|---|---|---|---|---|---|---|---|
| 2026-09-19 | detector | tier1/DRAIN_APPROVAL_PULL/ben | Benign | Uncertain(slither_high) | policy | Slither `unchecked-transfer` (High impact, code-quality) lifted the verdict. Overlay lift restricted to exploit-shape checks (`reentrancy-eth`, `arbitrary-send-*`, `suicidal`, `controlled-delegatecall`, `delegatecall-loop`, `msg-value-loop`, `unprotected-upgrade`, `protected-vars`, `rtlo`); other High checks stay INFO evidence (`evidence_only`). | fixed (run 2: Benign) |
| 2026-09-19 | detector | tier1/LEAK_PRIV_SWEEP/ben | Benign (acc. Uncertain) | Uncertain(slither_high) | policy | same `unchecked-transfer` lift; `foreign_only` already downgraded LEAK_PRIV_SWEEP to INFO | fixed (run 2: Benign) |
| 2026-09-19 | detector | (all, `--repeat 2`) | deterministic | run0/run1 differ | reporting | overlay reasoning embeds Slither's description with the staging path (`.bench_work/detector/run0/...`); strip path fragments, keep `#lines` | fixed (run 2: determinism pass) |

Run 2 — same tiers after the overlay fix: weighted 0.8981, determinism pass. Remaining `score < 1` rows are all the doctrine rows below.

Tier 2 compile triage (250 of 779 sources did not compile at ingest; first solc error bucketed, then re-measured through the retry ladder):

| date | tool | case id | expected | got | bucket | fix | status |
|---|---|---|---|---|---|---|---|
| 2026-09-19 | detector | tier2/* 42 files, exact pragma (`0.4.25`, `0.8.19`, `0.5.16`, …) | compile | `requires different compiler version` | compile | ladder rung (a): relax pragma, same picked minor; 35 rescued, 6 broken underneath, 1 fixed by constraint-aware pick | fixed (35/42) |
| 2026-09-19 | detector | tier2/* 33 files, no pragma (2017-era) | compile | 0.8.20 parser error | compile | ladder rung (b): no pragma → try 0.4.26, 0.5.17, 0.6.12, 0.7.6; 27 rescued, 6 syntax-broken at every 0.4.x (verified on 0.4.11/0.4.19 too) | fixed (27/33) |
| 2026-09-19 | detector | tier2/crpwarner 7 files, duplicate SPDX | compile | `Multiple SPDX license identifiers` | compile | ladder rung (c) removes the error, but all 7 then hit missing imports (partial flattening) | unfixable |
| 2026-09-19 | detector | tier2/pied-piper 171 `injected_*` | compile | undeclared identifier / modifier without `_` / bool→uint | compile | dataset injection produced non-compiling code; no compiler version accepts it | unfixable (dataset) |
| 2026-09-19 | detector | tier2/* 16 files, missing imports / garbage | compile | `Source "…" not found` | compile | dependency files absent from the dataset | unfixable (dataset) |

Net: 529 → 592 compiling of 779 (76%); the 187 remaining are `Uncertain(compile_failed)` by construction and are labelled `Uncertain` in the corpus.

Run 3 — Tier 2 first pass (779 cases, 590 compiling): weighted 0.7901; family recall A 0.967 / B 0.490 / C 1.0 (n=3) / F 0.031 (322); on the 527 compiling Malicious-labelled files 368 Malicious, 97 Uncertain, 62 Benign. Root-cause pass in progress; rows land here when it reports.

Probe — 2026-09-20, adversarial inputs and project layouts (`/tmp`, not corpus). Found outside the labelled corpus, fixed via spec amendments and harness fixtures:

| date | tool | case id | expected | got | bucket | fix | status |
|---|---|---|---|---|---|---|---|
| 2026-09-20 | detector | probe: `is ERC20, Ownable` + `onlyOwner` blacklist gate (`OzOwnableRug`, now `_harness/oz_ownable_rug`) | Malicious | Uncertain(med_findings) | policy | `library_role` downgraded EXIT_ADDR_GATE because `onlyOwner` is vendored. Provenance is not a benign signal; `library_role` removed from the downgrade table (spec amended) | open |
| 2026-09-20 | detector | probe: OZ `mocks/compound/CompTimelock.sol` | Benign/Uncertain | Malicious (OWN_FAKE_RENOUNCE, OWN_REASSIGN_NONSTD) | policy | `acceptAdmin` (pending → admin handoff) read as fake renounce + nonstandard reassign; `setPendingAdmin` gated by `msg.sender == address(this)` read as unprivileged. Spec: `two_step_handoff` drop discriminator, `eq_self` auth atom; fixtures `_harness/timelock_self_call`, `_harness/oz_ownable2step_token` | open |
| 2026-09-20 | detector | probe: Foundry layout, `import "../lib/oz/…"` | compiles | Uncertain(compile_failed) | compile | `--allow-paths` only covered the file's parent; spec: allow the whole input root, honour `remappings.txt`/`foundry.toml`, auto-map `node_modules/` and `lib/<pkg>/` | open |
| 2026-09-20 | detector | probe: Foundry/Hardhat layout, 263 vendored OZ files | not analysed as targets | 187 compile_failed + 75 Benign + 1 Malicious rows | reporting | dependency packages (`node_modules/`, package-shaped `lib/<pkg>/`) excluded from targets, count reported | open |
| 2026-09-20 | detector | probe: UTF-8 BOM prefix | compiles | Uncertain(compile_failed) | compile | BOM strip rung in the retry ladder | open |
| 2026-09-20 | detector | probe: CRLF, empty file, comment-only, interface-only, library-only, nested dirs, paths with spaces, 3000-state-var file, infinite assembly loop, non-.sol files, two pragmas, wide pragma | sane | sane (no crash, no hang, 5 s total) | — | none needed | ok |
| 2026-09-20 | detector | probe: `address o;` (internal, no getter) gating a setter of an unused mapping | ? | Malicious (OWN_HIDDEN_ROLE) | doctrine | consistent with `tier1/OWN_HIDDEN_ROLE/mal` (hidden role with no consumer is labelled Malicious). Whether a hidden role with **no impact** should be MED is a doctrine question for the owner; not changed | question |
| 2026-09-19 | detector | tier1/{BAL_PRIV_MINT,EXIT_AMOUNT_LIMIT,EXIT_GLOBAL_SWITCH,PRIV_ROLE}/ben | Benign (acc. Uncertain) | Uncertain(med_findings) | doctrine | capped mint / bounded window / unpause exists / documented blacklist role → MED by design | wontfix |
| 2026-09-19 | detector | tier3/{usdc_fiattoken,oz_erc20_pausable_ownable,oz_erc20capped_accesscontrol,reflection_token,bancor_smarttoken} | Benign (acc. Uncertain) | Uncertain(med_findings) | doctrine | disclosed/managed privilege (blacklister, pauser, minter cap, issuer) → MED; no HIGH survived | wontfix |
| 2026-09-19 | detector | tier3/lido_ldo_minime | Benign (acc. Uncertain) | Uncertain(external_dependency) | doctrine | `doTransfer` calls settable `controller` → STRUCT_EXTERNAL_GATE MED, as spec'd | wontfix |

Source of the gap list: `coverage.tool_gaps` / `coverage.format_gaps_md`. Tier 3 rows drive verdict-policy tuning (false positives); Tier 0/1/2 rows drive recall.
