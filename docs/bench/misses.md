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
| 2026-09-19 | detector | tier1/{BAL_PRIV_MINT,EXIT_AMOUNT_LIMIT,EXIT_GLOBAL_SWITCH,PRIV_ROLE}/ben | Benign (acc. Uncertain) | Uncertain(med_findings) | doctrine | capped mint / bounded window / unpause exists / documented blacklist role → MED by design | wontfix |
| 2026-09-19 | detector | tier3/{usdc_fiattoken,oz_erc20_pausable_ownable,oz_erc20capped_accesscontrol,reflection_token,bancor_smarttoken} | Benign (acc. Uncertain) | Uncertain(med_findings) | doctrine | disclosed/managed privilege (blacklister, pauser, minter cap, issuer) → MED; no HIGH survived | wontfix |
| 2026-09-19 | detector | tier3/lido_ldo_minime | Benign (acc. Uncertain) | Uncertain(external_dependency) | doctrine | `doTransfer` calls settable `controller` → STRUCT_EXTERNAL_GATE MED, as spec'd | wontfix |

Source of the gap list: `coverage.tool_gaps` / `coverage.format_gaps_md`. Tier 3 rows drive verdict-policy tuning (false positives); Tier 0/1/2 rows drive recall.
