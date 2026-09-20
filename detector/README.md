# detector — offline static detector for intentionally malicious ERC-20 / DeFi contracts

## What it is

`detector` reads a directory of Solidity sources and, for every `.sol` file, answers
`Malicious | Uncertain | Benign` with evidence. It targets intentional malice in token
contracts — rug pulls, honeypots, trapdoors, hidden owners, approval drainers — not accidental
bugs. Analysis runs on Slither's intermediate representation only: it models who can call
what (privilege), which state those callers can write, and whether that state gates or feeds
the transfer path, the balance mapping, or an ETH/token exit. It never reads identifier names
(a blacklist called `_isBot` and a switch called `i` are found the same way), it needs no
network, and the same input always produces byte-identical output.

## Submission mode (how the judges run it)

The organizers take a **directory**, analyse every `*.sol` **directly under it** (not subdirectories), and score **exactly one JSON array on stdout**. Logs go to stderr. Bench mode below is unchanged: two positional arguments still write `results.json` + `summary.md`.

```bash
./run.sh ./cases > out.json
docker run --rm --network none \
  -v "$PWD/cases":/input:ro trust404/detector:latest > out.json
check-jsonschema --schemafile detector/schema/judge.schema.json out.json
```

`./run.sh` uses `trust404/detector:latest` when that image is present; set `DETECTOR_NO_DOCKER=1` to force the local venv (`python -m detector.cli <dir>`). Docker `ENTRYPOINT` is `python -m detector.docker_entry`: a writable `/output` mount selects bench mode, otherwise submission mode.

Each array element is one input basename:

```json
{
  "file": "P3_Honeypot_sol.sol",
  "verdict": "MALICIOUS",
  "reasons": [
    "Settable address gate on transfers — setWhitelist writes whitelist; impact transfer require; An address-to-bool map that a privileged role can write is read in a require/revert on the transfer path: the role can freeze individual holders.",
    "Role-gated function — setWhitelist gated by owner (eq_state_address); A function is reachable only when msg.sender or tx.origin matches a stored address or an address-to-bool map; evidence for the other rules, never a verdict on its own."
  ],
  "evidence": [
    { "function": "setWhitelist", "line": 32 },
    { "function": "transfer", "line": 37 },
    { "function": "setWhitelist", "line": 29 }
  ],
  "risk_level": "HIGH",
  "risk_type": "BACKDOOR",
  "confidence": 0.8
}
```

```json
{
  "file": "P4_CappedMint_sol.sol",
  "verdict": "BENIGN",
  "reasons": [
    "privileged controls present but every one is bounded in code or off the transfer path; no unbounded privileged path to user assets",
    "Role-gated function — mint gated by owner (eq_state_address); A function is reachable only when msg.sender or tx.origin matches a stored address or an address-to-bool map; evidence for the other rules, never a verdict on its own.",
    "Privileged mint — mint increases bound balance or supply; A privileged function increases a balance or totalSupply outside the constructor: the role can print tokens."
  ],
  "evidence": [
    { "function": "mint", "line": 22 },
    { "function": "mint", "line": 28 }
  ],
  "risk_level": "LOW",
  "risk_type": "CENTRALIZATION",
  "confidence": 0.7
}
```

`verdict` is upper-case `MALICIOUS|BENIGN|UNCERTAIN`. `MALICIOUS` always carries at least one `evidence` item whose `line` is inside the file. A directory with no top-level `.sol` files prints `[]` (the grader scores an empty array as the whole submission 0; there is nothing else we can emit).

**Budget / timeout.** The grader kills the process at 10 minutes. Submission mode keeps an 8-minute wall budget (`--budget`, default 480 s) and the usual per-file `--timeout` (default 120 s). When the budget is exhausted, remaining files are emitted as `UNCERTAIN` with reason `global time budget exhausted before this file was analysed` and the array is still printed (exit 0). A file that fails to parse or compile is `UNCERTAIN` and the batch continues.

**stdout / stderr.** After argument parsing, submission mode duplicates fd 1, points fd 1 and `sys.stdout` at stderr, and writes the JSON array only to the saved stdout descriptor. solc / crytic-compile / Slither / worker logs therefore cannot corrupt the array. `DETECTOR_LOG_LEVEL` (default `INFO`) controls verbosity on stderr.

## Quick start

Docker (the image bundles Python, Slither, pinned `solc` binaries and a vendored
OpenZeppelin tree, so `--network none` is safe). Submission form first:

```bash
docker build -f detector/Dockerfile -t trust404/detector:latest .
mkdir -p in && cp path/to/*.sol in/
docker run --rm --network none -e DETECTOR_MODE=submission \
  -v "$PWD/in:/input:ro" \
  trust404/detector:latest > out.json
```

BAYBENCH bench mode (writes results.json + summary.md; prints nothing on stdout) — not for judging:

```bash
mkdir -p in out && cp path/to/*.sol in/
docker run --rm --network none \
  -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  trust404/detector:latest
```

Local (needs `pip install -r detector/requirements.txt`, `solc-select install` of the versions
below, and `vendor/openzeppelin-contracts` or `DETECTOR_OZ_DIR` pointing at an OpenZeppelin
checkout):

```bash
PYTHONPATH=. python -m detector.cli in out/results.json [--timeout 120] [--no-summary]
```

- Input: any directory tree; every `*.sol` under it is analysed (recursively, sorted by path).
  A file is compiled in isolation with its relative imports and `@openzeppelin/` remapped.
- Output: `out/results.json` — the Track 1 submission format, validated against
  `detector/schema/result.schema.json` before it is written — and `out/summary.md`, the
  human-readable report described below.
- Bundled `solc` (`detector/solc_versions.txt` is the single source of truth, read by the
  Dockerfile and `scripts/setup_local.sh`): 0.4.24–0.4.26, 0.5.16–0.5.17, 0.6.6, 0.6.12,
  0.7.6, and every 0.8.0 through 0.8.37 — 46 binaries. The
  version is chosen from the file's `pragma` constraints (default 0.8.20); a bounded retry
  ladder relaxes an over-strict pragma or a duplicate SPDX line, and a file that still does
  not compile is reported as `Uncertain(compile_failed)` rather than dropped.
- OpenZeppelin v4 and v5 trees are vendored (`vendor/openzeppelin-contracts`,
  `vendor/openzeppelin-contracts-v5`) and chosen per file.
- Exit code is 0 whenever `results.json` was written, even if every file is Uncertain.

### Reading `summary.md`

The report opens with a three-line legend (verdicts, severities, counts) and an overview
table — one row per file, Malicious first — whose `why` column is a plain sentence derived from
the verdict, its reason code and the findings. Each file then gets a section with its findings
grouped HIGH → MED → INFO in tables of `rule | title | where | lines | evidence`; `where` is
`Contract.function`, `lines` are compressed ranges, and `evidence` is the structural reason
plus, when a bounding discriminator moved a finding to INFO, a note such as
`downgraded HIGH→INFO: supply is capped by a constant`. More than six role-gated
functions are collapsed into one line with a `<details>` block.

## Environment variables

- `DETECTOR_IMAGE` — image `run.sh` prefers; default `trust404/detector:latest`. If that tag is absent locally, `run.sh` also tries `ghcr.io/sdh2222/trust404-detector:latest` (local inspect only; never pulls).
- `DETECTOR_NO_DOCKER` — if set, skip Docker and use a local interpreter.
- `DETECTOR_PYTHON` — interpreter for the local path; if unset, `${ROOT}/.venv/bin/python` when executable, else `python3`.
- `DETECTOR_MODE` — `submission` or `bench`; docker_entry override. Unset = auto-detect (writable `/output` → bench, otherwise submission).
- `DETECTOR_SOLC_ARTIFACTS` — solc artifact root (solc-select layout). Unset = default solc-select locations.
- `DETECTOR_OZ_DIR` — OpenZeppelin v4 tree; default `vendor/openzeppelin-contracts`.
- `DETECTOR_OZ_V5_DIR` — OpenZeppelin v5 tree; default `vendor/openzeppelin-contracts-v5`.
- `DETECTOR_SCRATCH_DIR` — scratch directory for per-file compile copies. Unset = a temporary directory for the batch.
- `DETECTOR_LOG_LEVEL` — logging level on stderr; default `INFO`.
- `DETECTOR_VALIDATE` — if `1`, validate the stdout array against the judge schema before printing.

## How a verdict is derived

Decisive mode (Phase 5). Grading is +1 correct / 0 `UNCERTAIN` / −1 wrong, so a finding set
we fully understand must resolve to **Malicious** or **Benign**. `UNCERTAIN` is an abstain,
not a hedge.

1. **Findings.** Every rule in the table below is a structural predicate over Slither IR. A
   finding records the contract, the function that carries the evidence, its source lines and
   a reasoning sentence. Identifiers appear in the reasoning for reporting only.
2. **Severities.** Each rule has a catalog base severity: HIGH, MED or INFO. Policy then
   sets `severity ∈ {HIGH, INFO}` for the verdict and keeps `base_severity` plus the matched
   discriminator names for reporting.
3. **Bounding discriminators** (the power is limited by code or is not a user-asset path →
   INFO, evidence only): `constant_cap`, `fee_cap`, `constant_floor`, `bounded_window`,
   `ungate_exists` (only when there is no `priv_bypass`), `no_custody`, `foreign_only`,
   `two_step_handoff`, `one_shot_initializer`, `representation_switch`. `priv_bypass`
   (owner-exempt gate) cancels `ungate_exists` / `constant_floor` / `bounded_window`: an
   asymmetric restriction is the organizers' rule-1 MALICIOUS.
4. **Governance discriminators** (who holds the power, not how much → recorded, **no
   downgrade**): `managed_role`, `issuer_token`, `role_separated_cap`. They annotate the
   reason text and can set `risk_type: CENTRALIZATION` on a BENIGN report; they never change
   the verdict. Provenance (`library_role`) is not a signal.
5. **Counting finding.** A finding whose rule is HIGH-base, **or** one of the decisive MED
   rules {`HONEYPOT_LEGACY`, `PONZI_SHAPE`, `STRUCT_PROXY_EOA_ADMIN`, `OWN_TX_ORIGIN`,
   `EXIT_TIME_GATE` only with `no_expiry`}, **or** a `SLITHER_HIGH_OVERLAY` exploit-shape
   check (`reentrancy-eth`, `arbitrary-send-eth`, `arbitrary-send-erc20`,
   `arbitrary-send-erc20-permit`, `suicidal`, `controlled-delegatecall`,
   `unprotected-upgrade`), **and** no bounding discriminator applies to it.
6. **Verdict.**
   - any counting finding → **Malicious** (`reason` empty; the HIGH rule ids are the reason);
   - else `STRUCT_EXTERNAL_GATE` present → **Uncertain** (`external_dependency`): behaviour
     lives in code we cannot see (the one analytic abstain);
   - else **Benign**. INFO findings (bounded controls, `PRIV_ROLE`, non-exploit Slither
     checks with `evidence_only`, `FEE_ADDR_MUTABLE`) stay on the report as evidence.
   Engine / submission abstains: `compile_failed`, `timeout`, `analysis_error`, and
   `budget_exhausted` in submission mode.

In one sentence each: **Malicious** is an unbounded privileged path to user assets, an
asymmetric exit restriction, a concealment / escape hatch, or an exploit-shaped Slither
check. **Benign** is nothing privileged touching exits, balances or funds — or every such
control is bounded in code. **Uncertain** is only used when we could not finish the analysis
or the transfer path calls a settable external contract.

### Worked example

- USDC `FiatTokenV1` (`cases/tier3_benign_risky/usdc_fiattoken`): `blacklist()` gates
  `_transfer` and `mint()` is bounded only by a `minterAllowed` the master minter can raise.
  Those writers are *managed roles*, but governance is not a code bound — the notes appear
  in `reasons` as `(governance: …)` and the findings stay HIGH. Verdict **Malicious**.
- `P4_CappedMint` (`cases/tier0_judge/P4_CappedMint_sol`): `onlyOwner mint` increases
  supply, but every writer is bounded by a constant/immutable cap (`constant_cap`).
  `BAL_PRIV_MINT` is INFO; the reason line carries `(bounded: cap is a constant/immutable)`.
  Verdict **Benign**.
- A token whose `owner` can flip `blacklist[account]` and whose `_transfer` reverts on that
  map, with no cap and no other role: `EXIT_ADDR_GATE` stays HIGH, verdict **Malicious**.
- A contract with a `private _dev` address compared against `msg.sender` in a modifier and no
  view exposing it: `OWN_HIDDEN_ROLE` at HIGH, verdict **Malicious** even when `owner` is
  public and renounced.

## What it detects

Twenty-nine rules in seven families; base severity from `baybench/catalog.yaml`, titles from
`detector/describe.py` (a test keeps this table, the catalog and the code in sync).

#### Family A — Exit gating

| rule | title | base | what fired |
| --- | --- | --- | --- |
| `PRIV_ROLE` | Role-gated function | INFO | A function is reachable only when `msg.sender` or `tx.origin` matches a stored address or an address-to-bool map; evidence for the other rules, never a verdict on its own. |
| `EXIT_ADDR_GATE` | Settable address gate on transfers | HIGH | An address-to-bool map that a privileged role can write is read in a require/revert on the transfer path: the role can freeze individual holders. |
| `EXIT_GLOBAL_SWITCH` | Privileged global transfer switch | HIGH | A privileged-writable bool gates the transfer path: the role can halt all transfers. |
| `EXIT_AMOUNT_LIMIT` | Privileged transfer amount limit | HIGH | A privileged-writable number is compared with the transfer amount in a require: the role can shrink the limit until nobody can exit. |
| `EXIT_TIME_GATE` | Privileged time gate on transfers | MED | A privileged-writable timestamp or block number gates the transfer path; HIGH when no writer bounds it in time. |
| `EXIT_SELL_ONLY` | Sell-only gate via a settable address | HIGH | The transfer path reverts only when the recipient or sender equals a settable address (the DEX pair): buys succeed, sells fail. |
| `EXIT_CALLBACK_CYCLE` | Callback cycle re-entering a transfer gate | HIGH | The transfer path calls out to a settable address and then compares an amount-dependent value with privileged state, so sells can be made to revert without listing the seller. |
| `FEE_UNBOUNDED` | Uncapped privileged fee | HIGH | A privileged-writable number feeds the transferred or fee amount with no cap; INFO when every writer caps it at 25 percent or less. |

#### Family B — Balance tamper

| rule | title | base | what fired |
| --- | --- | --- | --- |
| `BAL_PRIV_MINT` | Privileged mint | HIGH | A privileged function increases a balance or `totalSupply` outside the constructor; INFO under a bounding discriminator (`constant_cap`); governance notes (`managed_role`, `issuer_token`, `role_separated_cap`) stay HIGH and only annotate the reason. |
| `BAL_PRIV_BURN_OTHER` | Privileged burn of another account | HIGH | A privileged function decreases the balance of an account other than the caller. |
| `BAL_DIRECT_SET` | Privileged direct balance write | HIGH | A privileged function assigns an arbitrary value to a balance entry (reflection-token re-denominations are recognised and dropped). |
| `BAL_TRANSFER_HIDDEN_MINT` | Hidden mint inside transfer | HIGH | On the transfer path more is credited than debited, typically to a recipient other than the stated one. |
| `VIEW_CALLER_DEPENDENT` | Caller-dependent balanceOf or totalSupply | HIGH | `balanceOf` or `totalSupply` returns a value that depends on who is asking, so explorers and wallets are shown a different state than the one that settles. |

#### Family C — Fund extraction

| rule | title | base | what fired |
| --- | --- | --- | --- |
| `FEE_ADDR_MUTABLE` | Settable fee recipient | MED | The recipient of a fee or tax credited on the transfer path is a privileged-writable address; INFO always (the amount is `FEE_UNBOUNDED`'s job). |
| `LEAK_ARBITRARY_TRANSFERFROM` | Privileged transfer from any account without allowance | HIGH | A privileged path debits an arbitrary account without reading its allowance. |
| `LEAK_EXEMPT_PATH` | Privileged transfer path skipping the sender debit | HIGH | A branch on the transfer path taken for a privileged sender credits the recipient while skipping the sender debit. |
| `LEAK_PRIV_SWEEP` | Privileged sweep of custodied funds | HIGH | A privileged function sends the contract's whole ETH balance or its own tokens out; `foreign_only` / `no_custody` bound it to INFO. |
| `SLITHER_HIGH_OVERLAY` | Slither high-impact check | INFO | One of Slither's built-in High-impact detectors fired; exploit-shape checks count as HIGH (MALICIOUS), all others are evidence only. |

#### Family D — Control-plane deception

| rule | title | base | what fired |
| --- | --- | --- | --- |
| `OWN_HIDDEN_ROLE` | Undisclosed privileged role | HIGH | An address or map that gates privileged functions is not readable through any public variable or view: a second owner that explorers cannot show. |
| `OWN_FAKE_RENOUNCE` | Renouncement that keeps a privileged role alive | HIGH | A function clears one authority variable while another authority that still gates privileged functions survives, or the renounce writes a new non-zero authority. |
| `OWN_REASSIGN_NONSTD` | Non-standard reassignment of a privileged role | HIGH | An authority variable is written outside the constructor by a function that is not gated by that authority, or set to a literal address or `msg.sender`; one-shot initializers are exempt. |
| `OWN_TX_ORIGIN` | tx.origin-based authorisation | MED | Authorisation compares `tx.origin` instead of `msg.sender`; a decisive MED rule (counts as MALICIOUS). |

#### Family E — Structural escape hatches

| rule | title | base | what fired |
| --- | --- | --- | --- |
| `STRUCT_EXTERNAL_GATE` | Transfer logic delegated to a settable external contract | MED | The transfer path calls a contract at a privileged-writable address; the one analytic abstain — verdict `Uncertain(external_dependency)` unless a counting finding is also present. |
| `STRUCT_DELEGATECALL_SETTABLE` | delegatecall to a settable address | HIGH | A `delegatecall` targets a privileged-writable address outside the standard proxy fallback shape: the role can replace the contract's code. |
| `STRUCT_SELFDESTRUCT` | Reachable selfdestruct | HIGH | `selfdestruct` is reachable from a public or external function. |
| `STRUCT_PROXY_EOA_ADMIN` | Upgradeable proxy with a single-key admin | MED | A proxy fallback delegates to an implementation address whose writer is gated by a single stored address; a decisive MED rule (counts as MALICIOUS). |

#### Family F — Approval drainers and honeypots

| rule | title | base | what fired |
| --- | --- | --- | --- |
| `DRAIN_APPROVAL_PULL` | Approval drainer pulling caller funds to a third party | HIGH | A non-privileged function pulls tokens from the caller via `transferFrom` or `permit` to an address that is not the caller, with nothing credited back. |
| `HONEYPOT_LEGACY` | Legacy honeypot exit condition | MED | A deposit is accepted but the ETH exit depends on a constructor-set or privileged-set secret, or on a balance comparison that cannot hold; a decisive MED rule (counts as MALICIOUS). |

#### Family G — Ponzi schemes

| rule | title | base | what fired |
| --- | --- | --- | --- |
| `PONZI_SHAPE` | Ponzi payout shape | MED | ETH is paid to addresses stored by earlier payable calls and the contract has no value source other than `msg.value`; a decisive MED rule (counts as MALICIOUS). |

## Design guarantees

- **Name-agnostic.** No rule compares a user identifier against a word list; the only
  identifier-shaped anchors are protocol constants (the ERC-20 ABI signatures, `msg.sender`,
  `tx.origin`, `block.timestamp`, `selfdestruct`, `delegatecall`, …). A test alpha-renames every
  contract, function, modifier, variable and event in the fixtures and asserts the same rule
  ids fire; another test greps the rule and analysis modules for quoted identifier words.
- **Deterministic.** Sorted file walk, sorted contract and function iteration, canonically
  sorted findings, no timestamps or absolute paths in either output. Repeat runs are
  byte-identical (checked across `PYTHONHASHSEED` values and by the bench's double run).
- **Offline.** No network access, no chain queries, no hosted models. `solc` binaries are
  pinned and installed at image build time; OpenZeppelin is vendored.
- **Robust.** Every file is analysed in its own subprocess with a timeout (default 120 s).
  Compile failure → `Uncertain(compile_failed)`, timeout → `Uncertain(timeout)`, any other
  exception → `Uncertain(analysis_error)`. A bad file never aborts the batch and the process
  never exits non-zero once `results.json` exists.
- **Standalone.** `detector/` imports nothing from the bench; it vendors the result schema and
  its own `solc` selection.

## Evaluation

Measured with BAYBENCH (`bench run detector`): Tier 1 hand-written malicious/benign twins per
rule id, Tier 2 real-world rug pulls and honeypots from the Pied-Piper, CRPWarner and
HoneyBadger corpora, Tier 3 contracts that look privileged (the five bounded OpenZeppelin /
reflection / rescue fixtures must stay Benign; USDC FiatToken, Bancor SmartToken and Lido
LDO MiniMe are preferred Malicious under decisive mode), and Tier 0 judge samples.

<!-- BENCH NUMBERS: filled by orchestrator, 2026-09-20, image e0a089bddd3a built from the hardening waves (solc SSOT, OZ v4/v5, any-uid runtime); all-tier `bench run detector --repeat 2` in Docker `--network none` (reports/detector/) -->

| metric | value |
| --- | --- |
| Weighted score, all tiers (Tier 0 · 1 · 2 · 3 = 1.0 · 1.0 · 0.8909 · 0.9688) | **0.9714** |
| Tier 0 (organizers' public set) | 5/5 exact, `reasons` on every file |
| Tier 1 rule recall (71 cases incl. the OZ v4/v5 harness quartet, every `mal` twin fires its rule id) | 1.0 |
| Tier 1 benign HIGH-FP rate | 0.0 |
| Tier 3 HIGH-FP rate (five bounded fixtures Benign; USDC/Bancor Malicious; Lido `external_dependency`) | 0.0 |
| Tier 2 family recall, compiling subset (A 0.978 · B 0.867 · C 1.0 · F 0.910; 779 files, 190 `compile_failed`) | 0.9146 |
| Evidence hit rate (Tier 1 mal, `expected_functions`) | 1.0 |
| `Uncertain` reasons observed across all tiers | `compile_failed`, `external_dependency` only |
| Weighted score, Tier 1+3, vs `baseline_slither` / `baseline_keyword` | 0.9844 vs 0.5789 / 0.4222 |
| Determinism (`--repeat 2`, 864 files, byte-identical `results.json`) | pass |
| Runtime, Tier 1+3 in Docker (79 files) / all tiers (864 files), arm64 host under qemu | 35 s / 6.4 min per repeat on an idle host; 10.2 min with the host under load (same-file A/B of the hardening waves against `799361b`: +12 %) |

Per-miss triage lives in `docs/bench/misses.md`; the corpus labels and weights are in `docs/specs/baybench.md`.

## Limitations

- **Source only.** Bytecode is not analysed; an unverified contract cannot be judged here.
- **Compile-dependent.** A file that no bundled `solc` accepts is `Uncertain(compile_failed)`;
  very old 0.4.x sources are the usual case.
- **Storage-pointer writes are not attributed.** A MiniMe-style
  `updateValueAtNow(balances[x], v)` is not seen as a write to the balance mapping, so
  Family B rules can miss on that shape.
- **Bounded interprocedural depth.** Transfer-path closure follows modifiers and internal or
  library calls inside the compilation unit; behaviour behind an external call is, by design,
  `Uncertain(external_dependency)` rather than guessed.
- **Uncertain is a real third answer.** It is used only when analysis could not finish
  (`compile_failed`, `timeout`, `analysis_error`, `budget_exhausted`) or the transfer path
  calls a settable external contract (`external_dependency`). Bounded privilege is Benign;
  disclosed-but-unbounded governance is Malicious with a governance note.
- **Static only.** No simulation or fork; behaviour that depends on runtime state (an
  implementation address, an oracle) is reported structurally, not exercised.

## Layout of the package

| path | role |
| --- | --- |
| `cli.py` | `python -m detector.cli <input_dir> <results.json>`; writes `summary.md` beside it |
| `engine.py` | per-file worker subprocess with timeout, batch loop, `FileResult` assembly |
| `compile.py` | `solc` selection from pragma constraints, retry ladder, OpenZeppelin remap, Slither construction |
| `model.py` | `Finding` / `FileResult` dataclasses, canonical sort, schema-validated `results.json` writer |
| `policy.py` | discriminator table, severity adjustment, verdict and reason |
| `summary.py` | deterministic `summary.md` renderer |
| `describe.py` | human titles and one-line explanations for rule ids, families, discriminators and reason codes |
| `analysis/` | shared predicates: privilege (auth atoms), transfer path, balance binding, role shapes, ETH flows |
| `rules/` | one callable per rule id, grouped by family; `overlay.py` wraps Slither's High-impact detectors |
| `schema/result.schema.json` | vendored copy of the Track 1 result schema |
| `Dockerfile` | `python:3.11-slim` + Slither + pinned `solc` set + vendored OpenZeppelin; entrypoint `python -m detector.docker_entry` |
