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

## Quick start

Docker (the judging form; the image bundles Python, Slither, pinned `solc` binaries and a
vendored OpenZeppelin tree, so `--network none` is safe):

```bash
docker build -f detector/Dockerfile -t trust404/detector:latest .
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
- Bundled `solc`: 0.4.26, 0.5.17, 0.6.12, 0.7.6, 0.8.20 and 0.8.24 through 0.8.37. The
  version is chosen from the file's `pragma` constraints (default 0.8.20); a bounded retry
  ladder relaxes an over-strict pragma or a duplicate SPDX line, and a file that still does
  not compile is reported as `Uncertain(compile_failed)` rather than dropped.
- Exit code is 0 whenever `results.json` was written, even if every file is Uncertain.

### Reading `summary.md`

The report opens with a three-line legend (verdicts, severities, counts) and an overview
table — one row per file, Malicious first — whose `why` column is a plain sentence derived from
the verdict, its reason code and the findings. Each file then gets a section with its findings
grouped HIGH → MED → INFO in tables of `rule | title | where | lines | evidence`; `where` is
`Contract.function`, `lines` are compressed ranges, and `evidence` is the structural reason
plus, when the policy moved a finding away from its catalog severity, a note such as
`downgraded HIGH→MED: role is granted only by a different role`. More than six role-gated
functions are collapsed into one line with a `<details>` block.

## Submission mode (how the judges run it)

The organizers take a **directory**, analyse every `*.sol` **directly under it** (not subdirectories), and score **exactly one JSON array on stdout**. Logs go to stderr. Bench mode above is unchanged: two positional arguments still write `results.json` + `summary.md`.

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

## How a verdict is derived

1. **Findings.** Every rule in the table below is a structural predicate over Slither IR. A
   finding records the contract, the function that carries the evidence, its source lines and
   a reasoning sentence. Identifiers appear in the reasoning for reporting only.
2. **Severities.** Each rule has a catalog base severity: HIGH, MED or INFO.
3. **Discriminators.** Shapes that distinguish disclosed, institutional centralisation from a
   trapdoor can downgrade a HIGH finding to MED (or, for capped fees and foreign-token rescues,
   to INFO): a role that is granted only by a *different* role (USDC's owner → blacklister →
   blacklist), authority that comes from a vendored library (OpenZeppelin `Ownable`,
   `AccessControl`), an issuer-token shape (mint and burn-other both emit events), a constant
   floor or cap, a time-bounded launch window, a privileged un-gate for a pause switch.
   Concealment rules — `OWN_HIDDEN_ROLE`, `OWN_FAKE_RENOUNCE`, `VIEW_CALLER_DEPENDENT`,
   `BAL_TRANSFER_HIDDEN_MINT`, `LEAK_EXEMPT_PATH`, `EXIT_CALLBACK_CYCLE` — are never
   downgraded, and when one of them fires at HIGH no other finding in that contract is
   downgraded either: a disclosed pause switch cannot launder a hidden owner.
4. **Verdict.**
   - any HIGH finding → **Malicious** (`reason` empty);
   - else a transfer path that calls a contract at a settable address → **Uncertain**
     (`external_dependency`): the behaviour cannot be read from this source;
   - else two MED findings from different rule families that both still count (native MED
     rules, not bound- or shape-downgraded ones) → **Malicious** (`escalated:<ids>`), unless a
     benign institutional shape (managed role, library role, issuer token) is present in the
     contract;
   - else any MED → **Uncertain** (`med_findings`);
   - else a Slither exploit-shape check (`arbitrary-send-eth`, `reentrancy-eth`, `suicidal`,
     `controlled-delegatecall`, …) → **Uncertain** (`slither_high`); other Slither High
     results are INFO evidence only;
   - else **Benign**.
   Compile failure, per-file timeout and internal errors yield **Uncertain** with
   `compile_failed`, `timeout` or `analysis_error`.

In one sentence each: **Malicious** is a concealed control, an unbounded privilege over exits
or balances under an unmanaged role, or two independent native privileged controls from
different families. **Uncertain** is privilege that is bounded, disclosed, institutionally
structured, or depends on an external contract — a real third answer that asks for manual
review, not a hedge. **Benign** is nothing privileged touching exits, balances or funds.

### Worked example

- USDC `FiatTokenV1`: `blacklist()` gates `_transfer`, `pause()` halts it, `mint()` creates
  supply. Each would be HIGH in isolation, but the blacklister is appointed by the owner, the
  pauser by the owner, minters by the master minter — every writer is a *managed role*, so all
  three drop to MED and the shape suppresses escalation. Verdict **Uncertain**
  (`med_findings`), never Malicious. The summary lists the twelve role-gated functions and the
  five distinct authority variables so a reviewer can confirm the structure in seconds.
- A token whose `owner` can flip `blacklist[account]` and whose `_transfer` reverts on that
  map: the same gate shape, but the writer is gated by the very role it belongs to. No
  discriminator applies, `EXIT_ADDR_GATE` stays HIGH, verdict **Malicious**.
- A contract with a `private _dev` address compared against `msg.sender` in a modifier and no
  view exposing it: `OWN_HIDDEN_ROLE` at HIGH (concealment), verdict **Malicious** even when
  `owner` is public and renounced.

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
| `BAL_PRIV_MINT` | Privileged mint | HIGH | A privileged function increases a balance or `totalSupply` outside the constructor; MED under a constant cap, a cap set by a separate role, an issuer-token or a managed role. |
| `BAL_PRIV_BURN_OTHER` | Privileged burn of another account | HIGH | A privileged function decreases the balance of an account other than the caller. |
| `BAL_DIRECT_SET` | Privileged direct balance write | HIGH | A privileged function assigns an arbitrary value to a balance entry (reflection-token re-denominations are recognised and dropped). |
| `BAL_TRANSFER_HIDDEN_MINT` | Hidden mint inside transfer | HIGH | On the transfer path more is credited than debited, typically to a recipient other than the stated one. |
| `VIEW_CALLER_DEPENDENT` | Caller-dependent balanceOf or totalSupply | HIGH | `balanceOf` or `totalSupply` returns a value that depends on who is asking, so explorers and wallets are shown a different state than the one that settles. |

#### Family C — Fund extraction

| rule | title | base | what fired |
| --- | --- | --- | --- |
| `FEE_ADDR_MUTABLE` | Settable fee recipient | MED | The recipient of a fee or tax credited on the transfer path is a privileged-writable address. |
| `LEAK_ARBITRARY_TRANSFERFROM` | Privileged transfer from any account without allowance | HIGH | A privileged path debits an arbitrary account without reading its allowance. |
| `LEAK_EXEMPT_PATH` | Privileged transfer path skipping the sender debit | HIGH | A branch on the transfer path taken for a privileged sender credits the recipient while skipping the sender debit. |
| `LEAK_PRIV_SWEEP` | Privileged sweep of custodied funds | HIGH | A privileged function sends the contract's whole ETH balance or its own tokens out; rescue of foreign tokens only is INFO, an ETH sweep from a contract that takes no user deposits is MED. |
| `SLITHER_HIGH_OVERLAY` | Slither high-impact check | INFO | One of Slither's built-in High-impact detectors fired; exploit-shape checks lift Benign to Uncertain, all others are evidence only. |

#### Family D — Control-plane deception

| rule | title | base | what fired |
| --- | --- | --- | --- |
| `OWN_HIDDEN_ROLE` | Undisclosed privileged role | HIGH | An address or map that gates privileged functions is not readable through any public variable or view: a second owner that explorers cannot show. |
| `OWN_FAKE_RENOUNCE` | Renouncement that keeps a privileged role alive | HIGH | A function clears one authority variable while another authority that still gates privileged functions survives, or the renounce writes a new non-zero authority. |
| `OWN_REASSIGN_NONSTD` | Non-standard reassignment of a privileged role | HIGH | An authority variable is written outside the constructor by a function that is not gated by that authority, or set to a literal address or `msg.sender`; one-shot initializers are exempt. |
| `OWN_TX_ORIGIN` | tx.origin-based authorisation | MED | Authorisation compares `tx.origin` instead of `msg.sender`. |

#### Family E — Structural escape hatches

| rule | title | base | what fired |
| --- | --- | --- | --- |
| `STRUCT_EXTERNAL_GATE` | Transfer logic delegated to a settable external contract | MED | The transfer path calls a contract at a privileged-writable address, so its behaviour cannot be determined from this source alone; verdict `Uncertain(external_dependency)`. |
| `STRUCT_DELEGATECALL_SETTABLE` | delegatecall to a settable address | HIGH | A `delegatecall` targets a privileged-writable address outside the standard proxy fallback shape: the role can replace the contract's code. |
| `STRUCT_SELFDESTRUCT` | Reachable selfdestruct | HIGH | `selfdestruct` is reachable from a public or external function. |
| `STRUCT_PROXY_EOA_ADMIN` | Upgradeable proxy with a single-key admin | MED | A proxy fallback delegates to an implementation address whose writer is gated by a single stored address. |

#### Family F — Approval drainers and honeypots

| rule | title | base | what fired |
| --- | --- | --- | --- |
| `DRAIN_APPROVAL_PULL` | Approval drainer pulling caller funds to a third party | HIGH | A non-privileged function pulls tokens from the caller via `transferFrom` or `permit` to an address that is not the caller, with nothing credited back. |
| `HONEYPOT_LEGACY` | Legacy honeypot exit condition | MED | A deposit is accepted but the ETH exit depends on a constructor-set or privileged-set secret, or on a balance comparison that cannot hold. |

#### Family G — Ponzi schemes

| rule | title | base | what fired |
| --- | --- | --- | --- |
| `PONZI_SHAPE` | Ponzi payout shape | MED | ETH is paid to addresses stored by earlier payable calls and the contract has no value source other than `msg.value`. |

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
HoneyBadger corpora, Tier 3 real contracts that look risky but are legitimate (USDC, Bancor
SmartToken, Lido LDO MiniMe, OpenZeppelin Pausable/Capped/Permit wrappers, a reflection token,
a foreign-token rescue), and Tier 0 judge samples when available.

<!-- BENCH NUMBERS: filled by orchestrator -->

| metric | value |
| --- | --- |
| Tier 1 rule recall | — |
| Tier 1 benign HIGH-FP rate | — |
| Tier 3 HIGH-FP rate | — |
| Tier 2 family recall (compiling subset) | — |
| Evidence hit rate (Tier 1 mal) | — |
| Weighted score vs `baseline_slither` / `baseline_keyword` | — |
| Determinism (double run) | — |
| Runtime, Tier 1+3 in Docker | — |

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
- **Uncertain is a real third answer.** Disclosed, bounded or externally dependent privilege is
  reported as Uncertain with a reason code and evidence; it is not a low-confidence Malicious
  and not a Benign with a footnote.
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
| `Dockerfile` | `python:3.11-slim` + Slither + pinned `solc` set + vendored OpenZeppelin; entrypoint `/input → /output/results.json` |
