# Track 1 Detector — Spec (SSOT for Phase 4)

Offline static detector for TRUST404 Track 1 (intentional malice: rug pulls, honeypots, trapdoors). This document is the single source of truth for Phase 4 scope. Patterns and predicates come from [../research/track1-malice-patterns.md](../research/track1-malice-patterns.md) (§4 hiding places, §5 predicate triple, §6 lookalikes, §7 rule table); the bench contract from [baybench.md](baybench.md); rule IDs from [../../baybench/catalog.yaml](../../baybench/catalog.yaml). Verified against the corpus by `bench run detector`.

## Purpose

Given a directory of `.sol` files, emit one schema-valid `results.json` (the Track 1 submission format) plus a human-readable `summary.md`, with a verdict per file (`Malicious | Uncertain | Benign`) and evidence-bearing findings (contract, function, lines, reasoning), derived from **logic flow and permission structure**, never from identifier names.

## Non-negotiable constraints

- Static only, on Slither IR. No simulation, no chain access, no network, no hosted models. Must run under `docker run --rm --network none`.
- Deterministic: same input → byte-identical canonical output.
- A bad file never aborts the batch: compile failure → `Uncertain(compile_failed)`; per-file timeout → `Uncertain(timeout)`; any analysis exception → `Uncertain(analysis_error)`.
- Standalone: `detector/` does not import `baybench`. It vendors what it needs (schema copy, `pick_solc`).
- **Name-agnostic (judging criterion).** No rule or analysis module compares user identifiers (state var, function, modifier, contract, event, parameter names) against a word list. The only identifier-shaped anchors allowed are *protocol constants*: ERC-20 ABI signatures (`transfer(address,uint256)`, `transferFrom(address,address,uint256)`, `approve(address,uint256)`, `balanceOf(address)`, `totalSupply()`, `allowance(address,address)`; ERC-2612 `permit`), and Solidity builtins (`msg.sender`, `tx.origin`, `msg.value`, `block.timestamp`, `block.number`, `address(this).balance`, `selfdestruct`, `delegatecall`, `require`/`assert`/`revert`). DT-8 enforces this.

## Layout

```
detector/                      Python package = the tool (flat; ships standalone)
  __init__.py                  TOOL_NAME="detector", TOOL_VERSION
  cli.py                       python -m detector.cli <input_dir> <results.json>  (same argv contract as tools/*)
  compile.py                   pick_solc, solc binary lookup, OZ remap, Slither ctor
  engine.py                    per-file worker (subprocess + timeout), batch loop, file→results
  model.py                     Finding / FileResult dataclasses; results.json writer; canonical sort
  summary.py                   summary.md renderer
  policy.py                    severity adjustment (discriminators) + verdict + reason + escalation
  analysis/
    __init__.py
    context.py                 ContractContext: bindings + caches shared by all rules for one contract
    privilege.py               auth atoms, privileged functions, privileged writes, privileged-writable vars, role exposure
    transfer_path.py           ERC-20 roots, path closure, end nodes, gate reads, amount dependency
    balances.py                balance / totalSupply / allowance binding; debit / credit / set classification; arith_kind
    roles.py                   contract-level shapes: issuer_token, managed_role, library_role, one-shot initializer, custody
    flows.py                   ETH-flow helpers: value sends, whole-pot sends, payable inflow, external call targets
  rules/
    __init__.py                RULES registry: list of rule callables, ordered
    base.py                    Rule protocol, helpers to build Findings with lines/reasoning
    family_a_exit.py           EXIT_ADDR_GATE EXIT_GLOBAL_SWITCH EXIT_AMOUNT_LIMIT EXIT_TIME_GATE EXIT_SELL_ONLY EXIT_CALLBACK_CYCLE FEE_UNBOUNDED
    family_b_balance.py        BAL_PRIV_MINT BAL_PRIV_BURN_OTHER BAL_DIRECT_SET BAL_TRANSFER_HIDDEN_MINT VIEW_CALLER_DEPENDENT
    family_c_leak.py           FEE_ADDR_MUTABLE LEAK_ARBITRARY_TRANSFERFROM LEAK_EXEMPT_PATH LEAK_PRIV_SWEEP
    family_d_owner.py          PRIV_ROLE OWN_HIDDEN_ROLE OWN_FAKE_RENOUNCE OWN_REASSIGN_NONSTD OWN_TX_ORIGIN
    family_e_struct.py         STRUCT_EXTERNAL_GATE STRUCT_DELEGATECALL_SETTABLE STRUCT_SELFDESTRUCT STRUCT_PROXY_EOA_ADMIN
    family_fg.py               DRAIN_APPROVAL_PULL HONEYPOT_LEGACY PONZI_SHAPE
    overlay.py                 SLITHER_HIGH_OVERLAY (Slither built-in High-impact detectors → INFO)
  schema/result.schema.json    vendored copy of baybench/schema/result.schema.json (byte-identical; test asserts)
  requirements.txt             slither-analyzer==0.11.6, solc-select
  Dockerfile                   build context = repo root: `docker build -f detector/Dockerfile -t trust404/detector .`
  README.md                    judge-facing (DT-11)
tests/detector/                pytest; fixtures = the real Tier 1 cases under cases/tier1_pairs (solc 0.8.20 local)
reports/detector/              committed bench output (DT-12)
docs/bench/misses.md           triage log (DT-12)
```

Registry entry in `baybench/tools.yaml`:

```yaml
  - name: detector
    image: trust404/detector:latest
    cmd: ".venv/bin/python -m detector.cli {input} {output}/results.json"
```

## Data flow

```
/input/**/*.sol ──► engine: for each file (sorted) ──► worker subprocess (timeout)
                       │                                  │
                       │                                  ├─ compile.py: pick_solc(pragma) → Slither(file, solc, remaps)
                       │                                  │      fail → FileResult(Uncertain, compile_failed)
                       │                                  ├─ for each target contract (declared in this file, not interface/library/abstract):
                       │                                  │      ContractContext(bindings) → rules/* → raw Findings
                       │                                  ├─ overlay.py: Slither High detectors → INFO findings
                       │                                  └─ policy.py: adjust severities → verdict + reason
                       │                                  timeout → FileResult(Uncertain, timeout); exception → Uncertain(analysis_error)
                       └──► model.write_results(results.json)  +  summary.write_summary(summary.md)
```

One result per `.sol` file under the input root (recursive, sorted by relative POSIX path). A file is analysed in isolation with its imports resolved (relative imports and `@openzeppelin/` via remap). Findings are attributed to a file only for contracts *declared in that file*; inherited functions declared elsewhere are analysed as part of the target contract but their provenance is recorded (used by `library_role`).

## Module interfaces

### `compile.py`

- `INSTALLED_SOLC = ("0.4.26", "0.5.17", "0.6.12", "0.7.6", "0.8.20", "0.8.24", …, "0.8.37")` (contiguous 0.8.24..0.8.37 so exact recent pragmas resolve), `DEFAULT_SOLC = "0.8.20"`. The Dockerfile's `solc-select install` loop must list the same versions.
- `pick_solc(source: str) -> str` — constraint-aware. Every `pragma solidity` statement in the file is parsed (`^`, `~`, `>=`, `>`, `<=`, `<`, `=`, bare literals, partial literals as X-ranges, `||` alternatives OR-ed within a statement; all statements must hold). Rule: `DEFAULT_SOLC` whenever it satisfies the constraints; otherwise the **lowest** satisfying installed version (0.4 code usually breaks under 0.5 semantics, and the oldest satisfying patch is closest to what the author tested: `>=0.4.22 <0.6.0` → 0.4.26, `^0.8.26` → 0.8.26); otherwise the legacy nearest-same-minor of the first version literal, default `0.8.20` for an unknown minor (`0.4.24` → 0.4.26, `>=0.8.0 <=0.8.10` → 0.8.20 — solc then rejects the pragma and the retry ladder relaxes it).
- `solc_binary(version: str) -> Path` — `~/.solc-select/artifacts/solc-<v>/solc-<v>`.
- `oz_remapping() -> str | None` — `@openzeppelin/contracts/=<dir>/` where `<dir>` is `$DETECTOR_OZ_DIR` if set, else `<repo>/vendor/openzeppelin-contracts`, else `/app/vendor/openzeppelin-contracts`; `None` if none exists.
- `compile_file_ex(path: Path) -> CompileResult` — constructs `Slither(str(target), solc=<bin>, solc_remaps=[remap], solc_args="--allow-paths <parent>,<oz>")`, climbing the retry ladder below on failure. `CompileResult(slither, version, note: str | None, source_path, canonical_path)`: `note` is `None` when the first attempt succeeded; `source_path` is the file Slither actually parsed (a same-directory temp copy when the ladder rewrote the source, `canonical_path` otherwise). Filenames inside `slither` point at `source_path`, so `engine.target_contracts` must be given `source_path`. Raises `CompileError(message)` when every rung fails; the message carries the solc version, the first 500 chars of the **original** first error, and the attempt log (`retry ladder: <version> on <file>: <first error line> | …`).
- `compile_file(path: Path) -> Slither` — thin wrapper, `compile_file_ex(path).slither`, for callers that only need the Slither object.
- `is_temp_copy(path) -> bool` / `TEMP_COPY_SUFFIX = ".__relaxed__.sol"` — identifies ladder temp copies (a worker killed mid-compile can leave one behind; batch drivers should skip them).

**Retry ladder.** Each rung is a fresh `Slither(...)` construction; the ladder stops at the first success and performs at most `MAX_SOLC_ATTEMPTS = 5` constructions per file. Rewritten sources are written as `<stem>.__relaxed__.sol` **in the same directory** (relative imports and `--allow-paths` keep resolving), preserve line numbers exactly (statements are replaced in place, newlines kept), and are deleted in a `finally` whether the rung succeeded or not — Slither caches source text at construction, so `source_mapping.lines`/`.content` stay valid. Rungs: (a) the error says `requires different compiler version` → every `pragma solidity …;` replaced by `pragma solidity >=0.4.0;`, same picked version (`note = "pragma 0.4.25 relaxed; compiled with 0.4.26"`); (b) the file has **no** pragma and the default fails → retry with `0.4.26`, `0.5.17`, `0.6.12`, `0.7.6` in that order (`note = "no pragma; compiled with 0.4.26"`); (c) the error says `Multiple SPDX license identifiers` → every SPDX comment after the first is blanked, combined with (a) when both apply (`note = "duplicate SPDX identifiers removed; compiled with 0.8.20"`); (d) anything else (undeclared identifiers, missing imports, broken syntax at every version) → `CompileError`. The ladder never fires on a file whose first attempt compiles, so every Tier 1 / Tier 3 fixture still compiles with `note is None`.

### `engine.py`

- `analyze_file(path: Path, rel: str, *, timeout_s: int = 120) -> FileResult` — runs `_analyze_in_process` in a child process (`multiprocessing` spawn context); on timeout terminates the child and returns `FileResult(rel, "Uncertain", reason="timeout")`; on child failure returns `Uncertain(analysis_error)` (or `compile_failed` when the failure is a `CompileError`).
- `_analyze_in_process(path, rel) -> FileResult` — compile → target contracts → `ContractContext` → run `rules.RULES` → `overlay.run(slither)` → `policy.decide(findings)`.
- `analyze_dir(input_dir: Path, *, timeout_s=120) -> list[FileResult]` — sorted `rglob("*.sol")`, relative POSIX paths, one result each. Never raises for a bad file.
- `target_contracts(slither, path) -> list[Contract]` — contracts whose `source_mapping.filename.absolute` resolves to `path`, excluding interfaces, libraries, and `abstract` contracts.

### `model.py`

- `@dataclass Finding(rule_id, family, severity, contract, function, lines: tuple[int,...], reasoning, base_severity, discriminators: tuple[str,...], counts_for_escalation: bool)`; `to_json()` emits only the schema fields (`rule_id, family, severity, contract, function, lines, reasoning`).
- `@dataclass FileResult(file, verdict, reason="", findings=())`.
- `write_results(path, results: list[FileResult]) -> None` — `{"tool": {"name": "detector", "version": ...}, "results": [...]}`, results sorted by `file`, findings sorted by `(rule_id, contract, function, lines)`; validated against the vendored schema before writing; `json.dumps(..., sort_keys=True, indent=2)`.
- `Severity`, `Verdict` are `Literal` types; the catalog (rule → family, base severity) is a Python constant `CATALOG` in `rules/base.py` mirroring `baybench/catalog.yaml` (test asserts identity).

### `summary.py`

- `render_summary(results: list[FileResult], meta: dict) -> str` — header (tool, version, file count, verdict counts), then per file: verdict, reason, and a findings table (`rule_id | severity | contract.function | lines | reasoning`). Deterministic. Written next to `results.json` as `summary.md`.

### `cli.py`

`python -m detector.cli <input_dir> <results.json> [--timeout 120] [--no-summary]`. Exit 0 whenever `results.json` was written (even if every file is Uncertain). Exit 2 on argument errors only.

### `analysis/privilege.py` (research §5 predicate 1 — name-agnostic)

- `AuthAtom(node, kind ∈ {"eq_state_address", "map_bool", "tx_origin"}, auth_var: StateVariable, sender_source ∈ {"msg.sender","tx.origin"})` — a comparison/lookup in a node's condition that (a) is data-dependent on `msg.sender` or `tx.origin` and (b) resolves against **state**: `==`/`!=` against a state `address` variable (`eq_state_address`), or a `bool` loaded from a state mapping (possibly nested, e.g. `_roles[r].members[a]`) indexed by a sender-dependent key (`map_bool`). `require(balances[msg.sender] >= x)` is **not** an atom (non-bool value, non-address compare). `to == pair` is **not** an atom (no sender). (research §6: "Only `msg.sender`/`tx.origin` comparisons are auth".)
- `auth_atoms(function) -> list[AuthAtom]` — atoms in end nodes (`require`/`assert`/`if`→`revert`) of the function body, its modifiers, and its internal callees (closure).
- `branch_atoms(function) -> list[(AuthAtom, Node if_node)]` — atoms in plain `if` conditions (branch privilege).
- `is_privileged(function) -> bool` — `auth_atoms(function)` non-empty. Constructors are never privileged.
- `PrivilegedWrite(var: StateVariable, function, node, auth_vars: tuple[StateVariable,...], mode ∈ {"function","branch"})`.
- `privileged_writes(contract) -> list[PrivilegedWrite]` — every state-variable write in a privileged function (mode `function`) or inside a branch guarded by a branch atom (mode `branch`), constructors excluded.
- `unprivileged_writers(contract, var) -> list[Function]` — non-constructor functions that write `var` and are not privileged (and the write is not inside a privileged branch).
- `privileged_writable(contract) -> dict[StateVariable, list[PrivilegedWrite]]` — vars with ≥1 privileged write and **no** unprivileged writer; excludes `constant`/`immutable` vars.
- `auth_vars(contract) -> set[StateVariable]` — union of `AuthAtom.auth_var` over all functions.
- `is_exposed(contract, var) -> bool` — `var.visibility == "public"` or some public/external `view` function's return value is data-dependent on `var` (`hasRole`, `owner()` shapes). A hidden role is an auth var that is not exposed.
- `role_writers(contract, var) -> list[Function]` — non-constructor functions writing an auth var.

### `analysis/transfer_path.py` (research §5 predicate 3a/3b, §4 placement)

- `transfer_roots(contract) -> list[Function]` — functions with full signature `transfer(address,uint256)` or `transferFrom(address,address,uint256)`; fallback when absent: external non-privileged functions that debit the bound balance mapping at a sender-dependent key and credit it at another key.
- `transfer_path(contract) -> set[Function]` — closure of roots under modifiers and internal/library calls (`Function.modifiers`, `all_internal_calls()`), recursively; covers pre-`_transfer` checks (research §4 "Dialectic").
- `amount_params(root) -> list[Variable]` — the `uint256` parameter(s) of the root; `is_amount_dependent(var, function)` via `is_dependent` against any amount param propagated through internal calls (arguments → parameters mapping).
- `EndNode(node, kind ∈ {"require","assert","if_revert","if_return_before_write"}, guard_conditions: list[Node])` — `require`/`assert` `SolidityCall` nodes; `if` nodes whose taken branch reaches `revert`/`THROW` before any state write; `if` nodes whose branch returns before **any** balance-mapping write. `guard_conditions` = dominating `if` conditions (for nested gates such as `if (block.timestamp <= until) require(amount <= max)`).
- `end_nodes(contract) -> list[EndNode]` over the transfer path (excluding nodes inside the constructor).
- `GateRead(end_node, var: StateVariable, shape ∈ {"map_addr_bool","bool","numeric_vs_amount","numeric_vs_time","address_vs_to","address_vs_from"}, key_source ∈ {"from","to","msg.sender","other", None})` — how a privileged-writable var is read in the end node's condition. `numeric_vs_amount` requires the other operand to be amount-dependent; `numeric_vs_time` requires the other operand to be `block.timestamp`/`block.number`-dependent.
- `gate_reads(ctx) -> list[GateRead]` — over `end_nodes(contract)` ∩ `privileged_writable(contract)`.
- `external_calls_on_path(ctx) -> list[(Function, Node, target_var | None)]` — `HighLevelCall`/`LowLevelCall` on the transfer path with the destination resolved to a state variable when possible.

### `analysis/balances.py` (research §5 balance binding, §6 "bind balance mapping")

- `Bindings(balance_vars: tuple[StateVariable,...], supply_vars: tuple[...], allowance_vars: tuple[...], balance_of: Function | None, total_supply: Function | None)`.
- `bind(contract) -> Bindings` — `balance_vars` = state mappings read on the return path of the function with signature `balanceOf(address)` (or the public state mapping whose getter has that signature); fallback: the `mapping(address=>uint)` that is debited at a sender-dependent key and credited at another key in one public function. `supply_vars` from `totalSupply()` likewise. `allowance_vars` from `allowance(address,address)`; fallback: the nested mapping written at `[msg.sender][param]` in `approve(address,uint256)`. Never treat "any `address→uint` mapping" as balances.
- `BalanceWrite(node, function, var, key: Variable | None, key_source ∈ {"from","to","msg.sender","param","state","this","other"}, kind ∈ {"debit","credit","set"}, value: Variable | None, value_is_raw_amount: bool, value_reads_same_key: bool)`.
- `balance_writes(function, bindings) -> list[BalanceWrite]` — classifies `m[k] -= x`, `m[k] = m[k] - x`, `m[k] = sub(m[k], x)` as `debit`; `+=`/`add` as `credit`; other assignment as `set`. `value_is_raw_amount` = value is the root amount param or a copy without arithmetic. `value_reads_same_key` = value data-depends on `m[k]` (or another bound balance var at the same key).
- `arith_kind(call) -> "add" | "sub" | None` — for an internal/library call whose callee is `pure`, returns the operator when the callee's return value is a `Binary` of its two parameters (`+` → add, `-` → sub), so SafeMath-style helpers classify semantically, not by name.
- `is_constant_bound(node_condition, ctx) -> bool` — the bounding operand is a literal, `constant`, `immutable`, or an expression over those and `totalSupply()`/supply vars only (no privileged-writable var).

### `analysis/roles.py` (research §6 shapes; all structural)

- `managed_role(ctx, auth_var) -> bool` — `auth_var` is written outside the constructor **only** by privileged functions whose own auth atoms use a different auth var (`owner → blacklister → blacklist()`, two-step ownership `newOwner → owner`). Self-managed roles (OZ `Ownable._owner` written under `_owner`) are **not** managed.
- `library_role(ctx, function) -> bool` — every auth atom gating `function` lives in a source file **outside the input root** (e.g. vendored OZ `AccessControl`). Provenance-based, not name-based.
- `issuer_token(ctx) -> bool` — the same auth var gates both a privileged **credit** (mint) and a privileged **debit at a non-sender key** (burn-other) of the bound balance mapping, and each of those functions emits ≥1 event whose arguments include the amount (`EventCall` in the function or its internal callees). Bancor `issue/destroy`, MiniMe `generateTokens/destroyTokens`.
- `one_shot_initializer(function) -> bool` — the function's end node reads a state `bool`/`uint` that the same function writes (initializer shape); used to exempt `initialize` from OWN_REASSIGN_NONSTD.
- `has_custody(ctx) -> bool` — some non-privileged `payable` function exists whose `msg.value` is not forwarded in full by an external call in the same function (MiniMe's `proxyPayment` forward is not custody; a vault `deposit()` is).
- `ungate_exists(ctx, var, end_node) -> bool` — some privileged write of `var` can produce the *permissive* value for `end_node` (for `require(!paused)`: a write of `false` or of a parameter; for `require(enabled)`: a write of `true` or of a parameter).

### Implementation notes recorded in 4a (interface deltas, not scope changes)

- `unprivileged_writers` counts only public/external callers (writes in their internal callees are attributed to them); internal helpers such as OZ `_pause` are not writers on their own.
- `map_bool` auth atoms require **positive polarity** (the function proceeds iff the mapping value is true). `require(!m[msg.sender])` is a deny-list gate, never auth.
- `arith_kind` accepts non-`pure` helpers that write no state (0.4 `safeAdd`/`safeSub`).
- `is_whole_pot(value, function)`, `is_amount_dependent(var, function, ctx)`, `balance_writes(function, bindings, param_roles=...)`, and optional `ctx` on `transfer_roots/transfer_path/end_nodes` carry context for caching / role mapping.
- `tx.origin` compares are kind `tx_origin` (not `eq_state_address`).
- `engine.target_contracts` returns **leaf** contracts only (not inherited by another selected contract in the file) and drops 0.4 callback stubs with only unimplemented functions.
- Shared IR helpers live in `analysis/_ir.py`. All result-affecting iteration is ordered; caches are strong refs pinned on the context (determinism test in `tests/detector/test_determinism.py`).
- Known gap: storage-pointer writes (`updateValueAtNow(balances[x], v)`) are not attributed to the bound mapping.

### `analysis/flows.py`

- `value_sends(function) -> list[(node, to_expr, value_expr, kind ∈ {"transfer","send","call_value","selfdestruct"})]` — ETH leaving the contract.
- `is_whole_pot(value_expr) -> bool` — value is `address(this).balance`-dependent.
- `payable_inflows(contract) -> list[Function]`.
- `token_out_calls(function, bindings) -> list[(node, call, token_source ∈ {"param","state","this"}, to_expr, amount_expr)]` — `HighLevelCall`s to the ERC-20 `transfer`/`transferFrom` signatures on an external token.

### `rules/*` — one callable per rule: `rule(ctx: ContractContext) -> list[Finding]`

Every finding: `contract`, `function` (the function that carries the evidence — for gates the **writer** is one finding and the **impact site** another finding with the same rule_id only if both are needed for `expected_functions`; default: one finding at the writer and one at the impact site), `lines` (source lines of the writer node and the impact node), `reasoning` (names writer, gated var, impact node kind — via the actual identifiers *from the source*, which is reporting, not matching). `discriminators` lists the §6 discriminator names that matched; policy applies them.

### `policy.py`

- `adjust(finding, ctx_shapes) -> Finding` — applies the discriminator table below; sets `severity`, keeps `base_severity`, sets `counts_for_escalation`.
- `decide(findings: list[Finding]) -> (verdict, reason)`:
  1. any finding with `severity == HIGH` → `Malicious`.
  2. else if `STRUCT_EXTERNAL_GATE` present → `Uncertain`, `reason=external_dependency`.
  3. else escalation: ≥2 findings with `severity == MED`, `counts_for_escalation`, distinct rule IDs, from ≥2 different families → `Malicious` (`reason=escalated:<ids>`) — unless a **suppressing shape** (`issuer_token` or any `managed_role`/`library_role` downgrade applied in this contract) is present.
  4. else any MED → `Uncertain`, `reason=med_findings`.
  5. else any `SLITHER_HIGH_OVERLAY` whose check is an **exploit-shape** check (`reentrancy-eth`, `arbitrary-send-eth`, `arbitrary-send-erc20`, `arbitrary-send-erc20-permit`, `suicidal`, `controlled-delegatecall`, `delegatecall-loop`, `msg-value-loop`, `unprotected-upgrade`, `protected-vars`, `rtlo`) → `Uncertain`, `reason=slither_high`. Other High-impact checks (e.g. `unchecked-transfer`, `uninitialized-state`, `shadowing-state`) are emitted as INFO evidence with discriminator `evidence_only` and never move the verdict (run 1 miss: `DRAIN_APPROVAL_PULL/ben`).
  6. else `Benign`.
- Concealment override: if any of {`OWN_HIDDEN_ROLE`, `OWN_FAKE_RENOUNCE`, `VIEW_CALLER_DEPENDENT`, `BAL_TRANSFER_HIDDEN_MINT`, `LEAK_EXEMPT_PATH`, `EXIT_CALLBACK_CYCLE`} fired at HIGH in the contract, **no downgrade applies** to any finding of that contract (disclosed-centralization shapes cannot launder a concealed control).

## Rule table (all 29 catalog IDs; base severity = catalog)

Notation: PW = privileged-writable state var (`privilege.privileged_writable`); TP = transfer path; EN = end node on TP; `bal` = bound balance mapping(s).

| Rule | Fam | Base | Trigger (structural) | Discriminators → effect |
|---|---|---|---|---|
| `PRIV_ROLE` | A | INFO | one finding per privileged function (`function`=that function); reasoning names the auth var and atom kind | — |
| `EXIT_ADDR_GATE` | A | HIGH | GateRead shape `map_addr_bool` (key from/to/msg.sender) on a PW mapping in an EN | `managed_role`→MED; `library_role`→MED; `issuer_token`→MED |
| `EXIT_GLOBAL_SWITCH` | A | HIGH | GateRead shape `bool` on a PW bool in an EN | `ungate_exists`→MED (§6 OZ Pausable / Bancor / Lido); `managed_role`→MED; `issuer_token`→MED |
| `EXIT_AMOUNT_LIMIT` | A | HIGH | GateRead `numeric_vs_amount` on a PW numeric in an EN | `constant_floor` (every writer of the var requires new value ≥ constant-bound expr)→MED; `bounded_window` (EN guard is `block.timestamp` vs `immutable`/`constant` expr) →MED; `managed_role`→MED |
| `EXIT_TIME_GATE` | A | MED | GateRead `numeric_vs_time` on a PW numeric where the time comparison **is** the EN condition (not merely a guard of another gate) | `no_expiry` (no writer bounds the var by a constant/`block.timestamp + constant`) → **HIGH** |
| `EXIT_SELL_ONLY` | A | HIGH | GateRead `address_vs_to` / `address_vs_from` on a PW address in an EN (revert only when `to`/`from` equals a settable address) | `managed_role`→MED |
| `EXIT_CALLBACK_CYCLE` | A | HIGH | on TP, an external call whose destination is a PW address **and**, in the same branch/after it, an EN comparing an amount-dependent value with a PW var | — (concealment) |
| `FEE_UNBOUNDED` | A | HIGH | a PW numeric feeds (is_dependent) the value of a `bal` credit/debit on TP or an ETH/token send on TP, and is not a gate | `fee_cap` (every writer bounds the var: cap/denominator ≤ 0.25; denominator = the constant it is divided by on TP, default 100) → **INFO**; `managed_role`→MED |
| `FEE_ADDR_MUTABLE` | C | MED | a PW address is the key of a `bal` credit on TP, or the recipient of an ETH/token send on TP | — |
| `BAL_PRIV_MINT` | B | HIGH | privileged (mode function) `credit`/`set`-increase of `bal` at key_source ∈ {param, state, this, msg.sender} or a privileged increase of a supply var, outside constructor | `constant_cap` (EN in the writer bounds supply+amt by constant/immutable)→MED; `role_separated_cap` (bound is a PW var whose writers are gated by a different auth var, USDC `minterAllowed`)→MED; `issuer_token`→MED; `managed_role`→MED |
| `BAL_PRIV_BURN_OTHER` | B | HIGH | privileged `debit` (or `set` to literal 0) of `bal` at a key **not** sender-dependent, outside constructor | `issuer_token`→MED; `managed_role`→MED; `representation_switch` (see below) → drop |
| `BAL_DIRECT_SET` | B | HIGH | privileged `set` of `bal` at a param/state key with a value that is **not** `value_reads_same_key`, outside constructor | `representation_switch` → drop; `managed_role`→MED |
| `BAL_TRANSFER_HIDDEN_MINT` | B | HIGH | on TP: ≥2 `bal` credits where a credit to a key other than `to` has `value_is_raw_amount`, or total credited raw amount exceeds debited (credit of raw amount to `to` **and** to another key) | — (concealment) |
| `VIEW_CALLER_DEPENDENT` | B | HIGH | the bound `balanceOf`/`totalSupply` function's return value or a branch condition in it is data-dependent on `msg.sender`/`tx.origin` | — (concealment) |
| `LEAK_ARBITRARY_TRANSFERFROM` | C | HIGH | a `bal` debit at a non-sender key reachable under privilege (function or branch mode) with no read of an allowance var dominating it on that path | `issuer_token`→MED; `managed_role`→MED |
| `LEAK_EXEMPT_PATH` | C | HIGH | on TP, a branch whose condition reads a PW var (map/bool/address vs sender) and in which the `bal` debit at `from` is skipped while a credit still happens | — (concealment) |
| `LEAK_PRIV_SWEEP` | C | HIGH | privileged ETH send of `address(this).balance` (or `bal`/self-token transfer from `address(this)`, or `token_out_calls` with `token_source == "state"`) | `foreign_only` (`token_source == "param"` and either guarded by `!= address(this)` or the contract has no bound `bal`) → **INFO**; `no_custody` (ETH sweep and `not has_custody`) → MED; `issuer_token`→MED; `managed_role`→MED |
| `OWN_HIDDEN_ROLE` | D | HIGH | an auth var (address or map) that gates ≥1 privileged function and is **not exposed** (`is_exposed` false) | — (concealment) |
| `OWN_FAKE_RENOUNCE` | D | HIGH | a privileged function assigns `address(0)` (or `delete`) to an auth var `o` while another auth var `p ≠ o` that gates ≥1 privileged function is not cleared in the same function; or the "renounce" also writes a non-zero value into any auth var | — (concealment) |
| `OWN_REASSIGN_NONSTD` | D | HIGH | an auth var written outside the constructor by a **non-privileged** function, or assigned a literal address / `msg.sender` by a function that is not gated by that same var | `one_shot_initializer` → drop |
| `OWN_TX_ORIGIN` | D | MED | an AuthAtom with `sender_source == "tx.origin"` gates a function | — |
| `STRUCT_EXTERNAL_GATE` | E | MED | on TP, an external call (HighLevel/LowLevel) whose destination is a PW address (constructor-only/immutable targets do not fire) | → verdict `Uncertain(external_dependency)` unless a HIGH is present |
| `STRUCT_DELEGATECALL_SETTABLE` | E | HIGH | `delegatecall` (IR `LowLevelCall`, or YUL/inline-assembly `delegatecall`) whose target is a PW address, **not** in the proxy-fallback shape | — |
| `STRUCT_SELFDESTRUCT` | E | HIGH | `selfdestruct` reachable from any public/external function | — |
| `STRUCT_PROXY_EOA_ADMIN` | E | MED | proxy-fallback shape: `fallback` forwards calldata via `delegatecall` to an address loaded from a PW state var whose writer is gated by a single state `address` auth var | — |
| `DRAIN_APPROVAL_PULL` | F | HIGH | a non-privileged external function makes a `HighLevelCall` matching `transferFrom(address,address,uint256)` (or `safeTransferFrom`, or `permit` followed by such) with arg0 sender-dependent and arg1 **not** sender-dependent, and the function performs no state write keyed by the sender and no value/token send to the sender | — |
| `HONEYPOT_LEGACY` | F | MED | (a) non-privileged ETH exit sending the whole pot whose EN compares a caller-supplied value with a state var written only in the constructor or by a privileged writer; (b) `balance_disorder`: EN compares `msg.value` against `address(this).balance` in a way that cannot hold (`msg.value > balance`); (c) exit reachable only when a state var equals a constructor-set secret | — |
| `PONZI_SHAPE` | G | MED | a function sends ETH to an address loaded from state storage (array/mapping) that is populated by a payable function, payee ≠ `msg.sender`, and the contract has no external value source other than `msg.value` | — |
| `SLITHER_HIGH_OVERLAY` | C | INFO | one INFO per Slither built-in detector result with `impact == High` on a target contract (`function` = first function element) | lifts Benign → Uncertain only |

`representation_switch` (reflection tokens, §6 "address→uint status maps"): a privileged function's `bal` write is dropped when its value data-depends on another bound balance var at the same key (re-denomination), or it writes literal 0 while the same function also writes the selector mapping that `balanceOf` branches on, at the same key.

## Discriminator classes (for `counts_for_escalation`)

| class | names | effect on escalation |
|---|---|---|
| bound | `ungate_exists`, `constant_floor`, `bounded_window`, `constant_cap`, `role_separated_cap`, `fee_cap`, `foreign_only`, `no_custody` | downgraded finding does **not** count |
| shape | `managed_role`, `library_role`, `issuer_token` | does not count **and** suppresses escalation for the contract |
| native MED | catalog MED rules (`EXIT_TIME_GATE`, `FEE_ADDR_MUTABLE`, `OWN_TX_ORIGIN`, `STRUCT_PROXY_EOA_ADMIN`, `HONEYPOT_LEGACY`, `PONZI_SHAPE`) | counts |

`STRUCT_EXTERNAL_GATE` never counts (it is Uncertain-with-reason by design).

Rationale (judge-facing, goes in README): **Malicious** = a concealed control, or an unbounded privilege over exits/balances under an unmanaged role, or two independent native privileged controls from different families. **Uncertain** = privilege that is bounded, disclosed, institutionally structured (managed roles, issuer tokens), or depends on an external contract. **Benign** = nothing privileged touches exits, balances, or funds.

## Determinism

Sorted file walk; sorted contract/function iteration (by `source_mapping` start); findings sorted canonically in the writer; no timestamps in `results.json`; `summary.md` content is a pure function of results.

## Docker (`detector/Dockerfile`)

`python:3.11-slim`; `git`; `dpkg --add-architecture amd64 && apt-get install libc6:amd64` (portable to arm64 hosts, see `Dockerfile.bench`); `pip install -r detector/requirements.txt`; `solc-select install` the pinned set; `COPY detector /app/detector`, `COPY vendor/openzeppelin-contracts /app/vendor/openzeppelin-contracts`; `ENV DETECTOR_OZ_DIR=/app/vendor/openzeppelin-contracts PYTHONPATH=/app`; `ENTRYPOINT ["python","-m","detector.cli","/input","/output/results.json"]`. Image `trust404/detector:latest`.

## Tests (`tests/detector/`)

- `test_compile.py` — `pick_solc` table; `_harness/compile_fail` → `CompileError`; `_harness/oz_import` compiles with remap; `_harness/multi_file` compiles.
- `test_engine.py` — `analyze_dir` on `_harness` → `compile_fail/broken.sol` is `Uncertain(compile_failed)`; results sorted; a monkeypatched slow worker → `Uncertain(timeout)`; a raising worker → `Uncertain(analysis_error)`; output validates against the vendored schema; vendored schema is byte-identical to `baybench/schema/result.schema.json`.
- `test_privilege.py` — on Tier 1 fixtures: `is_privileged` true for the mal writers (`setBots`, `setBlacklist` under `_admins` map, `onlyOwnerOrigin` via tx.origin), false for `transfer`; `require(balances[msg.sender] >= x)` is not an atom; `is_exposed` false for `_dev`, true for OZ `_owner`.
- `test_transfer_path.py` — roots/closure on `EXIT_ADDR_GATE/mal` include `_transfer`; end nodes found; `GateRead` shapes for each Tier 1 A-family mal fixture.
- `test_balances.py` — bindings on Tier 1 B fixtures and on `bancor_smarttoken` (public mapping getter); `arith_kind` on a SafeMath-style helper; debit/credit/set classification incl. `value_is_raw_amount`.
- `test_rules_<family>.py` — for every catalog rule: `mal` fixture fires the rule (rule recall), `ben` fixture does not fire it at HIGH (may fire MED where the ben label accepts Uncertain; must not fire at all where the ben label accepts only Benign).
- `test_policy.py` — verdict table: HIGH → Malicious; only MED → Uncertain; external gate → reason; escalation with native MEDs from two families; no escalation for bound-downgraded MEDs; concealment override.
- `test_rename_invariance.py` (DT-8) — alpha-rename every user identifier (contracts, functions, modifiers, state vars, params, events; **not** ERC-20 ABI names, not builtins, not types) in `PRIV_ROLE/mal`, `OWN_HIDDEN_ROLE/mal`, `OWN_TX_ORIGIN/mal`, `EXIT_ADDR_GATE/mal`; assert the set of `(rule_id, severity)` is identical; plus a static test that no file under `detector/` contains identifier word-lists (regex for quoted `owner|admin|blacklist|pause|fee|dev|bot|whitelist` etc. outside of reasoning f-strings and this allow-list of protocol anchors).
- `test_summary.py` — renderer is deterministic and lists every file/finding.

## Acceptance (DT-1 .. DT-12) — status column is updated per phase; rows are never removed

| ID | Criterion | Status |
|---|---|---|
| DT-1 | `detector` is a registered bench tool with a Docker image; `bench run detector` completes under `--network none` on all tiers; output is schema-valid; determinism passes | OPEN |
| DT-2 | `_harness/compile_fail` → Uncertain(`compile_failed`); `STRUCT_EXTERNAL_GATE/mal` → Uncertain(`external_dependency`); `oz_import` and `multi_file` are not Malicious | OPEN |
| DT-3 | Tier 1 rule recall = 1.0 (every `mal` twin fires its `expected_rule_id`); floor 0.9 | OPEN |
| DT-4 | Tier 1 benign twins: HIGH-FP rate = 0; floor ≤ 0.05 | OPEN |
| DT-5 | Tier 3: HIGH-FP rate = 0; every fixture Benign or Uncertain | OPEN |
| DT-6 | Tier 2 family recall ≥ 0.6 on the compiling sources; per-family numbers recorded; every miss bucketed | OPEN |
| DT-7 | Evidence hit rate ≥ 0.9 on Tier 1 `mal` (`expected_functions`); every finding has contract, function, lines, reasoning | OPEN |
| DT-8 | Name-agnostic: identifier-renaming test on `PRIV_ROLE`, `OWN_HIDDEN_ROLE`, `OWN_TX_ORIGIN`, `EXIT_ADDR_GATE` mal fixtures yields identical rule IDs; no rule module contains identifier-name matching | OPEN |
| DT-9 | Beats baselines on the same tier set as the baseline reports (Tier 1 + Tier 3): weighted_score above `baseline_slither` (0.5789) and `baseline_keyword` (0.4222); Tier 3 HIGH-FP rate below the keyword baseline's 0.75 | OPEN |
| DT-10 | Runtime: Tier 1+3 in Docker under 5 minutes; per-file timeout yields Uncertain(`timeout`), never a crash | OPEN |
| DT-11 | Judge packaging: one `docker run --rm --network none -v in:/input:ro -v out:/output trust404/detector` produces `results.json` and a human-readable `summary.md`; README explains verdict derivation | OPEN |
| DT-12 | Iterate loop evidenced: `docs/bench/misses.md` has one triaged row per first-run gap with bucket, fix, status; `reports/detector/` committed | OPEN |

## Phasing (ordering only; no row is dropped)

- 4a Engine: package skeleton, `compile.py`, `engine.py`, `model.py`, `cli.py`, `analysis/*`, policy skeleton, Dockerfile, registry. → DT-1 (build), DT-2, DT-8 (analysis half).
- 4b Rules A, B, D + policy discriminators. → DT-3/DT-4 partial.
- 4c Rules C, E, F, G + overlay; full policy. → DT-3, DT-4, DT-5.
- 4d Iterate on Tier 2/3 with `docs/bench/misses.md`. → DT-6, DT-7, DT-9, DT-10, DT-12.
- 4e Packaging: `summary.md`, README. → DT-11.

## Known risks (recorded, not scope changes)

- Storage-pointer writes (MiniMe `updateValueAtNow(balances[x], v)`) may not be attributed by Slither to the mapping; B rules would then miss on that shape. Recorded in misses if observed.
- Inline-assembly `delegatecall` (proxy fallbacks) may need a YUL-node walk rather than IR.
- 0.4.x Tier 2 sources: `Slither` may fail on some despite `solc 0.4.26` → `compile_failed`, counted as accepted for non-compiling fixtures; recall measured on the compiling subset.
- Family F (HoneyBadger) is MED-driven; DT-6 reports per-family recall so F does not mask A/B/D.
