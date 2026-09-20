# TRUST404 Track 1 — noexit × detector

One repository, two independent offline engines, one entry point. Both engines read a directory of `.sol` files and emit the Track 1 judge schema; `run.sh` runs them side by side and merges the verdicts.

| | noexit (`noexit/`) | detector (`detector/`) |
|---|---|---|
| language | TypeScript, `@solidity-parser/parser` tolerant AST, optional solc-js wasm compile confirmation | Python, solc ladder (0.4 → 0.8.37) + Slither overlay |
| method | behaviour-based roles (balance / owner / pair / exempt), transfer-path closure, privileged-write dataflow, 55 rule ids | judge-aligned discriminators over the §7 catalog, decisive mode, 7-check exploit overlay |
| alone (BAYBENCH, official +1/0/−1 on 607 compiling cases) | 0.868 | 0.926 |
| **ensemble** | **0.947** — tier 0 5/5 · tier 1 1.00 · tier 2 0.94 · tier 3 1.00, zero high-severity false positives | |

## Run (grading entry point)

```bash
./run.sh ./cases > out.json          # JSON array on stdout, logs on stderr, exit 0
```

Requirements without Docker: Python ≥ 3.11 with `pip install -r detector/requirements.txt` and the solc versions from `detector/Dockerfile` (`solc-select install …`), plus Node ≥ 18 with `cd noexit && npm ci && npm run build`. Either engine missing or crashing is tolerated — the other one carries every file (see `tools/ensemble.py`).

With Docker (fully offline at run time; `--network none`):

```bash
docker build -t trust404/ensemble .
docker run --rm --network none -v "$PWD/cases:/input:ro" trust404/ensemble /input > out.json
check-jsonschema --schemafile docs/judge/challenge_public/schema.json out.json
```

`./run.sh` uses the image automatically when it exists. Single engines: `noexit/run.sh <dir>` and `./run_detector.sh <dir>`; `ENSEMBLE_ENGINES=noexit|detector ./run.sh <dir>` restricts the ensemble.

## Ensemble rule

`MALICIOUS` if either engine says so; `BENIGN` if neither says `MALICIOUS` and at least one says `BENIGN`; `UNCERTAIN` only when both abstain. Reasons and evidence are the union of the engines that voted for the final verdict, and a `MALICIOUS` row without a code location is downgraded to `UNCERTAIN` (schema). The rule was picked on BAYBENCH with the official scoring (correct +1, `UNCERTAIN` 0, wrong −1): the engines' positive calls are additive because each has zero high-severity false positives on the benign-risky tier, so "either" beats every stricter consensus (AND-consensus 0.880, detector-first 0.941, either 0.947 on the 607 compiling cases; 0.580 vs 0.581 vs 0.518 over all 859 including the 250 non-compiling fixtures labelled `UNCERTAIN`).

Verdict policy for both engines follows the track's boundary rules: a pause/limit that binds the owner too is availability only (`BENIGN` + centralisation note); an asymmetric one is `MALICIOUS`; privileged minting is `MALICIOUS` unless a supply cap is enforced in code; owner recovery of force-sent ETH is not theft. Web demo of the noexit engine (same rules, runs in the browser): https://ghwo336.github.io/T404/

---

# BAYBENCH

Offline harness for TRUST404 Track 1 detectors. A tool is a black box: it reads a directory of `.sol` files and writes one `results.json`. BAYBENCH scores that output identically for every teammate, then lists the misses to iterate on. Pattern and rule IDs come from [docs/research/track1-malice-patterns.md](docs/research/track1-malice-patterns.md); the spec is [docs/specs/baybench.md](docs/specs/baybench.md).

## Install

```bash
uv venv --python 3.12 .venv && uv pip install -e '.[dev]'
```

## Commands

```bash
bench run baseline_keyword --tier 1 --no-docker
bench coverage --cases cases
bench coverage baseline_keyword --tier 1 --no-docker
bench validate --tier 1
bench report
bench ingest-discord path/to/discord-export
bench ingest-paper piedpiper path/to/sources
```

`bench run` double-runs by default (`--repeat 2`), writes `reports/<tool>/report.md` and `report.json`, and prints weighted score, determinism, and compile-fail count. `ingest-discord` / `ingest-paper` are seams for Tier 0 / Tier 2 (BB-8, BB-9); they exit 2 until those tasks land.

## `results.json` shape

```json
{
  "tool": {"name": "my_tool", "version": "0.1"},
  "results": [
    {
      "file": "tier1/EXIT_ADDR_GATE/mal/mal.sol",
      "verdict": "Malicious",
      "reason": "",
      "findings": [
        {
          "rule_id": "EXIT_ADDR_GATE",
          "family": "A",
          "severity": "HIGH",
          "contract": "Token",
          "function": "setBots",
          "lines": [41, 47],
          "reasoning": "hardcoded allowlist"
        }
      ]
    }
  ]
}
```

`file` is relative to the staged input root (`<case.id>/<case.file>`). Verdicts are `Benign | Malicious | Uncertain`. Schema: `baybench/schema/result.schema.json`.

## Register a tool

Add an entry to `baybench/tools.yaml`:

```yaml
tools:
  - name: baseline_keyword
    image: baybench/baseline_keyword:latest          # docker mode
  - name: my_local_tool
    cmd: "python /path/tool.py --in {input} --out {output}/results.json"  # --no-docker
  - name: teammate_tool
    cmd: "node ${T404_DIR}/dist/baybench.js {input} {output}/results.json"  # env-relative
```

`{input}` and `{output}` are substituted in command mode. Docker mode mounts them at `/input` (ro) and `/output`. `cmd` is also env-expanded (`${T404_DIR}`) with cwd = repo root; an unset variable is a clear error.

```bash
export T404_DIR=/path/to/T404
.venv/bin/bench run noexit --no-docker
```

## Grading parity

Grading parity is `docker run --rm --network none`. Network-dependent tools score zero by construction. The bench image (`Dockerfile.bench`) bakes in `solc-select` compilers so `bench validate` runs offline (BB-11):

```bash
docker build -f Dockerfile.bench -t baybench .
docker run --rm --network none baybench validate
```
