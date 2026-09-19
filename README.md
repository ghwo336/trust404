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
