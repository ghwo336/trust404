# Tier 0 — judges' Discord public samples

This directory holds the **judges' Discord public samples** for TRUST404 Track 1. It is the highest-weight tier in the baybench report.

Populate it with:

```bash
bench ingest-discord <dir>
```

That command copies every `.sol` under `<dir>` here, writes a `labels.yaml` scaffold per file, and applies organizer verdicts from an optional `labels.csv` (`file,verdict`) when present.

**This tree is empty until samples arrive (BB-8).** The ingest command and labels scaffold ship now; fixtures are filled in when the Discord export is available.
