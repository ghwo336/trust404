---
name: deep-research-survey
description: >-
  Run a structured literature-and-prior-art survey (academic papers, SoKs,
  industry tool docs, datasets) for a technical problem and persist it as a
  research note that maps findings to implementation predicates. Use when the
  user asks for deep research, papers, prior art, "what does the literature
  say", a taxonomy of patterns, or before designing a detector, classifier,
  scoring rubric, or policy in a domain with existing research.
disable-model-invocation: true
---

# Deep Research Survey

Turns "go research X" into a sourced, decision-ready note in `docs/research/`.
The output is not a reading list. It is a taxonomy + the rules to implement it + the
false-positive boundary + datasets, every claim linked.

## Workflow

```
Progress:
- [ ] 0. Pin the judge
- [ ] 1. Name the field
- [ ] 2. Seed wave (parallel)
- [ ] 3. Harvest (grep, don't skim)
- [ ] 4. Gap wave (parallel) → saturation
- [ ] 5. Synthesize on the skeleton
- [ ] 6. Persist + report
```

### 0. Pin the judge

Read the primary requirement source (spec page, RFP, track rules, acceptance table). Extract:

- **Literal evaluation phrases.** They become search terms and the note's anchor section. (Track text "비정상적 권한 이전" turned out to be a named taxonomy category: *Ownership Fraud*.)
- **Hard constraints** that disqualify whole approaches (offline grading kills hosted APIs; source-only input kills transaction features). Record them up front; every later source is sorted into *usable* vs *context-only* against them.

### 1. Name the field

Write one sentence naming the academic sub-literature the problem belongs to, and one naming what it is **not** ("scam-contract detection, not vulnerability detection"). Getting this wrong wastes the whole survey.

If the request contains a name you do not confidently recognize, or from a fast-moving area (new model, new tool), search it **first**, including the name exactly as the user wrote it. Do not answer from partial memory.

### 2. Seed wave

Fire 6–8 web searches **in one parallel call**. Cover each slot:

| Slot | Query shape |
|---|---|
| Foundational | oldest well-cited paper by exact title in quotes + venue |
| Known tools | each tool/paper already known, by exact name + venue |
| Recent SoK / survey | `"<field>" SoK OR survey OR taxonomy <year-1> <year>` |
| Largest dataset | `<field> dataset labeled source code github` |
| Industry checklist | vendor API docs / field lists (what competitors will copy) |
| Practitioner tricks | `<field> concealment OR obfuscation OR hiding techniques` |
| Adjacent class | one category possibly missing from the framing |
| Current-era work | LLM / ML approaches from the last 12 months (awareness only) |

### 3. Harvest, don't skim

Fetched pages land as full-text files. Never rely on the search engine's synthesis for rules or numbers — open the file. Grep each for:

- `Table`, `Formula`, `Rule`, `Definition`, `Listing` → taxonomies and exact detection rules
- `False Positive`, `Limitations`, `Threats to Validity` → the benign-lookalike boundary
- `%`, `n =`, `out of`, `incidents` → base rates (they set severity weights later)
- `evaluat`, `compared`, `outperform` → which prior tool missed what, and why

Read 40–60 line slices around hits. Do not read whole PDFs.

### 4. Gap wave

After the harvest, write the "we need next" list privately (exact rules, concealment techniques, counts, datasets, benign lookalikes), then run a second parallel batch. Stop when new sources only repeat the taxonomy already in hand (saturation). Usually two waves; three at most.

### 5. Synthesize on the skeleton

Use [note-template.md](note-template.md). Rules while writing:

- Merge taxonomies **by attacker gain / outcome**, not by paper. One paper's "Limiting Sell Order" and another's "Exchange Permission" are the same row.
- Keep the numbers (precision, recall, base rates, coverage). They are the argument for priority.
- Extract **the unifying formula**: the one structural question every strong tool reduces to. Then map it to concrete predicates in the tool the build uses.
- The false-positive section is mandatory. It defines the Uncertain / boundary class and is where naive competitors fail.
- Sort transaction-side, hosted, or otherwise constraint-violating work into a *context only* subsection. Say why it is unusable.
- Every claim gets a link. Prefer primary PDFs (arXiv, USENIX, ACM, IEEE) for rules and numbers; vendor docs for field lists; blogs only for practitioner tricks.
- Add a **Decisions log** capturing what the survey ruled out, so the team stops re-arguing it.

### 6. Persist + report

- Write to `docs/research/<topic-kebab>.md`.
- In chat: the framing sentence, the paper map, the taxonomy summary, the three most consequential implications, and the file path. No markdown tables in chat; tables are fine inside the note.
- Finish with what remains open, if anything. Do not end on a plan.

## Quality bar

- A taxonomy without implementation predicates is trivia. Do not stop before §5 of the template is filled.
- If two papers disagree on a number or a category boundary, record both with links; do not average them.
- Distinguish *measured* (paper evaluated it) from *claimed* (vendor marketing).
- Record the date of the survey in the note; fast-moving fields age.

## Additional resources

- Note skeleton: [note-template.md](note-template.md)
- Worked example in this repo: `docs/research/track1-malice-patterns.md`
