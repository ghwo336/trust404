# <Topic> — Literature & Taxonomy

- **Status:** research note (input to the spec; not itself the spec)
- **Date:** YYYY-MM-DD
- **Scope:** <what is being built / decided; one line>
- **Anchor:** <link to the primary requirement source>

---

## 0. What is being judged / constrained

Verbatim requirements from the anchor. Hard constraints that disqualify approaches. Which literal phrases map to named categories in the literature.

## 1. Problem framing the literature agrees on

One sentence naming the sub-field. One sentence naming what it is not. The single structural question all strong tools reduce to.

## 2. Paper map

Grouped by contribution type, not chronology:

- **2.1 Foundational** — title · authors · venue · link · one-line contribution · reusable artifact
- **2.2 Closest to this build** — same, plus the exact rules / formulas they use
- **2.3 Taxonomies and tool audits** — SoKs; coverage numbers; named failure modes
- **2.4 Context only** — work that violates the constraints (why unusable)
- **2.5 Industry checklists** — vendor field lists (what competitors will copy)

## 3. Consolidated taxonomy

Merged across sources, grouped by attacker gain / outcome. Per row: pattern · shape · real example (from a cited paper). Include base rates where known.

## 4. Where it hides — why naive matching fails

Placement, naming, structure, runtime-conditional activation. The named failure modes of prior tools. The convergent fix.

## 5. Unifying formula → implementation predicates

The one structural triple / question. Then a table: predicate → concrete surface in the tool this build uses.

## 6. Benign lookalikes — the boundary class

Table: lookalike · why confused · discriminator. Calibration notes from base rates.

## 7. Draft rule set

Rule ID · family · trigger · severity. Draft verdict policy. Evidence fields every finding must carry.

## 8. Datasets

Source · what · link. Priority order. Note anything that must be fetched before a constraint (e.g., offline) applies.

## 9. Implications for the build

Direction confirmed or changed. Numbered additions the survey justifies.

## 10. Decisions log

What the survey ruled out and why. One line each.
