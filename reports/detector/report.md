# BAYBENCH report — detector

## Summary

| metric | value |
| --- | --- |
| weighted_score | 0.8981 |
| mean_verdict_score | 0.9638 |
| n_cases | 69 |
| determinism | pass |
| runtime_p50 | - |
| runtime_p95 | - |
| compile_fail_count | 1 |

## Per-tier

| tier | n | mean_score | family_recall | rule_recall | high_fp_rate | evidence_hit_rate | uncertain_rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| tier1_pairs | 61 | 0.9836 | 1.0 | 1.0 | 0.0 | 1.0 | 0.1967 |
| tier3_benign_risky | 8 | 0.8125 | - | - | 0.0 | - | 0.75 |

## Per-family

| family | n_cases | mean_score |
| --- | --- | --- |
| A | 8 | 1.0 |
| B | 5 | 1.0 |
| C | 3 | 1.0 |
| D | 3 | 1.0 |
| E | 2 | 1.0 |
| F | 1 | 1.0 |
| G | 0 | 0.0 |

## Coverage

families_zero_cases (0): -
rules_zero_cases (0): -
rules_missing_pair (BB-6): PASS
unknown_rule_ids: -
extra_results: tier1/_harness/multi_file/Helper.sol

## Gaps

(no gaps)

