# BAYBENCH report — baseline_keyword

## Summary

| metric | value |
| --- | --- |
| weighted_score | 0.4222 |
| mean_verdict_score | 0.5543 |
| n_cases | 69 |
| determinism | pass |
| runtime_p50 | 0.3348 |
| runtime_p95 | 0.3348 |
| compile_fail_count | 0 |

## Per-tier

| tier | n | mean_score | family_recall | rule_recall | high_fp_rate | evidence_hit_rate | uncertain_rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| tier1_pairs | 61 | 0.5943 | 0.4545 | 0.3182 | 0.3226 | 0.0 | 0.0 |
| tier3_benign_risky | 8 | 0.25 | - | - | 0.75 | - | 0.0 |

## Per-family

| family | n_cases | mean_score |
| --- | --- | --- |
| A | 8 | 0.625 |
| B | 5 | 0.6 |
| C | 3 | 0.0 |
| D | 3 | 1.0 |
| E | 2 | 1.0 |
| F | 1 | 0.0 |
| G | 0 | 0.0 |

## Coverage

families_zero_cases (0): -
rules_zero_cases (0): -
rules_missing_pair (BB-6): PASS
unknown_rule_ids: -
extra_results: tier1/_harness/multi_file/Helper.sol

## Gaps

| case | verdict | reason | expected | fired |
| --- | --- | --- | --- | --- |
| tier1/BAL_DIRECT_SET/mal | Benign | no_expected_rule | BAL_DIRECT_SET | - |
| tier1/BAL_TRANSFER_HIDDEN_MINT/mal | Malicious | no_expected_rule | BAL_TRANSFER_HIDDEN_MINT | BAL_PRIV_MINT |
| tier1/DRAIN_APPROVAL_PULL/mal | Benign | no_expected_rule | DRAIN_APPROVAL_PULL | - |
| tier1/EXIT_AMOUNT_LIMIT/mal | Malicious | no_expected_rule | EXIT_AMOUNT_LIMIT | FEE_UNBOUNDED |
| tier1/EXIT_CALLBACK_CYCLE/mal | Benign | no_expected_rule | EXIT_CALLBACK_CYCLE | - |
| tier1/EXIT_SELL_ONLY/mal | Benign | no_expected_rule | EXIT_SELL_ONLY | - |
| tier1/EXIT_TIME_GATE/mal | Benign | no_expected_rule | EXIT_TIME_GATE | - |
| tier1/LEAK_ARBITRARY_TRANSFERFROM/mal | Benign | no_expected_rule | LEAK_ARBITRARY_TRANSFERFROM | - |
| tier1/LEAK_EXEMPT_PATH/mal | Benign | no_expected_rule | LEAK_EXEMPT_PATH | - |
| tier1/LEAK_PRIV_SWEEP/mal | Benign | no_expected_rule | LEAK_PRIV_SWEEP | - |
| tier1/OWN_FAKE_RENOUNCE/mal | Malicious | no_expected_rule | OWN_FAKE_RENOUNCE | EXIT_ADDR_GATE |
| tier1/OWN_HIDDEN_ROLE/mal | Malicious | no_expected_rule | OWN_HIDDEN_ROLE | EXIT_ADDR_GATE |
| tier1/OWN_REASSIGN_NONSTD/mal | Malicious | no_expected_rule | OWN_REASSIGN_NONSTD | EXIT_ADDR_GATE |
| tier1/PRIV_ROLE/mal | Malicious | no_expected_rule | PRIV_ROLE | BAL_PRIV_MINT, EXIT_ADDR_GATE |
| tier1/VIEW_CALLER_DEPENDENT/mal | Benign | no_expected_rule | VIEW_CALLER_DEPENDENT | - |

