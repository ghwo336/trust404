# BAYBENCH report — baseline_slither

## Summary

| metric | value |
| --- | --- |
| weighted_score | 0.5789 |
| mean_verdict_score | 0.5435 |
| n_cases | 69 |
| determinism | pass |
| runtime_p50 | 18.4477 |
| runtime_p95 | 18.4477 |
| compile_fail_count | 0 |

## Per-tier

| tier | n | mean_score | family_recall | rule_recall | high_fp_rate | evidence_hit_rate | uncertain_rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| tier1_pairs | 61 | 0.5328 | 0.0 | 0.0 | 0.0968 | 0.0 | 0.0164 |
| tier3_benign_risky | 8 | 0.625 | - | - | 0.375 | - | 0.0 |

## Per-family

| family | n_cases | mean_score |
| --- | --- | --- |
| A | 8 | 0.0 |
| B | 5 | 0.0 |
| C | 3 | 0.0 |
| D | 3 | 0.0 |
| E | 2 | 0.5 |
| F | 1 | 1.0 |
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
| tier1/BAL_PRIV_BURN_OTHER/mal | Benign | no_expected_rule | BAL_PRIV_BURN_OTHER | - |
| tier1/BAL_PRIV_MINT/mal | Benign | no_expected_rule | BAL_PRIV_MINT | - |
| tier1/BAL_TRANSFER_HIDDEN_MINT/mal | Benign | no_expected_rule | BAL_TRANSFER_HIDDEN_MINT | - |
| tier1/DRAIN_APPROVAL_PULL/mal | Malicious | no_expected_rule | DRAIN_APPROVAL_PULL | SLITHER_HIGH_OVERLAY |
| tier1/EXIT_ADDR_GATE/mal | Benign | no_expected_rule | EXIT_ADDR_GATE | - |
| tier1/EXIT_AMOUNT_LIMIT/mal | Benign | no_expected_rule | EXIT_AMOUNT_LIMIT | - |
| tier1/EXIT_CALLBACK_CYCLE/mal | Benign | no_expected_rule | EXIT_CALLBACK_CYCLE | - |
| tier1/EXIT_GLOBAL_SWITCH/mal | Benign | no_expected_rule | EXIT_GLOBAL_SWITCH | - |
| tier1/EXIT_SELL_ONLY/mal | Benign | no_expected_rule | EXIT_SELL_ONLY | - |
| tier1/EXIT_TIME_GATE/mal | Benign | no_expected_rule | EXIT_TIME_GATE | - |
| tier1/FEE_UNBOUNDED/mal | Benign | no_expected_rule | FEE_UNBOUNDED | - |
| tier1/LEAK_ARBITRARY_TRANSFERFROM/mal | Benign | no_expected_rule | LEAK_ARBITRARY_TRANSFERFROM | - |
| tier1/LEAK_EXEMPT_PATH/mal | Benign | no_expected_rule | LEAK_EXEMPT_PATH | - |
| tier1/LEAK_PRIV_SWEEP/mal | Benign | no_expected_rule | LEAK_PRIV_SWEEP | - |
| tier1/OWN_FAKE_RENOUNCE/mal | Benign | no_expected_rule | OWN_FAKE_RENOUNCE | - |
| tier1/OWN_HIDDEN_ROLE/mal | Benign | no_expected_rule | OWN_HIDDEN_ROLE | - |
| tier1/OWN_REASSIGN_NONSTD/mal | Benign | no_expected_rule | OWN_REASSIGN_NONSTD | - |
| tier1/PRIV_ROLE/mal | Benign | no_expected_rule | PRIV_ROLE | - |
| tier1/STRUCT_DELEGATECALL_SETTABLE/mal | Malicious | no_expected_rule | STRUCT_DELEGATECALL_SETTABLE | SLITHER_HIGH_OVERLAY |
| tier1/STRUCT_SELFDESTRUCT/mal | Benign | no_expected_rule | STRUCT_SELFDESTRUCT | - |
| tier1/VIEW_CALLER_DEPENDENT/mal | Benign | no_expected_rule | VIEW_CALLER_DEPENDENT | - |

