# BAYBENCH report — probe_network

## Summary

| metric | value |
| --- | --- |
| weighted_score | 0.6742 |
| mean_verdict_score | 0.6159 |
| n_cases | 69 |
| determinism | pass |
| runtime_p50 | 0.3889 |
| runtime_p95 | 0.3889 |
| compile_fail_count | 0 |

## Per-tier

| tier | n | mean_score | family_recall | rule_recall | high_fp_rate | evidence_hit_rate | uncertain_rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| tier1_pairs | 61 | 0.5984 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 |
| tier3_benign_risky | 8 | 0.75 | - | - | 0.0 | - | 1.0 |

## Per-family

| family | n_cases | mean_score |
| --- | --- | --- |
| A | 8 | 0.5 |
| B | 5 | 0.5 |
| C | 3 | 0.5 |
| D | 3 | 0.5 |
| E | 2 | 0.5 |
| F | 1 | 0.5 |
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
| tier1/BAL_DIRECT_SET/mal | Uncertain | no_expected_rule | BAL_DIRECT_SET | - |
| tier1/BAL_PRIV_BURN_OTHER/mal | Uncertain | no_expected_rule | BAL_PRIV_BURN_OTHER | - |
| tier1/BAL_PRIV_MINT/mal | Uncertain | no_expected_rule | BAL_PRIV_MINT | - |
| tier1/BAL_TRANSFER_HIDDEN_MINT/mal | Uncertain | no_expected_rule | BAL_TRANSFER_HIDDEN_MINT | - |
| tier1/DRAIN_APPROVAL_PULL/mal | Uncertain | no_expected_rule | DRAIN_APPROVAL_PULL | - |
| tier1/EXIT_ADDR_GATE/mal | Uncertain | no_expected_rule | EXIT_ADDR_GATE | - |
| tier1/EXIT_AMOUNT_LIMIT/mal | Uncertain | no_expected_rule | EXIT_AMOUNT_LIMIT | - |
| tier1/EXIT_CALLBACK_CYCLE/mal | Uncertain | no_expected_rule | EXIT_CALLBACK_CYCLE | - |
| tier1/EXIT_GLOBAL_SWITCH/mal | Uncertain | no_expected_rule | EXIT_GLOBAL_SWITCH | - |
| tier1/EXIT_SELL_ONLY/mal | Uncertain | no_expected_rule | EXIT_SELL_ONLY | - |
| tier1/EXIT_TIME_GATE/mal | Uncertain | no_expected_rule | EXIT_TIME_GATE | - |
| tier1/FEE_UNBOUNDED/mal | Uncertain | no_expected_rule | FEE_UNBOUNDED | - |
| tier1/LEAK_ARBITRARY_TRANSFERFROM/mal | Uncertain | no_expected_rule | LEAK_ARBITRARY_TRANSFERFROM | - |
| tier1/LEAK_EXEMPT_PATH/mal | Uncertain | no_expected_rule | LEAK_EXEMPT_PATH | - |
| tier1/LEAK_PRIV_SWEEP/mal | Uncertain | no_expected_rule | LEAK_PRIV_SWEEP | - |
| tier1/OWN_FAKE_RENOUNCE/mal | Uncertain | no_expected_rule | OWN_FAKE_RENOUNCE | - |
| tier1/OWN_HIDDEN_ROLE/mal | Uncertain | no_expected_rule | OWN_HIDDEN_ROLE | - |
| tier1/OWN_REASSIGN_NONSTD/mal | Uncertain | no_expected_rule | OWN_REASSIGN_NONSTD | - |
| tier1/PRIV_ROLE/mal | Uncertain | no_expected_rule | PRIV_ROLE | - |
| tier1/STRUCT_DELEGATECALL_SETTABLE/mal | Uncertain | no_expected_rule | STRUCT_DELEGATECALL_SETTABLE | - |
| tier1/STRUCT_SELFDESTRUCT/mal | Uncertain | no_expected_rule | STRUCT_SELFDESTRUCT | - |
| tier1/VIEW_CALLER_DEPENDENT/mal | Uncertain | no_expected_rule | VIEW_CALLER_DEPENDENT | - |

