# BAYBENCH report — detector

## Summary

| metric | value |
| --- | --- |
| weighted_score | 0.9714 |
| tier0_exact | 5/5 |
| mean_verdict_score | 0.9008 |
| n_cases | 859 |
| determinism | pass |
| runtime_p50 | 381.913 |
| runtime_p95 | 381.913 |
| compile_fail_count | 190 |

## Per-tier

| tier | n | mean_score | family_recall | rule_recall | high_fp_rate | evidence_hit_rate | uncertain_rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| tier0_judge | 5 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 0.0 |
| tier1_pairs | 67 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 0.0299 |
| tier2_realworld | 779 | 0.8909 | 0.9146 | - | - | - | 0.2503 |
| tier3_benign_risky | 8 | 0.9688 | 1.0 | - | 0.0 | - | 0.125 |

## Per-family

| family | n_cases | mean_score |
| --- | --- | --- |
| A | 105 | 0.9048 |
| B | 107 | 0.965 |
| C | 8 | 1.0 |
| D | 4 | 1.0 |
| E | 5 | 0.95 |
| F | 324 | 0.9923 |
| G | 1 | 1.0 |

## Coverage

families_zero_cases (0): -
rules_zero_cases (0): -
rules_missing_pair (BB-6): PASS
unknown_rule_ids: -
extra_results: tier1/_harness/multi_file/Helper.sol

## Gaps

| case | verdict | reason | expected | fired |
| --- | --- | --- | --- | --- |
| tier2/crpwarner/0x90F75ca026adD95aE15ECBf48EFc77ED272945bE_sol | Malicious | no_expected_family | B | LEAK_PRIV_SWEEP, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/crpwarner/0x9372b371196751dd2F603729Ae8D8014BbeB07f6_sol | Benign | no_expected_family | B | PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/hidden_state_update_0x03209bde47da583547c17c47e7ca74bfa3dfb404_sol | Malicious | no_expected_family | F | PRIV_ROLE, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/hidden_state_update_0x07ec6c3159c2336ba36ab41f73411f8fee430470_sol | Benign | no_expected_family | F | PRIV_ROLE |
| tier2/honeybadger/hidden_state_update_0x0ffb3f4605dd9f01de1a06052b7687418a9d82ee_sol | Malicious | no_expected_family | F | EXIT_TIME_GATE, FEE_UNBOUNDED, LEAK_PRIV_SWEEP, OWN_FAKE_RENOUNCE, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/hidden_state_update_0x175744fb0849584129fa3d0e6350c00206d95d2f_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/hidden_state_update_0x286bbee3f20f1702e707e58d33dc28a69e7efd4e_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/hidden_state_update_0x38321bbb97a3541bb3913c12201b35d504f7af39_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_HIDDEN_ROLE, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/hidden_state_update_0x7409bac00c479b0003651cc157a72d1a227eccfb_sol | Malicious | no_expected_family | F | SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/hidden_state_update_0x75890afea0658ed67e145df17948c8fceed0affa_sol | Malicious | no_expected_family | F | FEE_UNBOUNDED, LEAK_PRIV_SWEEP, OWN_FAKE_RENOUNCE, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/hidden_state_update_0x7a2ac9691ce2fcffb9777311c14a82a6aec7e639_sol | Malicious | no_expected_family | F | EXIT_TIME_GATE, FEE_UNBOUNDED, LEAK_PRIV_SWEEP, OWN_FAKE_RENOUNCE, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/hidden_state_update_0x7c05c837f7a84dced69ae94f8649bbc3897d2b31_sol | Malicious | no_expected_family | F | EXIT_TIME_GATE, FEE_UNBOUNDED, LEAK_PRIV_SWEEP, OWN_FAKE_RENOUNCE, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/hidden_state_update_0x85bc00724203d53536072b000c44a2cc16cd12c5_sol | Malicious | no_expected_family | F | BAL_PRIV_MINT, EXIT_GLOBAL_SWITCH, LEAK_PRIV_SWEEP, PRIV_ROLE |
| tier2/honeybadger/hidden_state_update_0x95be22039da3114d17a38b9e7cd9b3576de83924_sol | Uncertain | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xb389327f8325d9568826b0f3ca63ef613687cfab_sol | Malicious | no_expected_family | F | EXIT_TIME_GATE, FEE_UNBOUNDED, LEAK_PRIV_SWEEP, OWN_FAKE_RENOUNCE, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/hidden_state_update_0xb620cee6b52f96f3c6b253e6eea556aa2d214a99_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_HIDDEN_ROLE, OWN_REASSIGN_NONSTD, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/hidden_state_update_0xb85a54944b58342b07887942e6f530f616479efd_sol | Malicious | no_expected_family | F | EXIT_TIME_GATE, FEE_UNBOUNDED, LEAK_PRIV_SWEEP, OWN_FAKE_RENOUNCE, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/hidden_state_update_0xc8b2c33a45ce83d19da15a58d1d1ddb2738506bf_sol | Malicious | no_expected_family | F | BAL_PRIV_MINT, EXIT_GLOBAL_SWITCH, LEAK_PRIV_SWEEP, PRIV_ROLE |
| tier2/honeybadger/hidden_state_update_0xe35a91f2acceccf1ce6bae792274da6100b639af_sol | Malicious | no_expected_family | F | EXIT_TIME_GATE, FEE_UNBOUNDED, LEAK_PRIV_SWEEP, OWN_FAKE_RENOUNCE, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/hidden_state_update_0xed4fd2e53153b8bfd866e11fb015a1bc4a0e9655_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_HIDDEN_ROLE, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/hidden_state_update_0xf6b55acbbc49f4524aa48d19281a9a77c54de10f_sol | Malicious | no_expected_family | F | BAL_DIRECT_SET, BAL_PRIV_MINT, LEAK_PRIV_SWEEP, PRIV_ROLE |
| tier2/honeybadger/hidden_state_update_0xfb0513602b08ede66c28c128ece6a2f11161f17f_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_HIDDEN_ROLE, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/inheritance_disorder_0x2d05359a51ca13c4ac5f4437585afaf5bf2050f9_sol | Malicious | no_expected_family | F | BAL_PRIV_MINT, LEAK_PRIV_SWEEP, OWN_HIDDEN_ROLE, PRIV_ROLE, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x849019a489c3c26c7a7668e468be81a4d132781f_sol | Malicious | no_expected_family | F | OWN_HIDDEN_ROLE, PRIV_ROLE, SLITHER_HIGH_OVERLAY, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x9c0c5a14fde1306686a8a270f271165acda670c2_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, PRIV_ROLE |
| tier2/honeybadger/inheritance_disorder_0xfdc39e06a7297268a0f6d5bd1692ae5fa9026152_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, PRIV_ROLE |
| tier2/honeybadger/inheritance_disorder_0xff41067fe843f190482d998a9976c7b19cd7c8b7_sol | Malicious | no_expected_family | F | OWN_HIDDEN_ROLE, PRIV_ROLE, SLITHER_HIGH_OVERLAY |
| tier2/honeybadger/named_RACEFORETH_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_HIDDEN_ROLE, PRIV_ROLE |
| tier2/honeybadger/named_TwelHourTrains_sol | Benign | no_expected_family | F | PRIV_ROLE |
| tier2/honeybadger/named_X2_FLASH_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0x74808c86c6f0bc6f59a3a1430ddfcd2e29952eac_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, PRIV_ROLE, SLITHER_HIGH_OVERLAY, STRUCT_SELFDESTRUCT |
| tier2/pied-piper/injected_DestroyToken_15_sol | Malicious | no_expected_family | B | OWN_HIDDEN_ROLE, PRIV_ROLE |
| tier2/pied-piper/injected_DestroyToken_2_sol | Malicious | no_expected_family | B | OWN_HIDDEN_ROLE, PRIV_ROLE |
| tier2/pied-piper/injected_FreezeAccount_8_sol | Benign | no_expected_family | A | - |
| tier2/pied-piper/real_0x1829aa045e21e0d59580024a951db48096e01782_sol | Malicious | no_expected_family | B | EXIT_ADDR_GATE, EXIT_GLOBAL_SWITCH, LEAK_PRIV_SWEEP, PRIV_ROLE, SLITHER_HIGH_OVERLAY, STRUCT_EXTERNAL_GATE |
| tier2/pied-piper/real_0x46b9ad944d1059450da1163511069c718f699d31_sol | Malicious | no_expected_family | B | EXIT_ADDR_GATE, EXIT_GLOBAL_SWITCH, EXIT_SELL_ONLY, PRIV_ROLE |
| tier2/pied-piper/real_0x744d70fdbe2ba4cf95131626614a1763df805b9e_sol | Malicious | no_expected_family | B | EXIT_GLOBAL_SWITCH, LEAK_PRIV_SWEEP, PRIV_ROLE, SLITHER_HIGH_OVERLAY, STRUCT_EXTERNAL_GATE |
| tier2/pied-piper/real_0x765f0c16d1ddc279295c1a7c24b0883f62d33f75_sol | Uncertain | no_expected_family | B | EXIT_GLOBAL_SWITCH, LEAK_PRIV_SWEEP, PRIV_ROLE, SLITHER_HIGH_OVERLAY, STRUCT_EXTERNAL_GATE |
| tier2/pied-piper/real_0x814f67fa286f7572b041d041b1d99b432c9155ee_sol | Malicious | no_expected_family | B | EXIT_SELL_ONLY, PRIV_ROLE, STRUCT_EXTERNAL_GATE |
| tier2/pied-piper/real_0x93ed3fbe21207ec2e8f2d3c3de6e058cb73bc04d_sol | Uncertain | no_expected_family | B | EXIT_GLOBAL_SWITCH, LEAK_PRIV_SWEEP, PRIV_ROLE, SLITHER_HIGH_OVERLAY, STRUCT_EXTERNAL_GATE |
| tier2/pied-piper/real_0xb9e7f8568e08d5659f5d29c4997173d84cdf2607_sol | Uncertain | no_expected_family | B | EXIT_GLOBAL_SWITCH, PRIV_ROLE, STRUCT_EXTERNAL_GATE |
| tier2/pied-piper/real_0xcbeaec699431857fdb4d37addbbdc20e132d4903_sol | Uncertain | no_expected_family | B | EXIT_GLOBAL_SWITCH, LEAK_PRIV_SWEEP, PRIV_ROLE, SLITHER_HIGH_OVERLAY, STRUCT_EXTERNAL_GATE |
| tier2/pied-piper/real_0xd4c435f5b09f855c3317c8524cb1f586e42795fa_sol | Uncertain | no_expected_family | B | EXIT_GLOBAL_SWITCH, LEAK_PRIV_SWEEP, PRIV_ROLE, SLITHER_HIGH_OVERLAY, STRUCT_EXTERNAL_GATE |
| tier2/pied-piper/real_0xe1aee98495365fc179699c1bb3e761fa716bee62_sol | Uncertain | no_expected_family | A | - |

