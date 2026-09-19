# BAYBENCH report — noexit

## Summary

| metric | value |
| --- | --- |
| weighted_score | 0.6579 |
| mean_verdict_score | 0.5483 |
| n_cases | 848 |
| determinism | - |
| runtime_p50 | 48.7083 |
| runtime_p95 | 48.7083 |
| compile_fail_count | 12 |

## Per-tier

| tier | n | mean_score | family_recall | rule_recall | high_fp_rate | evidence_hit_rate | uncertain_rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| tier1_pairs | 61 | 0.7541 | 0.7727 | 0.6818 | 0.0323 | 0.7586 | 0.0164 |
| tier2_realworld | 779 | 0.5315 | 0.5631 | - | - | - | 0.018 |
| tier3_benign_risky | 8 | 0.625 | - | - | 0.375 | - | 0.0 |

## Per-family

| family | n_cases | mean_score |
| --- | --- | --- |
| A | 100 | 0.755 |
| B | 103 | 0.9126 |
| C | 6 | 1.0 |
| D | 3 | 0.0 |
| E | 2 | 1.0 |
| F | 323 | 0.726 |
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
| tier1/BAL_TRANSFER_HIDDEN_MINT/mal | Benign | no_expected_rule | BAL_TRANSFER_HIDDEN_MINT | - |
| tier1/EXIT_CALLBACK_CYCLE/mal | Malicious | no_expected_rule | EXIT_CALLBACK_CYCLE | EXIT_AMOUNT_LIMIT, EXIT_SELL_ONLY, STRUCT_EXTERNAL_GATE |
| tier1/LEAK_ARBITRARY_TRANSFERFROM/mal | Malicious | no_expected_rule | LEAK_ARBITRARY_TRANSFERFROM | BAL_DIRECT_SET, BAL_PRIV_BURN_OTHER |
| tier1/OWN_FAKE_RENOUNCE/mal | Benign | no_expected_rule | OWN_FAKE_RENOUNCE | - |
| tier1/OWN_HIDDEN_ROLE/mal | Benign | no_expected_rule | OWN_HIDDEN_ROLE | - |
| tier1/OWN_REASSIGN_NONSTD/mal | Benign | no_expected_rule | OWN_REASSIGN_NONSTD | - |
| tier1/PRIV_ROLE/mal | Malicious | no_expected_rule | PRIV_ROLE | EXIT_ADDR_GATE |
| tier2/crpwarner/0x10f6f2b97F3aB29583D9D38BaBF2994dF7220C21_sol | Benign | no_expected_family | B | - |
| tier2/crpwarner/0x25d8f027Fd25eecBcd812521fb2F75f175807A91_sol | Benign | no_expected_family | B | - |
| tier2/crpwarner/0x2753dcE37A7eDB052a77832039bcc9aA49Ad8b25_sol | Benign | no_expected_family | A | - |
| tier2/crpwarner/0x50C6eC50a89a946C5886Aeb54a22fe732558F7D1_sol | Malicious | no_expected_family | C | BAL_PRIV_MINT |
| tier2/crpwarner/0x90F75ca026adD95aE15ECBf48EFc77ED272945bE_sol | Benign | no_expected_family | B | - |
| tier2/crpwarner/0x9372b371196751dd2F603729Ae8D8014BbeB07f6_sol | Malicious | no_expected_family | B | LEAK_ARBITRARY_TRANSFERFROM |
| tier2/crpwarner/0x9A3fB36bF72a387fCC821A38eE9F50f1A0eb8Cbd_sol | Benign | no_expected_family | B | - |
| tier2/crpwarner/0xE7E63e244c52b2230666e263657bA8Db2B6b3705_sol | Benign | no_expected_family | B | - |
| tier2/crpwarner/0xEe45E37e2B73E86c709d9edD1c8eA3B0ec72DaD3_sol | Malicious | no_expected_family | A | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/hidden_state_update_0x03209bde47da583547c17c47e7ca74bfa3dfb404_sol | Malicious | no_expected_family | F | EXIT_GLOBAL_SWITCH, FEE_ADDR_MUTABLE, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/hidden_state_update_0x0595d187cac88f04466371eff3a6b6d1b12fb013_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x07ec6c3159c2336ba36ab41f73411f8fee430470_sol | Benign | no_expected_family | F | EXIT_GLOBAL_SWITCH |
| tier2/honeybadger/hidden_state_update_0x0ffb3f4605dd9f01de1a06052b7687418a9d82ee_sol | Malicious | no_expected_family | F | EXIT_TIME_GATE, LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0x11f4306f9812b80e75c1411c1cf296b04917b2f0_sol | Malicious | no_expected_family | F | OWN_REASSIGN_NONSTD |
| tier2/honeybadger/hidden_state_update_0x175744fb0849584129fa3d0e6350c00206d95d2f_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0x1efd5dc066eb56d4db7e2ff38843c8bf8aa59168_sol | Uncertain | no_expected_family | F | BAL_PRIV_BURN_OTHER, EXIT_GLOBAL_SWITCH, LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0x24cad91c063686c49f2ef26a24bf80329fb131c7_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x2634baad203cba4aa4114c132b2e50a3a6027ff9_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x265c91539255a96e1005a0fd11ca776c183d04f5_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x26ae986bfab33f4cbadec30ea55b5eed9e883ecf_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x286bbee3f20f1702e707e58d33dc28a69e7efd4e_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0x2cc8e271f11934f5fa15942dfda2b59432c2e0f3_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x2e4eb4585cb949e53212e796cef13d562c24374b_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x2fe321bbb468d71cc392dd95082efef181df2038_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x377f64e05c29309c8527022dbe5fbbfa8e40f6dd_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x38321bbb97a3541bb3913c12201b35d504f7af39_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0x3c3f481950fa627bb9f39a04bccdc88f4130795b_sol | Malicious | no_expected_family | F | OWN_REASSIGN_NONSTD |
| tier2/honeybadger/hidden_state_update_0x448fcea60482c0ea5d02fa44648c3749c46c4a29_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x53018f93f9240cf7e01301cdc4b3e45d25481f73_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x686847351a61eb1cae8ac0efa4208ff689fd53f2_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x68af0f18c974a9603ec863fefcebb4ceb2589070_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x6f905e47d3e6a9cc286b8250181ee5a0441acc81_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x7409bac00c479b0003651cc157a72d1a227eccfb_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x75658ed3dba1e12644d2cd9272ba9ee888f4c417_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x75890afea0658ed67e145df17948c8fceed0affa_sol | Malicious | no_expected_family | F | EXIT_TIME_GATE, LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0x7a2ac9691ce2fcffb9777311c14a82a6aec7e639_sol | Malicious | no_expected_family | F | EXIT_TIME_GATE, LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0x7c05c837f7a84dced69ae94f8649bbc3897d2b31_sol | Malicious | no_expected_family | F | EXIT_TIME_GATE, LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0x7fefc8bf6e44784ed016d08557e209169095f0f3_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x7ffc2bd9431b059c509b45b33e77852d47de827d_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0x807a3ef8a8dbdd7fc9863df695bbe8691e450e8e_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/hidden_state_update_0x85bc00724203d53536072b000c44a2cc16cd12c5_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x8bce9d720745b93c58c505fc0d842a7d9cd59697_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x8d056569b215c8b56e4b3a615dac425d8d2352a4_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x8d4eb49f0ed7ee6d6e00fc76ea3e9c3898bf219d_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x930dfbdc5e9f1984a8d87de29d6a79fbb2bb7b32_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0x95be22039da3114d17a38b9e7cd9b3576de83924_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/hidden_state_update_0xaa3a6f5bddd02a08c8651f7e285e2bec33ea5e53_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0xaa4fd1781246f0b9a63921f7aee292311ea05bf7_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xabcdd0dbc5ba15804f5de963bd60491e48c3ef0b_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xae3bf0f077ed66dda9fb1b5475942c919ef3bb0d_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0xaec8162438b83646518f3bf3a70b048979f81fab_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xb389327f8325d9568826b0f3ca63ef613687cfab_sol | Malicious | no_expected_family | F | EXIT_TIME_GATE, LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0xb620cee6b52f96f3c6b253e6eea556aa2d214a99_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/hidden_state_update_0xb85a54944b58342b07887942e6f530f616479efd_sol | Malicious | no_expected_family | F | EXIT_TIME_GATE, LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0xb919b2903e07293bc84372471a7081ecb69e8d36_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/hidden_state_update_0xb91a6c5c6362b10db6440d690e5391bb1eabe591_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0xbc272b58e7cd0a6002c95afd1f208898d756c580_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xbf5fb038c28df2b8821988da78c3ebdbf7aa5ac7_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xc1d73e148590b60ce9dd42d141f9b27bbad07879_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0xc304349d7cc07407b7844d54218d29d1a449b854_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xc5ce9c06a0caf0e4cbd90572b6550feafd69b740_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xc6389ef3d79cf17a5d103bd0f06f83cf76b14258_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xc8b2c33a45ce83d19da15a58d1d1ddb2738506bf_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xcb71b51d9159a49050d56516737b4b497e98bb99_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0xd0981f1e922be67f2d0bb4f0c86f98f039dd24cc_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xdfe06d5a4534fbe955eebe8a4908ef596763c2a4_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xe35a91f2acceccf1ce6bae792274da6100b639af_sol | Malicious | no_expected_family | F | EXIT_TIME_GATE, LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0xe3b0fe57f7de3281579a504dcc3af491afbb23e5_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xe830d955cbe549d9bcf55e3960b86ffac6ef83f1_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xed4fd2e53153b8bfd866e11fb015a1bc4a0e9655_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0xef75f477126d05519d965d116fc9606e60fc70a8_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xefbfc3f373c9cc5c0375403177d71bcc387d3597_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xf331f7887d31714dce936d9a9846e6afbe82e0a0_sol | Malicious | no_expected_family | F | FEE_UNBOUNDED, LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0xf3f3dd2b5d9f3de1b1ceb6ad84683bf31adf29d1_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/hidden_state_update_0xf6b55acbbc49f4524aa48d19281a9a77c54de10f_sol | Malicious | no_expected_family | F | BAL_DIRECT_SET, EXIT_GLOBAL_SWITCH, EXIT_TIME_GATE, LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_state_update_0xfb0513602b08ede66c28c128ece6a2f11161f17f_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_transfer_0x3f2ef511aa6e75231e4deafc7a3d2ecab3741de2_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_transfer_0x55654a38372617aedd583009f76e28700e48fdad_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_transfer_0x78c2a1e91b52bca4130b6ed9edd9fbcfd4671c37_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_transfer_0x7a4349a749e59a5736efb7826ee3496a2dfd5489_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_transfer_0x806a6bd219f162442d992bdc4ee6eba1f2c5a707_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_transfer_0xc7f4ade4874e06a20fab9c5dc4f1dd8b6d85faf2_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_transfer_0xd2018bfaa266a9ec0a1a84b061640faa009def76_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_transfer_0xdb1c55f6926e7d847ddf8678905ad871a68199d2_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_transfer_0xe4eabdca81e31d9acbc4af76b30f532b6ed7f3bf_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_transfer_0xe82f0742a71a02b9e9ffc142fdcb6eb1ed06fb87_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/hidden_transfer_0xf70d589d76eebdd7c12cc5eec99f8f6fa4233b9e_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/inheritance_disorder_0x017bcaee2456d8bd0e181f94165919a4a2ecc2d9_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/inheritance_disorder_0x038e20839aebfe12b7956adcbc2511f6f7085164_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x07f06a75ddf49de735d51dbf5c0a9062c034e7c6_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/inheritance_disorder_0x0bcccba050c2ce6439c57bd203378b113cc3cfd6_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/inheritance_disorder_0x11f3081cd6b2ac5a263e65e206f806bea7fa9c56_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/inheritance_disorder_0x1767856bc75cf070de5e6ba3d0c718440f008c66_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x2d05359a51ca13c4ac5f4437585afaf5bf2050f9_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x33685492a20234101b553d2a429ae8a6bf202e18_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/inheritance_disorder_0x33b44a1d150f3feaa40503ad20a75634adc39b18_sol | Malicious | no_expected_family | F | OWN_REASSIGN_NONSTD, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x340844b39aacbdb4e7718fa14a95758f87a09a9a_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/inheritance_disorder_0x3526cf7d12c95b11a680678cc1f705cba667578d_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x3e7840b88396acd80bac66021e1354064461a498_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x4ba0d338a7c41cc12778e0a2fa6df2361e8d8465_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/inheritance_disorder_0x4c7c98c4d64c29ef8103b005eeccf5145cfdf8c1_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x4dc76cfc65b14b3fd83c8bc8b895482f3cbc150a_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/inheritance_disorder_0x4fed7f5f0314bd156a8486fc41dc8bd4737c24fb_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/inheritance_disorder_0x50abfc76b637b70571c301071f7ce660c1c3d847_sol | Malicious | no_expected_family | F | OWN_REASSIGN_NONSTD |
| tier2/honeybadger/inheritance_disorder_0x50ddfe3722fc303cace413df41db23d55025e2e6_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/inheritance_disorder_0x52c2d09acf0ef12c487ae0c20a92d4f9a4abbfd1_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x5b2028602af2693d50b4157f4acf84d632ec8208_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x5c8546a7b86ba30202c09a84f5a72644a2a4f7ba_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x641074844a0dd00042347161f830346bdfe348bc_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x68563d2a5fc58f88db8140a981170989f001b746_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x6e843aefc1f2887e5b0aeb4002c1924c433d9a13_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x70c01853e4430cae353c9a7ae232a6a95f6cafd9_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/inheritance_disorder_0x7704442e1005b9ab403463ed85e2fb24761a8738_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/inheritance_disorder_0x787080326e1f7e0eae490efdb18e90cfd0ae2692_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/inheritance_disorder_0x78faf034c61f4158a4a12bfa372187a21405ae33_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/inheritance_disorder_0x7e97c48497a8d650dc030744b74c81e29816f8e3_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/inheritance_disorder_0x81edefc64aabdce71f68347774bd4673d1d31419_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/inheritance_disorder_0x849019a489c3c26c7a7668e468be81a4d132781f_sol | Malicious | no_expected_family | F | OWN_REASSIGN_NONSTD, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x9168fdc9f9db7b71865fe4bfd6f78b3610ebc704_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x96050da7c01bbd4891ed766720a5c1c79b824163_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0x98fe1d52649a3a13863647c6789f16e46e090377_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/inheritance_disorder_0x9c0c5a14fde1306686a8a270f271165acda670c2_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/inheritance_disorder_0xa16cdcba1d6cb6874ff9fd8a6c8b82a3f834f512_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0xb31820c1d84e183377030b6d3f0e1ee5c1cff643_sol | Malicious | no_expected_family | F | OWN_REASSIGN_NONSTD, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0xc0c7d89e4968775931e53e9510ebad43644b0866_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/inheritance_disorder_0xcacf9396a56e9ff1e3f6533be83a043c36ce0436_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0xe65c53087e1a40b7c53b9a0ea3c2562ae2dfeb24_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/inheritance_disorder_0xf1aab4171ceb49b6a276975347e3c1d4d5650e5a_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0xf5615138a7f2605e382375fa33ab368661e017ff_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/inheritance_disorder_0xfae0300c03a1ea898176bcb39f919c559f64f4ff_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/inheritance_disorder_0xfdc39e06a7297268a0f6d5bd1692ae5fa9026152_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/inheritance_disorder_0xff41067fe843f190482d998a9976c7b19cd7c8b7_sol | Malicious | no_expected_family | F | BAL_PRIV_MINT, LEAK_ARBITRARY_TRANSFERFROM, LEAK_PRIV_SWEEP |
| tier2/honeybadger/named_DividendDistributor_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/named_EtherBet_sol | Malicious | no_expected_family | F | OWN_REASSIGN_NONSTD |
| tier2/honeybadger/named_For_Test_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/named_GuessNumber_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/named_ICO_Hold_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/named_KingOfTheHill_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/named_OpenAddressLottery_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/named_PrivateBank_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/named_RACEFORETH_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/named_RichestTakeAll_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/named_TerrionFund_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/named_Test1_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/named_TestBank_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD |
| tier2/honeybadger/named_TransferReg_sol | Malicious | no_expected_family | F | STRUCT_DELEGATECALL_SETTABLE |
| tier2/honeybadger/named_TrustFund_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/named_WhaleGiveaway1_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/named_X2_FLASH_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/named_firstTest_sol | Malicious | no_expected_family | F | STRUCT_DELEGATECALL_SETTABLE, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/named_testBank2_sol | Malicious | no_expected_family | F | STRUCT_DELEGATECALL_SETTABLE, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/skip_empty_string_literal_0x7bc51b19abe2cfb15d58f845dad027feab01bfa0_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/skip_empty_string_literal_0x858c9eaf3ace37d2bedb4a1eb6b8805ffe801bba_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/skip_empty_string_literal_0xa0174f796d3b901adaa16cfbb589330462be0329_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/skip_empty_string_literal_0xa395480a4a90c7066c8ddb5db83e2718e750641c_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/skip_empty_string_literal_0xaa12936a79848938770bdbc5da0d49fe986678cc_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/skip_empty_string_literal_0xd022969da8a1ace11e2974b3e7ee476c3f9f99c6_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/skip_empty_string_literal_0xe63760e74ffd44ce7abdb7ca2e7fa01b357df460_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/straw_man_contract_0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/straw_man_contract_0x23a91059fdc9579a9fbd0edc5f2ea0bfdb70deb4_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/straw_man_contract_0x4320e6f8c05b27ab4707cd1f6d5ce6f3e4b3a5a1_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/straw_man_contract_0x463f235748bc7862deaa04d85b4b16ac8fafef39_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/straw_man_contract_0x477d1ee2f953a2f85dbecbcb371c2613809ea452_sol | Malicious | no_expected_family | F | STRUCT_DELEGATECALL_SETTABLE, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/straw_man_contract_0x4e73b32ed6c35f570686b89848e5f39f20ecc106_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/straw_man_contract_0x561eac93c92360949ab1f1403323e6db345cbf31_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/straw_man_contract_0x62d5c4a317b93085697cfb1c775be4398df0678c_sol | Malicious | no_expected_family | F | STRUCT_DELEGATECALL_SETTABLE |
| tier2/honeybadger/straw_man_contract_0x7a7d08bcb2faf27414e86ecf9a0351d928054b6b_sol | Malicious | no_expected_family | F | STRUCT_DELEGATECALL_SETTABLE |
| tier2/honeybadger/straw_man_contract_0x7a8721a9d64c74da899424c1b52acbf58ddc9782_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/straw_man_contract_0x8c7777c45481dba411450c228cb692ac3d550344_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/straw_man_contract_0x941d225236464a25eb18076df7da6a91d0f95e9e_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/straw_man_contract_0x95d34980095380851902ccd9a1fb4c813c2cb639_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/straw_man_contract_0xa5d6accc5695327f65cbf38da29198df53efdcf0_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/straw_man_contract_0xa91a453abde404a303fb118c46e00c8f630216a9_sol | Malicious | no_expected_family | F | STRUCT_DELEGATECALL_SETTABLE |
| tier2/honeybadger/straw_man_contract_0xaae1f51cf3339f18b6d3f3bdc75a5facd744b0b8_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/straw_man_contract_0xb4c05e6e4cdb07c15095300d96a5735046eef999_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/straw_man_contract_0xb5e1b1ee15c6fa0e48fce100125569d430f1bd12_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/straw_man_contract_0xb93430ce38ac4a6bb47fb1fc085ea669353fd89e_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/straw_man_contract_0xbabfe0ae175b847543724c386700065137d30e3b_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/straw_man_contract_0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/straw_man_contract_0xbe4041d55db380c5ae9d4a9b9703f1ed4e7e3888_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/straw_man_contract_0xbf64a825e602a4f1c31480a470e99e1d896c88a7_sol | Malicious | no_expected_family | F | BAL_DIRECT_SET, BAL_PRIV_BURN_OTHER, LEAK_PRIV_SWEEP, OWN_REASSIGN_NONSTD, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/straw_man_contract_0xd116d1349c1382b0b302086a4e4219ae4f8634ff_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/straw_man_contract_0xd518db222f37f9109db8e86e2789186c7e340f12_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/straw_man_contract_0xdad02644b70cbb20dec56d25282ddc65bb7805a1_sol | Malicious | no_expected_family | F | STRUCT_DELEGATECALL_SETTABLE |
| tier2/honeybadger/straw_man_contract_0xdd17afae8a3dd1936d1113998900447ab9aa9bc0_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/straw_man_contract_0xe610af01f92f19679327715b426c35849c47c657_sol | Malicious | no_expected_family | F | STRUCT_EXTERNAL_GATE |
| tier2/honeybadger/straw_man_contract_0xff5a11c0442028ee2a60d31e6ebb3cbac121ffe5_sol | Malicious | no_expected_family | F | STRUCT_DELEGATECALL_SETTABLE |
| tier2/honeybadger/type_deduction_overflow_0x2ecf8d1f46dd3c2098de9352683444a0b69eb229_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/type_deduction_overflow_0x752406cbfd32593fc422da69cdd702d1eaadc121_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/type_deduction_overflow_0x791d0463b8813b827807a36852e4778be01b704e_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/type_deduction_overflow_0xf5b1d75f4415f853fef2466a5ab8e412d593dd44_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/uninitialised_struct_0x2075d158924f5030aece55179848c2bd7ec5833f_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0x29d6cf436c893c7e44ea926411d5fd4dd763d9b3_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0x2f069a1d7a052052458e8b5511e91221eb337c52_sol | Benign | no_expected_family | F | LEAK_PRIV_SWEEP |
| tier2/honeybadger/uninitialised_struct_0x3268ecb4fcba1ca9f43da8ed05ffc80382cef1da_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0x4fdc2078d8bc92e1ee594759d7362f94b60b1a3d_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0x559cc6564ef51bd1ad9fbe752c9455cb6fb7feb1_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0x6324d9d0a23f5ddba165bf8cc61da455350895f2_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0x650734bfd0465b7c6cd2932ea555e721308fd0b3_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0x6a2e025f43ca4d0d3c61bdee85a8e37e81880528_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0x741f1923974464efd0aa70e77800ba5d9ed18902_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0x74808c86c6f0bc6f59a3a1430ddfcd2e29952eac_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0x783cf9c6754bf826f1727620b4baa19714fedf8d_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/uninitialised_struct_0x787b9a8978b21476abb78876f24c49c0e513065e_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0xad1aa68300588aa5842751ddcab2afd4a69e9016_sol | Benign | no_expected_family | F | - |
| tier2/honeybadger/uninitialised_struct_0xc57fc2c9fd3130933bd29f01ff940dc52bc4115b_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0xe19ca313512e0231340e778abe7110401c737c23_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0xe6f245bb5268b16c5d79a349ec57673e477bd015_sol | Malicious | no_expected_family | F | STRUCT_SELFDESTRUCT |
| tier2/honeybadger/uninitialised_struct_0xefba96262f277cc8073da87e564955666d30a03b_sol | Malicious | no_expected_family | F | LEAK_PRIV_SWEEP, STRUCT_SELFDESTRUCT |
| tier2/pied-piper/injected_DestroyToken_40_sol | Malicious | no_expected_family | B | STRUCT_SELFDESTRUCT |
| tier2/pied-piper/injected_FreezeAccount_8_sol | Benign | no_expected_family | A | - |
| tier2/pied-piper/real_0x17280da053596e097604839c61a2ef5efb7d493f_sol | Malicious | no_expected_family | A | BAL_PRIV_MINT |
| tier2/pied-piper/real_0x1829aa045e21e0d59580024a951db48096e01782_sol | Benign | no_expected_family | B | LEAK_PRIV_SWEEP |
| tier2/pied-piper/real_0x46b9ad944d1059450da1163511069c718f699d31_sol | Malicious | no_expected_family | B | EXIT_ADDR_GATE, EXIT_GLOBAL_SWITCH, EXIT_SELL_ONLY, EXIT_TIME_GATE, OWN_REASSIGN_NONSTD |
| tier2/pied-piper/real_0x6e8b6f2d02eacbe33b4c45154cbfa53df1b542ea_sol | Benign | no_expected_family | A | - |
| tier2/pied-piper/real_0x6f7a4bac3315b5082f793161a22e26666d22717f_sol | Benign | no_expected_family | A | - |
| tier2/pied-piper/real_0x744d70fdbe2ba4cf95131626614a1763df805b9e_sol | Malicious | no_expected_family | B | EXIT_GLOBAL_SWITCH, LEAK_ARBITRARY_TRANSFERFROM, LEAK_PRIV_SWEEP, STRUCT_EXTERNAL_GATE |
| tier2/pied-piper/real_0x765f0c16d1ddc279295c1a7c24b0883f62d33f75_sol | Malicious | no_expected_family | B | EXIT_GLOBAL_SWITCH, LEAK_ARBITRARY_TRANSFERFROM, LEAK_PRIV_SWEEP, STRUCT_EXTERNAL_GATE |
| tier2/pied-piper/real_0x814f67fa286f7572b041d041b1d99b432c9155ee_sol | Benign | no_expected_family | B | - |
| tier2/pied-piper/real_0x8bcb64bfda77905398b67af0af084c744e777a20_sol | Benign | no_expected_family | A | - |
| tier2/pied-piper/real_0x93ed3fbe21207ec2e8f2d3c3de6e058cb73bc04d_sol | Malicious | no_expected_family | B | EXIT_GLOBAL_SWITCH, LEAK_ARBITRARY_TRANSFERFROM, LEAK_PRIV_SWEEP, STRUCT_EXTERNAL_GATE |
| tier2/pied-piper/real_0xb9e7f8568e08d5659f5d29c4997173d84cdf2607_sol | Malicious | no_expected_family | B | EXIT_GLOBAL_SWITCH, LEAK_ARBITRARY_TRANSFERFROM, STRUCT_EXTERNAL_GATE |
| tier2/pied-piper/real_0xcbeaec699431857fdb4d37addbbdc20e132d4903_sol | Malicious | no_expected_family | B | EXIT_GLOBAL_SWITCH, LEAK_ARBITRARY_TRANSFERFROM, LEAK_PRIV_SWEEP, STRUCT_EXTERNAL_GATE |
| tier2/pied-piper/real_0xd4c435f5b09f855c3317c8524cb1f586e42795fa_sol | Malicious | no_expected_family | B | EXIT_GLOBAL_SWITCH, LEAK_ARBITRARY_TRANSFERFROM, LEAK_PRIV_SWEEP, STRUCT_EXTERNAL_GATE |
| tier2/pied-piper/real_0xfa456cf55250a839088b27ee32a424d7dacb54ff_sol | Uncertain | no_expected_family | A | BAL_DIRECT_SET, BAL_PRIV_BURN_OTHER |

