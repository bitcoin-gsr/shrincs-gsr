# Nested-macro SHRINCS experiment

These are **prototype** measurements against the in-progress, uncommitted GSR Core checkout at `bc37aa9c3454-dirty` on an Apple M4 Pro. The source snapshot used by the rebuilt evaluator and benchmark has `src/script/interpreter.cpp` SHA256 `b48b31ea7461c688d4bbd3b608d0ccd4f46ef14049a7efaa35213a373e040de2`. The benchmark harness is `zk/groth16-gsr-field-ops/tools/bench_gsr_script.cpp`, compiled `-O2` against that Core build. Each reported time is one 7-epoch median of Tapscript-v2 evaluation plus final stack check; it excludes signing, transaction generation, process startup, and fixture loading. Compare times **within this table only**.

| Stage | Encoding | Script bytes | Full transaction WU | Varops | Transaction budget used | Evaluation |
|:--|:--|--:|--:|--:|--:|--:|
| WOTS+C | Inline | 50,402 | 51,368 | 10,266,339 | 2.00% | 0.405 ms |
| WOTS+C | Flat macro | 1,956 | 2,922 | 16,334,378 | 55.90% | 0.493 ms |
| WOTS+C | Nested macros | 1,328 | 2,294 | 18,256,624 | 79.58% | 0.495 ms |
| FXMSS depth 8 | Inline | 17,319 | 18,415 | 11,434,583 | 6.21% | 0.452 ms |
| FXMSS depth 8 | Flat macros | 2,313 | 3,409 | 16,905,295 | 49.59% | 0.512 ms |
| FXMSS depth 8 | Nested macros | 1,811 | 2,907 | 18,827,919 | 64.77% | 0.525 ms |

Padding is **zero** for all six rows. Nested WOTS+C defines the 47-byte chain-hash body as macro 0, then the 182-byte chain walk as macro 1; the walk calls macro 0 and the main script calls macro 1. FXMSS uses a 38-byte chain hash at index 0, the same chain walk at index 1, and a 74-byte Merkle-parent hash at index 2. Thus every body calls only a previously defined body. The nested transactions exactly recover the old runtime-function transaction weights, but not their old varops charges or timings.

Both nested transactions passed the evaluator's exact funded-budget check and a regtest block spend. Fifteen project tests passed, including four independently generated valid and corrupted cases per stage. The focused Core Tapscript-v2 unit suite (63 cases) and `feature_tapscript_v2.py` passed. The complete Core unit suite was not run.

One accounting trade-off is visible: the draft intentionally charges a macro reference even in an inactive branch. A minimal skipped `OP_CALLMACRO` adds **4,003 varops**. The chain walk contains many such references, so nested form uses about 1.92 million more varops than flat form at each stage despite similar evaluator time. This is an intentional current rule, not a newly discovered execution failure; whether it is the desired long-term rule remains a design question.

Reproduce the fixtures with `python3 research/stage1_wots_c_inline.py --variant nested-macros` and `python3 research/stage2_fxmss_fixed.py --variant nested-macros`. The generated [WOTS+C result](stage1-wots-c-nested-macros.json) and [FXMSS result](stage2-fxmss-depth8-nested-macros.json) include serialized transactions, hashes, budgets, and evaluator fixture names. Benchmark each corresponding `*-eval.json` with the matching Core-linked harness and `--epochs 7`.
