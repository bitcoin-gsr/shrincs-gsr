# Static-macro backend: stages 1 and 2

These are measurements of the **current, uncommitted** GSR backend (`bc37aa9c3454-dirty`), not the earlier `OP_DEFINE`/`OP_INVOKE` backend. Both variants at each stage use the same proof, witness, tree, evaluator, cost schedule, and Apple M4 Pro host. The benchmark compiles `tools/bench_gsr_script.cpp` at `-O2` against the current Core `RelWithDebInfo` build and times `EvalTapscriptV2` plus the final stack check. Times exclude process startup, signing, and fixture generation.

| Stage | Encoding | Script bytes | Full tx WU | Padding WU | Varops | Tx varops used | Evaluator median, 7 / 15 epochs |
|:--|:--|--:|--:|--:|--:|--:|--:|
| WOTS+C | Inline | 50,402 | 51,368 | 0 | 10,266,339 | 2.00% | 0.612 / 0.623 ms |
| WOTS+C | Static macro | 1,956 | 2,922 | 0 | 16,334,378 | 55.90% | 0.724 / 0.723 ms |
| FXMSS depth 8 | Inline | 17,319 | 18,415 | 0 | 11,434,583 | 6.21% | 0.672 / 0.677 ms |
| FXMSS depth 8 | Static macros | 2,313 | 3,409 | 0 | 16,905,295 | 49.59% | 0.740 / 0.772 ms |

All four exact transactions were accepted in regtest blocks. The macro variant's 15-step WOTS+C chain body is flattened because macro bodies cannot call another macro. Stage 2 defines that body (index 0) and the Merkle-parent body (index 1) before the main script. Calls encode a CompactSize index in the script, not an ID on the stack. The current `OP_MULTI OP_SHA256` hashes length-framed items, so both variants explicitly use `OP_MULTI OP_CAT OP_SHA256` to preserve SHRINCS's raw-concatenation hash.

The new static macros reduce full transaction weight by **17.6×** at stage 1 and **5.40×** at stage 2, at the cost of about **10–16%** more evaluator time and **1.59× / 1.48×** more absolute varops than current inline encoding. This is a within-backend comparison; the older benchmark records used a different, clean Core revision and a different `OP_MULTI` hash behavior.

Fixtures and transaction results: [stage 1 inline](stage1-wots-c-inline-current.json), [stage 1 macros](stage1-wots-c-macros.json), [stage 2 inline](stage2-fxmss-depth8-inline-current.json), [stage 2 macros](stage2-fxmss-depth8-macros.json). Each result identifies its evaluator fixture, script hash, full transaction weight, and exact budget. Run `python3 research/stage1_wots_c_inline.py --variant macros` or `python3 research/stage2_fxmss_fixed.py --variant macros` to regenerate the macro artifacts; use `--variant inline --artifact-tag inline-current` for inline artifacts. Then benchmark each `*-eval.json` with `/private/tmp/bench_shrincs_gsr_static --input FILE --epochs 15` after compiling the harness against the matching Core build.

Core source SHA256: `interpreter.cpp` `59a521ef0d5c79bca64a8ef1c10480700af142caac1370b8674bce21c94ea3b3`; `script.h` `f11ac616333d317ac72bc39da03d92508f641cc89c47a7455ae22e640cf42650`; `varops.h` `fdecbe7f71dcefb96c535c9563957e5a6a0d3a415c9fa247e8030558ec9818c7`.
