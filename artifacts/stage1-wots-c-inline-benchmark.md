# Stage 1: inline WOTS+C verification

## Result

| Metric | Measured value |
|:--|--:|
| Median evaluator time | **0.350 ms** |
| Two independent 15-epoch medians | 0.350 ms, 0.349 ms |
| Inline script | 49,920 bytes |
| WOTS+C signature | 514 bytes |
| Complete transaction | 50,886 WU |
| Block weight | 1.27215% |
| Padding | 0 WU |
| Varops | 10,127,721 |
| Transaction varops budget | 508,860,000 |
| Relative varops consumed | 1.9902765% |
| 80,000-Schnorr control medians | 1.215605 s, 1.217388 s |

The timed region is `EvalTapscriptV2` plus its final stack check. It excludes process startup, fixture loading, signing and script generation. The two benchmark runs alternated verifier and 80,000-Schnorr control measurements.

The transaction has one Tapscript-v2 input, so all 50,886 WU participate in BIP 440 accounting. Its raw serialization already supplies over 50 times the verifier's required budget weight; no padding was added. A clean committed node accepted the exact-weight construction in a regtest block.

## What executes

The script implements `wots_c_pubkey_from_sig` from the upstream Python reference. It validates the two-byte grinding counter, derives 32 four-bit indexes, checks that they sum to 240, executes the corresponding 240 chain hashes, hashes all recovered chain tips and compares the result with the committed key.

There are 242 logical SHA256 operations: one grinding hash, 240 chain hashes and one final compression of the chain tips. `OP_MULTI OP_SHA256` hashes concatenated stack values without materializing each concatenation. The verifier uses no `OP_DEFINE`, `OP_INVOKE`, native signature operation or field-arithmetic operation.

## Provenance

- Machine: Apple M4 Pro MacBook Pro (`Mac16,7`), 48 GB RAM.
- Build: `RelWithDebInfo`, AppleClang 17, ARM SHA256 enabled.
- GSR Core: clean `d2799052604eb138c5a79acf88514a0c8b07f4ef`.
- SHRINCS draft base: `4cd63a6497a0ba7c5e99699b94d33973546d9e37`.
- Evaluator fixture: `stage1-wots-c-inline-eval.json`.
- Result data: `stage1-wots-c-inline.json`.
- Benchmark source: `zk/groth16-gsr-field-ops/tools/bench_gsr_script.cpp`.

SHA256 checksums:

```text
56adb0e01c904ba9f2ab9af02857f278c1338fb0832e802faf92ad81246bccb7  stage1-wots-c-inline-eval.json
1bfb02253375b49e4ed722fd7b9d38be215eab6cc93e858462e0aa51fc8a3761  stage1-wots-c-inline.json
33e6219689caf9ff7af8feec13a6388ec6a4584ac58e464b03eb242cc4745404  bench_shrincs_gsr_clean
b04a07011a43df0c2866a1ecfdbb29e79fbcd616c905893a5b45d374e3af5ef0  bitcoin-util
31c5225d0d478a2cbd885a56943cc21b8b7a9d0f28d455e4a079ce1dd3b75c15  bench_gsr_script.cpp
```

The benchmark harness was compiled at `-O2 -std=c++20 -arch arm64` against the clean Core build. It was run twice with:

```sh
/private/tmp/bench_shrincs_gsr_clean \
  --input artifacts/stage1-wots-c-inline-eval.json \
  --epochs 15
```

Correctness checks:

```sh
GSR_CORE=/private/tmp/gsr-full-shrincs \
GSR_BITCOIN_UTIL=/private/tmp/gsr-full-shrincs/build/bin/bitcoin-util \
python3 -m unittest -v tests/test_stage1_wots_c_inline.py

GSR_CORE=/private/tmp/gsr-full-shrincs \
python3 research/feature_stage1_wots_c.py \
  --configfile=/private/tmp/gsr-full-shrincs/build/test/config.ini
```

This stage accepts a caller-supplied 32-byte digest. It does not yet construct or bind a Bitcoin transaction message, and WOTS+C alone is a one-time-signature component rather than complete SHRINCS authorization.
