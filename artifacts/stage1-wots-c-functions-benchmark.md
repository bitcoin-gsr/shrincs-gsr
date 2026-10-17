# Stage 1: WOTS+C verification with reusable functions

## Result

| Metric | Measured value |
|:--|--:|
| Median evaluator time | **0.576 ms** |
| Two independent 15-epoch medians | 0.577 ms, 0.576 ms |
| Script | 1,328 bytes |
| WOTS+C signature | 514 bytes |
| Complete transaction | 2,294 WU |
| Block weight | 0.05735% |
| Padding | 0 WU |
| Varops | 17,468,443 |
| Transaction varops budget | 22,940,000 |
| Relative varops consumed | 76.1484% |
| 80,000-Schnorr control medians | 1.214444 s, 1.214539 s |

The timed region is `EvalTapscriptV2` plus its final stack check. It excludes process startup, fixture loading, signing and script generation. The two benchmark runs alternated verifier and 80,000-Schnorr control measurements.

The transaction has one Tapscript-v2 input, so all 2,294 WU participate in BIP 440 accounting. Its raw serialization funds the verifier with 5,471,557 varops to spare; no padding was added. A clean committed node accepted the exact-weight construction in a regtest block.

## What changed

The verifier performs exactly the same WOTS+C computation as the inline variant. It defines a 46-byte function for a chain hash and a 182-byte function for the full conditional 15-step chain walk. The second function invokes the first. The outer script invokes the chain walk 32 times, causing exactly 240 active chain-hash invocations for this signature.

Compared with the inline form, reusable functions reduce script size **37.6×** (49,920 to 1,328 bytes) and full transaction weight **22.2×** (50,886 to 2,294 WU). Runtime increases **1.65×** (0.350 to 0.576 ms), and absolute varops increase **1.72×** (10.13M to 17.47M), principally because invocation and dynamic address construction replace duplicated constants.

## Provenance

- Machine: Apple M4 Pro MacBook Pro (`Mac16,7`), 48 GB RAM.
- Build: `RelWithDebInfo`, AppleClang 17, ARM SHA256 enabled.
- GSR Core: clean `d2799052604eb138c5a79acf88514a0c8b07f4ef`.
- SHRINCS draft base: `4cd63a6497a0ba7c5e99699b94d33973546d9e37`.
- Evaluator fixture: `stage1-wots-c-functions-eval.json`.
- Result data: `stage1-wots-c-functions.json`.
- Benchmark source: `zk/groth16-gsr-field-ops/tools/bench_gsr_script.cpp`.

SHA256 checksums:

```text
ad450ddd007423e1ebbe5da8097bd1b8897f6e561292b71aa0ccd2ff63077d13  stage1-wots-c-functions-eval.json
022d48d05dd696ee669f651d828cf626d150b017d28ba1e4b3c51f86472a385f  stage1-wots-c-functions.json
33e6219689caf9ff7af8feec13a6388ec6a4584ac58e464b03eb242cc4745404  bench_shrincs_gsr_clean
b04a07011a43df0c2866a1ecfdbb29e79fbcd616c905893a5b45d374e3af5ef0  bitcoin-util
31c5225d0d478a2cbd885a56943cc21b8b7a9d0f28d455e4a079ce1dd3b75c15  bench_gsr_script.cpp
```

The benchmark harness was compiled at `-O2 -std=c++20 -arch arm64` against the clean Core build. It was run twice with:

```sh
/private/tmp/bench_shrincs_gsr_clean \
  --input artifacts/stage1-wots-c-functions-eval.json \
  --epochs 15
```

Correctness checks:

```sh
GSR_CORE=/private/tmp/gsr-full-shrincs \
GSR_BITCOIN_UTIL=/private/tmp/gsr-full-shrincs/build/bin/bitcoin-util \
python3 -m unittest -v tests/test_stage1_wots_c_inline.py

SHRINCS_GSR_VARIANT=functions GSR_CORE=/private/tmp/gsr-full-shrincs \
python3 research/feature_stage1_wots_c.py \
  --configfile=/private/tmp/gsr-full-shrincs/build/test/config.ini
```

This stage accepts a caller-supplied 32-byte digest. It does not yet construct or bind a Bitcoin transaction message, and WOTS+C alone is a one-time-signature component rather than complete SHRINCS authorization.
