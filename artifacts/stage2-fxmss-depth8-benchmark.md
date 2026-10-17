# Stage 2: fixed-depth FXMSS verification

## Results

| Metric | Inline | Reusable functions |
|:--|--:|--:|
| Median evaluator time | **0.391 ms** | **0.607 ms** |
| Two 15-epoch medians | 0.393, 0.388 ms | 0.608, 0.606 ms |
| Script | 16,829 bytes | 1,811 bytes |
| FXMSS signature | 642 bytes | 642 bytes |
| Leaf-index witness | 1 byte | 1 byte |
| Complete transaction | 17,925 WU | 2,907 WU |
| Block weight | 0.448125% | 0.072675% |
| Padding | 0 WU | 0 WU |
| Varops | 11,291,069 | 18,053,795 |
| Transaction varops budget | 179,250,000 | 29,070,000 |
| Relative varops consumed | 6.2991% | 62.1046% |
| 80,000-Schnorr controls | 1.224236, 1.229314 s | 1.223231, 1.227950 s |

The timed region is `EvalTapscriptV2` plus its final stack check. It excludes process startup, fixture loading, signing, tree generation and script generation. Both forms use the same WOTS+C signature, eight-node authentication path, digest, key, balanced tree, depth 8 and leaf index `0xad`. The index is a runtime witness input, not a script constant.

The verifier recovers the WOTS+C leaf, applies eight FXMSS `H` hashes in the child order selected by the supplied leaf index, and compares the result with the committed root. This is 250 logical SHA256 calls: the Stage-1 total of 242 plus eight Merkle-parent hashes.

The inline form stores the shared SHA256/address prefix on the altstack but expands every conditional chain step in place. The reusable form defines a 37-byte WOTS+C chain hash, a 182-byte complete chain walk and a 73-byte Merkle-parent hash. Compared with inline, functions reduce script size **9.29×** and full transaction weight **6.17×**. Runtime is **1.55×** and absolute varops **1.60×** higher, but the raw transaction still funds execution with 11,016,205 varops to spare. Neither form uses padding.

This is deliberately not a complete stateful SHRINCS verifier: depth is fixed in the script, and the caller supplies the leaf index and 32-byte digest. Dynamic header parsing, other depths and `H_msg_sf` remain Stage 3 work.

## Provenance and reproduction

- Machine: Apple M4 Pro MacBook Pro (`Mac16,7`), 48 GB RAM.
- Build: `RelWithDebInfo`, AppleClang 17, ARM SHA256 enabled.
- GSR Core: clean `d2799052604eb138c5a79acf88514a0c8b07f4ef`.
- SHRINCS draft base: `4cd63a6497a0ba7c5e99699b94d33973546d9e37`.
- Benchmark harness: `zk/groth16-gsr-field-ops/tools/bench_gsr_script.cpp`, compiled at `-O2 -std=c++20 -arch arm64` against the clean Core build.

SHA256 checksums:

```text
a2a3bd47f76d817eadef2655d662a80f4a80df1cae5ae8cfe09689695aa9e553  stage2-fxmss-depth8-inline-eval.json
404f47e54111ba873b75df5791e56ea937fefcc0a9b8a1bb0119da8450d609de  stage2-fxmss-depth8-inline.json
bdc192ead6e65495d9ae0c3d77fe6941219cb9182397ae2ff643bb5e0f9c131a  stage2-fxmss-depth8-functions-eval.json
fcaaf0ad43d36fc412116c8d218d726ae5e244cfb4be9982407529ddbcb683d3  stage2-fxmss-depth8-functions.json
33e6219689caf9ff7af8feec13a6388ec6a4584ac58e464b03eb242cc4745404  bench_shrincs_gsr_clean
b04a07011a43df0c2866a1ecfdbb29e79fbcd616c905893a5b45d374e3af5ef0  bitcoin-util
31c5225d0d478a2cbd885a56943cc21b8b7a9d0f28d455e4a079ce1dd3b75c15  bench_gsr_script.cpp
```

Benchmark commands, each run twice:

```sh
/private/tmp/bench_shrincs_gsr_clean \
  --input artifacts/stage2-fxmss-depth8-inline-eval.json --epochs 15
/private/tmp/bench_shrincs_gsr_clean \
  --input artifacts/stage2-fxmss-depth8-functions-eval.json --epochs 15
```

Correctness commands:

```sh
GSR_CORE=/private/tmp/gsr-full-shrincs \
GSR_BITCOIN_UTIL=/private/tmp/gsr-full-shrincs/build/bin/bitcoin-util \
python3 -m unittest -v \
  tests/test_stage1_wots_c_inline.py tests/test_stage2_fxmss_fixed.py

GSR_CORE=/private/tmp/gsr-full-shrincs \
python3 research/feature_stage2_fxmss_fixed.py \
  --configfile=/private/tmp/gsr-full-shrincs/build/test/config.ini

SHRINCS_GSR_VARIANT=functions GSR_CORE=/private/tmp/gsr-full-shrincs \
python3 research/feature_stage2_fxmss_fixed.py \
  --configfile=/private/tmp/gsr-full-shrincs/build/test/config.ini
```
