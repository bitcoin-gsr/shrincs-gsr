# SHRINCS in GSR Script

Post-quantum signatures checked by ordinary Bitcoin Script on the GSR branch (Tapleaf 0xC2: BIP 440 varops budget, BIP 441 restored opcodes and static macros, `OP_TX`). The scheme is the [upstream SHRINCS draft](https://github.com/SHRINCS/shrincs-bip) at `4cd63a6`. It combines a stateful hash-based signature (WOTS+C one-time keys in an FXMSS tree) with a stateless SPHINCS+-style fallback. Measurements use node `jmoik/bitcoin` branch `gsr` at `ad6c16f`.

## Result

- **Spend cost.** Bound to its transaction, a SHRINCS spend costs **516 vB** with a stateful signature (a key for 256 signatures) and **1,853 vB** with the stateless fallback. A Schnorr key-path spend of the same shape is about 111 vB, so these are 4.6× and 17× larger.
- **Budget.** Both fit the GSR budget without a new opcode. The stateful spend uses 55% of the varops its own weight buys. The stateless spend uses 97–100%. About 3% of stateless signatures need padding; at the 99th percentile that is 70 WU.
- **Lock cost.** Locking costs the same for every variant: one 43-byte output (172 WU) and no varops. The leaf script (0.6–1.2 KB) is only revealed at spend, where it is counted.
- **Correctness.**
  - All 14 variants were spent on regtest through the mempool and a block.
  - Differential tests check that each verifier accepts exactly what the Python reference accepts.
  - A signature bound by `OP_TX` fails in any other transaction.
- **Other schemes.** Under the same cost model, only SHRINCS stateful stays under 600 vB:
  - XMSS costs about 2× the stateful spend.
  - SLH-DSA-SHA2-128s costs 1.4× the stateless SHRINCS spend.
  - Standard Falcon-512 is dominated by SHAKE256. Keccak-f, measured at 14.4M varops, puts it at about 4.7 kvB.

**Verdict: a strong demo, with one hard limit.**

Why it is strong:
- It is a complete post-quantum authorization path (verify and bind) built only from generic opcodes.
- The stateful cost is in the range of an ordinary complex script (about 0.5 kvB).
- Adopting or replacing a scheme takes a new leaf, not a soft fork.

The limits:
- **Hard limit:** the protection holds only in script-only outputs (P2MR, BIP 360). In P2TR the key path stays quantum-vulnerable.
- The stateless path sits at the edge of its budget.
- Stateful signing needs reliable state.
- None of the code is audited.

## How GSR provides post-quantum signatures

A verifier is ordinary Script, so there is no signature opcode to standardize. A soft fork for GSR once allows any scheme whose verifier fits the budget. Each building block maps to a feature:

| Need | GSR feature |
|---|---|
| Tweakable hash `SHA256(pk_seed ‖ 0⁴⁸ ‖ ADRS ‖ M)` | `SHA256`, `CAT`, `LEFT`, `SUBSTR` on elements up to 4 MB |
| Message digits, checksums, leaf indexes, big-endian addresses | Arithmetic and bitwise ops on large numbers: `ADD`, `RSHIFT`, `AND`, `BYTEREV`, `WITHIN` |
| 240–1,500 chain steps | Static macros (`OP_MACRO` / `OP_CALLMACRO`): 11–73 KB of code becomes 0.6–1.2 KB |
| The signed message | `OP_TX` collates the spending transaction (like `SIGHASH_ALL` plus the tapleaf hash) |
| Paying for it | 10,000 varops per weight unit: the signature's own bytes fund its verification |

**Where the varops go.** In the stateful and stateless spends (5a, 5b):
- Macro unrolling: 26% and 25%.
- SHA-256 itself: about 12%.
- The rest, about 62%: pushes, stack moves, byte slicing and digit arithmetic.

So the cost is set by the instruction count, not by hashing. Every instruction pays a base of 300, plus reads and writes: a push costs about 1.2k, an 8-byte XOR about 1.3k, and a 102-byte SHA-256 about 6.5k. For scale, one stateful verification costs as many varops as 22 `CHECKSIG`s and takes 0.25 ms.

**What GSR does not solve:**
- The Taproot key path (see [Security](#security)).
- Script has no loops. Every possible chain step must exist as code, so skipped steps still pay the unroll charge. A verifier sized for depth 255 pays 6.7M before it runs.
- Bit-oriented hashes are expensive. A Keccak-f permutation costs as much as about 2,800 SHA-256 calls on 64 bytes.

## Cost per stage

**Lock.** Every variant locks into one output: 8-byte amount and a 34-byte witness program (P2TR here; P2MR has the same size). That is 43 B, or 172 WU in the funding transaction, with no varops. The output commits to the leaf script but does not contain it. **Spend.** The table below is one input and one output, paying back to the same script. It is reproduced by `gsr/measure.py`. Timings are the median of 25 runs of `txeval` on an Apple M4 Pro, verification only.

| id | variant | script B (unrolled) | signature B | witness B | tx WU | vsize vB | varops | unroll charge | budget used | padding WU | verify µs |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1a | WOTS+C, inline | 11,234 | 514 | 11,822 | 12,200 | 3,050 | 7.60M | 0.00M | 6.2% | 0 | 241 |
| 1b | WOTS+C, macros | 609 (11,234) | 514 | 1,197 | 1,575 | 394 | 10.40M | 2.80M | 68.2% | 0 | 236 |
| 2a | FXMSS depth 8, inline | 12,281 | 642 | 12,999 | 13,377 | 3,345 | 8.02M | 0.00M | 6.0% | 0 | 268 |
| 2b | FXMSS depth 8, macros | 773 (12,281) | 642 | 1,491 | 1,869 | 468 | 10.93M | 2.91M | 60.1% | 0 | 259 |
| 3a | UXMSS-255 key, 1st signature (depth 1) | 990 (45,333) | 548 | 1,612 | 1,990 | 498 | 15.48M | 6.74M | 79.8% | 0 | 333 |
| 3b | BXMSS-8 key (256 signatures) | 948 (12,480) | 660 | 1,682 | 2,060 | 515 | 11.10M | 2.93M | 55.2% | 0 | 262 |
| 3c | UXMSS-20 key, depth-20 signature (= any BXMSS-20 signature) | 959 (14,077) | 854 | 1,887 | 2,265 | 567 | 11.95M | 3.11M | 53.9% | 0 | 280 |
| 3d | UXMSS-255 key, depth 64 | 990 (45,333) | 1,563 | 2,627 | 3,005 | 752 | 18.94M | 6.74M | 64.1% | 0 | 412 |
| 3e | UXMSS-255 key, last signature (depth 255) | 990 (45,333) | 4,619 | 5,683 | 6,061 | 1,516 | 33.32M | 6.74M | 55.4% | 0 | 640 |
| 4a | stateless, signature 1 | 1,155 (72,647) | 5,777 | 7,007 | 7,385 | 1,847 | 72.83M | 18.25M | 99.3% | 0 | 1,625 |
| 4b | stateless, signature 2 | 1,155 (72,647) | 5,777 | 7,007 | 7,385 | 1,847 | 72.34M | 18.25M | 98.6% | 0 | 1,717 |
| 4c | stateless, signature 3 | 1,155 (72,647) | 5,777 | 7,007 | 7,385 | 1,847 | 72.58M | 18.25M | 99.0% | 0 | 1,629 |
| 5a | BXMSS-8 leaf, OP_TX message | 953 (12,485) | 660 | 1,686 | 2,064 | 516 | 11.12M | 2.93M | 55.2% | 0 | 252 |
| 5b | stateless leaf, OP_TX message | 1,160 (72,652) | 5,777 | 7,031 | 7,409 | 1,853 | 73.59M | 18.25M | 100.0% | 20 | 1,668 |

Stages 1–4 verify a signature over a 32-byte message taken from the witness, so they authorize nothing. Stage 5 is the authorization.

**Stage 1: WOTS+C one-time signature**
- What it checks: 32 hash chains. The signer grinds a counter until the 32 digits sum to 240, so verification always runs exactly 240 chain hashes. The script then hashes the recovered tips and compares the result with the key.
- Spend: 514 B signature, 394 vB, 10.4M varops (68%).
- Macros versus inline: the macro form is 7.7× smaller than inline (3,050 vB) and costs 2.8M more varops, which is exactly the unroll charge.
- Against the earlier `OP_MULTI` prototype, the transaction is 31% smaller.

**Stage 2: FXMSS at a fixed depth of 8**
- Adds a leaf index and 8 Merkle levels (128 B).
- Spend: 468 vB, 10.9M varops (60%). This is 36% smaller than the earlier prototype.

**Stage 3: complete stateful SHRINCS**
- What it adds: parsing of the signature header (depth, R, leaf index, counter), the message hash `H_msg_sf`, and any depth up to the verifier's maximum.
- Balanced key (BXMSS-8): 515 vB, 11.1M varops (55%). A depth-20 signature, as from a 2²⁰-signature balanced key, costs 567 vB.
- Unbalanced key (UXMSS-255), where signature k sits at depth k: 498 vB at depth 1, 752 vB at depth 64, and 1,516 vB at depth 255.
- Each extra level adds 16 B and about 70k varops. The 16 WU fund 160k, so deeper signatures stay funded.
- The verifier's maximum depth fixes its unroll charge: 2.9M at depth 8, 6.7M at depth 255. A verifier should be sized to its key.

**Stage 4: stateless fallback**
- What it checks: FORS (k = 10 trees of height 13) and a 5-layer hypertree of WOTS-TW and 9-level XMSS.
- Spend: 5,777 B signature, 1,847 vB, 72.3–72.8M varops (99%).
- The cost is linear in the WOTS-TW chain steps a signature needs: 49.6M + 16,326 per step.
- The step count varies by signature: mean 1,318, standard deviation 64, over 40 real signatures. That matches the analytic model (mean 1,336).
- Without padding, the spend is funded up to 1,457 steps. Under that model, 3.4% of signatures need padding: 1.9 WU on average, 71 WU at the 99th percentile, and 1,785 WU in the worst case (every digit 0).
- The verifier takes a padding item, which the script ignores and the signed message does not cover.

**Stage 5: bound to the transaction**
- The message is SHA-256 of what `OP_TX` collates (selector `00570B222F03`):
  - version and locktime;
  - every input's outpoint, amount, scriptPubKey and sequence;
  - every output;
  - the input index, annex and tapleaf hash.
- The stateful and stateless leaves sit under one output, so a spend reveals and pays for only its own leaf.
- Cost of binding: +5 B of script and +19.5k varops; the 33 B message item drops out of the witness. The second leaf adds 32 B to the control block.
- Results: stateful 516 vB, 11.1M varops (55%); stateless 1,853 vB, 73.6M varops (100%; this signature needed 20 WU of padding).
- Rejected, both in `txeval` and on regtest:
  - the same witness on another output;
  - the same witness in a changed transaction;
  - a signature made for the other leaf.

## Other post-quantum signatures under the same cost model

These are estimates, not verifiers. `gsr/estimates.py` multiplies each scheme's operation counts by unit costs measured on the node, using pieces of the SHRINCS verifiers or small loop bodies written for the scheme (in `gsr/estimates.md`). The only complete new piece is `gsr/keccak.py`: Keccak-f[1600] in Script, checked against a reference and `hashlib.sha3_256`. Spends are priced like stage 5. Script sizes for the estimated schemes are guesses.

| scheme | basis | signatures per key | signature B | varops | spend vB |
|---|---|---|---:|---:|---:|
| WOTS+C (stage 1) | measured | 1 | 514 | 10.4M | 394 |
| SHRINCS stateful, BXMSS-8 (5a) | measured | 256 | 660 | 11.1M | 516 |
| SHRINCS stateful, depth 20 (3c) | measured | 2²⁰ | 854 | 11.9M | 567 |
| XMSS-SHA2_10_192 (SP 800-208) | estimate | 1,024 | 1,492 | 33M | 853 (worst 1,193) |
| XMSS-SHA2_10_256 (RFC 8391) | estimate | 1,024 | 2,500 | 43M | 1,105 (worst 1,562) |
| Falcon-512, SHA-256 hash-to-point (non-standard) | estimate | unlimited | 1,065 | 56M | 1,418 |
| SHRINCS stateless (5b) | measured | unlimited | 5,777 | 73.6M | 1,853 |
| Lamport, 256 bits | estimate | 1 | 8,192 | 8.4M | 2,268 |
| SLH-DSA-SHA2-128s (FIPS 205) | estimate | unlimited | 7,856 | 101M | 2,535 |
| Falcon-512 / FN-DSA (SHAKE256) | estimate | unlimited | 1,065 | 186M | 4,656 |
| SLH-DSA-SHAKE-128s (FIPS 205) | estimate | unlimited | 7,856 | 32.5G | 813,586 (no standard tx) |

**Lamport.** It is the cheapest to verify (8.4M: one hash per bit plus a running hash of the key), but 256 preimages and their complement hashes take 8 KB. WOTS+C is the same idea compressed to 514 B. Larger Winternitz parameters do not pay off without loops: at w = 256, the code for 255 possible steps per chain alone costs over 80M.

**Plain XMSS (RFC 8391).**
- Why it costs more than SHRINCS stateful:
  - Each chain step makes three hash calls (a PRF for the key, a PRF for the bitmask, then F), against SHRINCS's one: 40k against 16.4k varops per step.
  - It has 67 chains of 32-byte values.
  - It has no WOTS+C counter, so the digit sum, and with it the cost, varies.
- The result is about 2× SHRINCS stateful. A worst-case signature needs padding.

**SLH-DSA-SHA2-128s.**
- It uses the same tweakable hash as the SHRINCS stateless path, so its cost is that verifier scaled: 7 layers instead of 5, and 14 FORS trees of height 12 instead of 10 of height 13.
- Result: 101M varops, which is past the budget its 7.9 KB buys, so it needs about 660 WU of padding. Total 2.5 kvB.

**Keccak and SHAKE.**
- Keccak-f[1600] measured at **14.4M varops** per permutation. Each round costs 600k: rho/pi 347k, chi 145k, theta 107k.
- The state is held as five 80-byte rows with every lane doubled, so a lane rotation is a single shift.
- SHAKE-based hash signatures are therefore out of reach. SLH-DSA-SHAKE-128s needs about 2,250 permutations.

**Falcon-512.**
- Hash-to-point (SHAKE256, at least 9 permutations, 130M) is 70% of the cost, which confirms the expectation.
- The NTT is not needed. In Script an NTT is 2,304 butterflies of about 15k each, roughly 35M per transform. GSR's big-number `MUL` instead computes s₂·h as one 2,560 × 2,560-byte multiplication (Kronecker substitution, 6.65M measured), followed by a negacyclic fold.
- What remains is per-coefficient work: unpack, reduce mod q, centre, square and accumulate the norm, about 33k per coefficient (measured). That totals about 56M.
- With a SHA-256 hash-to-point, Falcon would be the cheapest unlimited-use option here, at 1.4 kvB. That variant is not FN-DSA and changes its security analysis.

## Security

- **The P2TR key path is quantum-vulnerable.** A Taproot output key is a curve point. An attacker who can compute discrete logarithms spends through the key path, whatever the leaves contain. A NUMS internal key does not help, because the attacker solves for the output key directly.
  - These leaves protect coins only in script-only outputs, such as P2MR (BIP 360), which commits to a script tree without a key and accepts future leaf versions such as 0xC2.
  - The demo uses P2TR only because that is what the GSR branch can spend today.
  - See [`gsr-projects/README.md`](../../gsr-projects/README.md) item 9, and [`L2_IDEAS.md`](../../gsr-projects/L2_IDEAS.md) items 19 (post-quantum exit paths) and 25 (post-quantum migration).
- **State.** A stateful key must never sign twice with the same leaf. A signer that is unsure of its state uses the stateless leaf.
- **Binding.** Only stage 5 authorizes a spend. Stages 1–4 accept any transaction carrying a valid signature over the witness message.
- **Padding.** The padding item is outside the signed message. Like any witness data, a relayer can change it, but that only raises the weight (lowering the fee rate) or invalidates the spend.
- **Status.** The code is experimental and unaudited. SHRINCS is a draft.

## Method and reproduction

- **Verifiers.** `gsr/verifiers.py` builds them with a small assembler, `gsr/asm.py` (opcodes, `x<hex>` pushes, `@MACRO` references). Fixtures, keys and signatures come from the reference [`impl/shrincs.py`](./impl/shrincs.py), through `gsr/fixtures.py`.
- **Measurement.** `gsr/tools/txeval.cpp` runs Core's `VerifyScript` with the standard flags under the BIP 440 transaction budget, and reports weight, budget, varops and time. Script-only evaluation uses `bitcoin-util evalscript`.
- **Unroll charge.** `Program.unroll_charge()` reproduces the node's pre-execution macro charge: 300 per substituted instruction and per reference, plus writing the unrolled script. It matches the measured inline/macro difference exactly.
- **Checks.**
  - Differential: valid vectors, flipped bits in every signature field, wrong depth, wrong signature type, padding, and the other leaf's message.
  - Every measured spend also checks one corrupted signature and, for `OP_TX`, a changed transaction.

```bash
python3 gsr/measure.py --repeat 25
```

```bash
python3 gsr/test_verifiers.py
```

```bash
python3 gsr/feature_shrincs_regtest.py --configfile=../gsr-stark-verifier/build/bitcoin/test/config.ini
```

```bash
python3 gsr/keccak.py
```

```bash
python3 gsr/estimates.py
```

`GSR_ROOT` defaults to `../gsr-stark-verifier`, a checkout of the GSR node built in `build/`. The first `measure.py` run builds `gsr/build/txeval` with `gsr/tools/build_txeval.sh`. Outputs: `gsr/results.json` (with transaction hex and script hashes), `gsr/results.md` and `gsr/estimates.md`.

**Historical material.** `research/`, `tests/` and `artifacts/` belong to the earlier prototype, which used `OP_MULTI` (outside GSR), and to older evaluator versions. Their numbers are not comparable with the tables above.

## Upstream specification

The [scheme specification](./SHRINCS.md), [Bitcoin integration draft](./leaf-version-0xC2.mediawiki) and [Python reference](./impl/shrincs.py) are retained from upstream. The integration draft's proposed `0xC2` semantics differ from GSR; our experiments target GSR's existing evaluator.

> [!WARNING]
>
> All code and cryptography specified in this repository are highly experimental and subject to change.
>
> Formal security proofs and optimized implementations are forthcoming as future work.


## Templating

The SHRINCS specification in [`SHRINCS.md`](./SHRINCS.md) includes Python reference code and documentation defined inline at [`impl/shrincs.py`](./impl/shrincs.py). We use simple templating to pull Python code and docstrings from `shrincs.py`.

If you wish to make changes to the specification of SHRINCS functions inside of a `<!-- DOC START xyz -->` ... `<!-- DOC END xyz -->` templating envelope, please make the changes directly in `shrincs.py` first, and then run the [`pydoc_insert.py` script](./pydoc_insert.py).

>[!WARNING]
> Running the templating script will overwrite `SHRINCS.md`. Make sure you have saved and committed other important changes first!

```sh
./pydoc_insert.py
```

A simple git pre-commit validation hook is available in [`hooks/pre-commit`](./hooks/pre-commit), to remind you to run the templating script if needed before committing.

```
cp hooks/pre-commit .git/hooks
```
