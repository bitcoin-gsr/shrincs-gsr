# Post-quantum signatures in GSR Script

This project implements SHRINCS signature verification in Bitcoin Script. SHRINCS is a post-quantum signature scheme built only from hashes. Its verifier is an ordinary tapleaf script using what GSR restores: hashing and byte operations, arithmetic on large numbers, static macros and `OP_TX`. No new signature opcode is needed.

The verifier is built in five stages, from a one-time signature up to the full scheme, and each stage is measured on the GSR node.

- **Assumption.** Coins are held in P2MR outputs (BIP 360). P2MR has no key path, so the leaf script is the only way to spend. The tests use P2TR outputs, which the GSR branch can spend today. The leaf scripts, witnesses and costs are the same.
- **Versions.** SHRINCS draft [`4cd63a6`](https://github.com/SHRINCS/shrincs-bip); GSR node `jmoik/bitcoin`, branch `gsr`, commit `ad6c16f`.

## Stages

Stage 5 is SHRINCS as it would be deployed: one output with both leaves, each signing the spending transaction. Stages 3 and 4 measure its two signature paths alone, over a message from the witness. BXMSS-8 and UXMSS-255 are key shapes chosen at key generation:
- **BXMSS-8** is a balanced tree of depth 8, which gives 256 stateful signatures.
- **UXMSS-255** is an unbalanced tree in which signature k sits at depth k.

| id | variant | script B (inline) | signature B | witness B | tx WU | vsize vB | varops | unroll charge | budget used | padding WU | verify µs |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | WOTS+C one-time signature | 609 (11,234) | 514 | 1,197 (11,822) | 1,575 (12,200) | 394 (3,050) | 10.40M (7.60M) | 2.80M (0.00M) | 68.2% (6.2%) | 0 | 236 (241) |
| 2 | FXMSS tree, fixed depth 8 | 773 (12,281) | 642 | 1,491 (12,999) | 1,869 (13,377) | 468 (3,345) | 10.93M (8.02M) | 2.91M (0.00M) | 60.1% (6.0%) | 0 | 259 (268) |
| 3a | SHRINCS stateful path: UXMSS-255 key, 1st signature (depth 1) | 990 (45,333) | 548 | 1,612 | 1,990 | 498 | 15.48M | 6.74M | 79.8% | 0 | 333 |
| 3b | SHRINCS stateful path: BXMSS-8 key (256 signatures) | 948 (12,480) | 660 | 1,682 | 2,060 | 515 | 11.10M | 2.93M | 55.2% | 0 | 262 |
| 3c | SHRINCS stateful path: depth-20 signature (UXMSS-20 key; = any BXMSS-20 signature) | 959 (14,077) | 854 | 1,887 | 2,265 | 567 | 11.95M | 3.11M | 53.9% | 0 | 280 |
| 3d | SHRINCS stateful path: UXMSS-255 key, depth 64 | 990 (45,333) | 1,563 | 2,627 | 3,005 | 752 | 18.94M | 6.74M | 64.1% | 0 | 412 |
| 3e | SHRINCS stateful path: UXMSS-255 key, last signature (depth 255) | 990 (45,333) | 4,619 | 5,683 | 6,061 | 1,516 | 33.32M | 6.74M | 55.4% | 0 | 640 |
| 4a | SHRINCS stateless path, signature 1 | 1,155 (72,647) | 5,777 | 7,007 | 7,385 | 1,847 | 72.83M | 18.25M | 99.3% | 0 | 1,625 |
| 4b | SHRINCS stateless path, signature 2 | 1,155 (72,647) | 5,777 | 7,007 | 7,385 | 1,847 | 72.34M | 18.25M | 98.6% | 0 | 1,717 |
| 4c | SHRINCS stateless path, signature 3 | 1,155 (72,647) | 5,777 | 7,007 | 7,385 | 1,847 | 72.58M | 18.25M | 99.0% | 0 | 1,629 |
| 5a | SHRINCS, bound by OP_TX: stateful leaf (BXMSS-8 key) | 953 (12,485) | 660 | 1,686 | 2,064 | 516 | 11.12M | 2.93M | 55.2% | 0 | 252 |
| 5b | SHRINCS, bound by OP_TX: stateless leaf | 1,160 (72,652) | 5,777 | 7,031 | 7,409 | 1,853 | 73.59M | 18.25M | 100.0% | 20 | 1,668 |

- **Lock.** Every variant locks coins into one 43-byte output (172 WU) and uses no varops. The output commits to the leaf script, which is revealed only at spend.
- **Spend.** One input and one output. "Script B" is the committed leaf script.
- **Budget.** A spend may use 10,000 varops per weight unit, minus 500,000. The unroll charge is the part paid up front for expanding the macros. Padding is extra witness bytes that buy budget.
- **Brackets.** A value in brackets is for the inline form, which runs the same instructions but commits the whole unrolled script. Stages 1 and 2 were also measured inline; for later stages the brackets give only the inline script size.
- **Timing.** Verification only: the median of 25 runs on an Apple M4 Pro.
- **Authorization.** Stages 1–4 verify a signature over a 32-byte message from the witness, so they authorize nothing. Stage 5 binds the signature to the spending transaction.

### Full transaction size compared

One input and one output each, spending SHRINCS in GSR Script (stage 5) against two references:
- a Schnorr key-path spend, which is today's cheapest spend but is not post-quantum;
- SHRINCS as a native opcode, following the upstream integration draft. That draft redefines `CHECKSIG` in its own leaf version, so the leaf is just `<flag‖public key> OP_CHECKSIG` (51 B).

| spend | signature B | tx WU | vsize vB | against Schnorr |
|---|---:|---:|---:|---:|
| Schnorr key path (P2TR, not post-quantum) | 64 | 444 | 111 | 1.0× |
| SHRINCS stateful, native opcode | 660 | 1,128 | 282 | 2.5× |
| SHRINCS stateful, GSR Script (5a) | 660 | 2,064 | 516 | 4.6× |
| SHRINCS stateless, native opcode | 5,777 | 6,245 | 1,562 | 14.1× |
| SHRINCS stateless, GSR Script (5b) | 5,777 | 7,409 | 1,853 | 16.7× |

The signatures are the same in both SHRINCS forms. What GSR adds is the verifier itself:
- the leaf script is 953 B (stateful) or 1,160 B (stateless) instead of 51 B;
- the second leaf adds 32 B to the control block.

That is +936 WU (+234 vB) for a stateful spend, and +1,164 WU (+291 vB) for a stateless one, which includes 20 WU of padding. In exchange, GSR needs no soft fork for the scheme itself. A native opcode would also have its own validation cost, which is not measured here.

### Compared with Simplicity

Blockstream's Simplicity SHRINCS verifier, ported to these BIP-draft parameters, verifies the same signatures. It uses the same keys, context and message, signed by `impl/shrincs.py`. The port and its measurements are in [`simplicity/shrincs-bip`](../../simplicity/shrincs-bip/README.md), a local workbench outside this repository.

The cost model is Elements': an input may cost 1000 mWU per witness byte, plus 50 WU. The transaction is the same 1-in-1-out one.

| spend | GSR Script vsize | Simplicity vsize | Simplicity / GSR |
|---|---:|---:|---:|
| stateful, BXMSS-8 key (3b) | 515 vB | 1,469 vB | 2.9× |
| stateful, bound to the transaction (5a) | 516 vB | 1,477 vB | 2.9× |
| stateless (4a) | 1,847 vB | 8,191 vB | 4.4× |
| stateless, bound to the transaction (5b) | 1,853 vB | 7,682 vB | 4.1× |

The gap has three causes:
- **Static cost bound.** Simplicity charges a program's worst case. GSR charges varops as they execute.
- **Moving bits costs more than hashing.** Simplicity charges every combinator and every copied bit. The 22-byte ADRS leaves each hash input unaligned, so a Winternitz step costs about 9.5k mWU, while the SHA-256 compression jet costs 771.
- **Program size.** The pruned stateful program is 4.7 kB, against the 948 B script here.

A Simplicity jet for the BIP's tweakable hash would remove most of the per-step cost.

Script excerpts below are the assembler source from `gsr/verifiers.py`:
- opcodes and decimal pushes appear as written;
- `@NAME` calls a macro, and `NAME_x4` / `NAME_x16` call it 4 and 16 times;
- `<…>` is a pushed constant and `...` marks omitted lines;
- stack pictures list the bottom item first.

### Stage 1: WOTS+C, a one-time signature

**Idea.** A Winternitz key has 32 hash chains of length 15, and the public key commits to the chain ends.
- **Signing:** the signer reveals one value from each chain, at the position given by a 4-bit digit of the message hash.
- **Verifying:** the verifier hashes each value the remaining 15 − digit times and checks the ends.

Plain Winternitz adds checksum chains so that a forger cannot move values forward. WOTS+C drops them: the signer grinds a 2-byte counter until the 32 digits sum to exactly 240. Every verification then runs exactly 240 hashes.

**How it is built.**
- `NIB` takes two digits from the next byte and adds them to a running sum.
- `CHAIN` takes the next 16-byte value from the signature, builds its address and runs `WALK`.
- `WALK` holds the 15 possible steps of one chain. Each step is skipped while the counter is above zero, and hashes once it reaches zero.

A last hash of the 32 chain ends gives the one-time public key, which must equal the key in the script.

```
# main: [signature message]
SIZE 32 NUMEQUALVERIFY SWAP SIZE 514 NUMEQUALVERIFY SWAP
<pk_seed‖0⁴⁸‖ADRS[:9]> TOALTSTACK
...                                          # g = H_grind(message, counter)
0 SWAP @NIB_x16 DROP 240 NUMEQUALVERIFY      # the 32 digits of g must sum to 240
32 ROLL 0 SWAP @CHAIN_x16 @CHAIN_x16 DROP    # walk all 32 chains to their ends
... SWAP CAT SHA256 16 LEFT                  # one-time public key = T(chain ends)
NIP <wots_pk> EQUAL

# NIB: [sum D] -> [hi lo sum' D']  two digits from the next byte of D
DUP 1 LEFT DUP 4 RSHIFT SWAP 15 AND 2DUP ADD 4 ROLL ADD 3 ROLL 1 64 SUBSTR

# WALK, step j of 15: [P82 node c] -> skip while c > 0, otherwise hash
DUP 0NOTEQUAL IF 1SUB ELSE 2 PICK <BE4(j)> CAT ROT CAT SHA256 16 LEFT SWAP ENDIF
```

**Script size.** 609 B, made up of:
- the main script: 200 B;
- `WALK`: 302 B;
- `CHAIN`: 27 B, `NIB`: 20 B and `BE4`: 10 B;
- four group macros: 32 B;
- declaration headers: 18 B.

Unrolled, the script is 11,234 B: `WALK` is written once but runs through 32 `CHAIN` calls.

**Costs.**
- The signature is 514 B: the counter plus 32 values of 16 B.
- The spend is 1,575 WU (394 vB) and 10.40M varops, of which 2.80M is the unroll charge. That is 68% of the budget.
- Inline, the same verifier makes the spend 12,200 WU (3,050 vB).
- The earlier `OP_MULTI` prototype needed 2,294 WU.

### Stage 2: many signatures from a Merkle tree (FXMSS, depth 8)

**Idea.** 256 one-time keys go under a Merkle tree, and the root becomes the public key. A signature adds its leaf index and the 8 sibling hashes on the path to the root. The signer must remember which leaves it has used: the scheme is stateful.

**How it is built.**
- Stage 1 recovers the leaf's one-time public key.
- `FX_LEVEL` hashes one level up. The bit of the index sets the order of the two nodes, and the hash includes the address of the level.
- Eight calls reach the root, which must equal the root in the script.

```
# main: [signature message index]
SIZE 1 NUMEQUALVERIFY ROT SIZE 642 NUMEQUALVERIFY ROT SIZE 32 NUMEQUALVERIFY
...                                                 # stage 1: the leaf's one-time public key
@FX_LEVEL_x4 @FX_LEVEL_x4 DROP NIP NIP <sf_root> EQUAL

# FX_LEVEL: [h pos node path] -> [h' pos' node' path']
DUP 16 LEFT SWAP 16 6000 SUBSTR TOALTSTACK          # next sibling; rest of the path aside
2 PICK 1 AND 0NOTEQUAL IF SWAP ENDIF CAT            # node‖sib, or sib‖node at an odd position
ROT 1ADD ROT 1 RSHIFT                               # h' = h + 1, pos' = pos >> 1
2DUP @BE8 CAT <0x12‖0¹²> CAT <pk_seed‖0⁴⁸> SWAP CAT 3 ROLL CAT SHA256 16 LEFT FROMALTSTACK
```

**Script size.** 773 B, made up of:
- the main script: 219 B;
- `WALK`: 302 B and `FX_LEVEL`: 117 B;
- `CHAIN`: 27 B, `NIB`: 20 B, `BE8`: 14 B and `BE4`: 10 B;
- group macros: 40 B;
- declaration headers: 24 B.

Unrolled, the script is 12,281 B.

**Costs.**
- The signature is 642 B: stage 1's 514 B plus a 128 B path. The leaf index adds 1 B.
- The spend is 1,869 WU (468 vB) and 10.93M varops, of which 2.91M is the unroll charge. That is 60% of the budget.
- Inline, the spend is 3,345 vB.
- The earlier prototype needed 2,907 WU.

### Stage 3: complete stateful SHRINCS

**Idea.** This is the real SHRINCS signature format, which signs a hashed message. A signature carries, in order:
- a header byte giving its depth d;
- a 16-byte randomizer R;
- the leaf index, in ⌈min(d, 64)/8⌉ bytes;
- the counter;
- the chains;
- a path of 16·d bytes.

The message is hashed with R, the public key and the context `bitcoin-tx` (`H_msg_sf`). Two tree shapes are supported:
- **Balanced (BXMSS-d):** 2^d leaves, all at depth d.
- **Unbalanced (UXMSS):** signature k sits at depth k, so early signatures are small.

One verifier accepts every depth up to its maximum.

**How it is built.**
- The header is parsed and checked: the depth range, the total length, and the index range.
- Two SHA-256 calls compute `H_msg_sf`.
- WOTS+C runs as in stage 1.
- `CFX_LEVEL` repeats up to the maximum depth. Each level runs only while path bytes remain.

```
# main: [signature message]
SIZE 32 NUMEQUALVERIFY TOALTSTACK                   # message to the altstack
SIZE SWAP DUP 1 LEFT xff OVER SUB                   # d = 255 - header byte: the depth
DUP 1 9 WITHIN VERIFY                               # 1 <= d <= 8 for this verifier
DUP 64 MIN DUP 7 ADD 3 RSHIFT                       # index bytes s = ceil(min(d, 64) / 8)
ROT 4 LSHIFT OVER ADD 531 ADD 5 ROLL NUMEQUALVERIFY # length = 531 + s + 16 d
...
OVER BYTEREV 1 5 ROLL LSHIFT LESSTHAN VERIFY        # leaf index < 2^min(d, 64)
...                                                 # H_msg_sf, then WOTS+C as in stage 1
@CFX_LEVEL_x4 @CFX_LEVEL_x4 DROP NIP NIP <sf_root> EQUAL

# CFX_LEVEL: one more level while path bytes remain
SIZE 0NOTEQUAL IF @FX_LEVEL ENDIF
```

**Script size.** The depth-8 verifier is 948 B, made up of:
- the main script: 386 B;
- `WALK`: 302 B and `FX_LEVEL`: 117 B;
- `CHAIN`: 27 B, `NIB`: 20 B, `BE8`: 14 B, `BE4`: 10 B and `CFX_LEVEL`: 6 B;
- group macros: 40 B;
- declaration headers: 26 B.

Unrolled, it is 12,480 B. The depth-255 verifier is 990 B (45,333 B unrolled), because it needs larger groups (x16, x64).

**Costs.**
- **BXMSS-8:** 515 vB and 11.10M varops (55% of the budget).
- **Depth 20:** 567 vB. This is any signature from a 2²⁰-signature balanced key.
- **UXMSS-255:** 498 vB at depth 1, 752 vB at depth 64, and 1,516 vB at depth 255.
- Each extra level adds 16 B and about 70k varops. The 16 WU buy 160k of budget, so deeper signatures stay funded.
- The maximum depth sets the unroll charge: 2.9M at depth 8 and 6.7M at depth 255. A verifier should be sized to its key.

### Stage 4: the stateless fallback

**Idea.** A signer that has lost its state signs statelessly, in the style of SPHINCS+ (SLH-DSA). The structure has two parts:
- **FORS:** the message digest selects one leaf in each of 10 FORS trees of height 13. The signature reveals those leaves and their paths, and the 10 roots form a FORS public key.
- **Hypertree:** 5 layers sign the FORS public key. Each layer is a WOTS-TW one-time signature under a 9-level XMSS tree. WOTS-TW has 35 chains: 32 digits plus 3 checksum digits.

The root of the top layer is the stateless public key.

**How it is built.**
- `FORS_TREE` hashes the revealed leaf and climbs 13 `HT_LEVEL`s.
- `LAYER` reuses `NIB`, `CHAIN` and `WALK` for WOTS-TW, then climbs 9 `HT_LEVEL`s.
- The main script computes `H_msg_sl`, runs 10 FORS trees and 5 layers, and compares the root.
- A padding item at the bottom of the witness can buy extra budget.

```
# main: [padding signature message]
SIZE 32 NUMEQUALVERIFY TOALTSTACK                    # message to the altstack
SIZE 5777 NUMEQUALVERIFY DUP 1 LEFT xff EQUALVERIFY  # a stateless signature starts with 0xff
...                                                  # H_msg_sl, tree and leaf index
@FORS_TREE_x4 @FORS_TREE_x4 @FORS_TREE @FORS_TREE    # 10 FORS roots
2DROP 2DROP CAT SHA256 16 LEFT                       # FORS public key = T(roots)
@LAYER_x4 @LAYER DROP NIP NIP <sl_root> EQUAL NIP    # 5 layers up to the root

# LAYER: one hypertree layer
SIZE 704 DIV 5 SWAP SUB 64 LSHIFT 4 PICK ADD @BE9    # layer j = 5 - (signature left) / 704
...
0 SWAP @NIB_x16 DROP 480 SWAP SUB DUP 8 RSHIFT OVER 4 RSHIFT 15 AND ROT 15 AND   # 32 + 3 checksum digits
35 ROLL 0 SWAP @CHAIN_x16 @CHAIN_x16 @CHAIN @CHAIN @CHAIN DROP                  # 35 chains
...                                                  # one-time public key
@HT_LEVEL_x4 @HT_LEVEL_x4 @HT_LEVEL                  # 9 XMSS levels
```

**Script size.** 1,155 B, made up of:
- the main script: 310 B;
- `WALK`: 302 B, `LAYER`: 231 B, `FORS_TREE`: 91 B and `HT_LEVEL`: 45 B;
- `CHAIN`: 27 B, `NIB`: 20 B, `BE9`: 15 B, `BE8`: 14 B and `BE4`: 10 B;
- group macros: 56 B;
- declaration headers: 34 B.

Unrolled, it is 72,647 B, and that unrolling costs 18.25M varops.

**Costs.**
- The signature is 5,777 B. The spend is 7,385 WU (1,847 vB) and 72.3–72.8M varops: 99% of the budget.
- The cost is linear in the chain steps a signature needs: 49.6M + 16,326 per step.
- Over 40 real signatures, the steps averaged 1,318 (standard deviation 64). Without padding, a spend is funded up to 1,457 steps.
- By the analytic model, 3.4% of signatures need padding: 1.9 WU on average, 71 WU at the 99th percentile, and 1,785 WU in the worst case (every digit 0).

### Stage 5: SHRINCS bound to the transaction

**Idea.** One output holds two leaves: the stateful verifier (stage 3, depth 8) and the stateless one (stage 4). A spend reveals only the leaf it uses. Both sign the spending transaction.

**How it is built.** One line changes in each leaf. The message is no longer taken from the witness, and is instead the SHA-256 of what `OP_TX` collates:
- version and locktime;
- every input's outpoint, amount, scriptPubKey and sequence;
- every output;
- the input index, the annex and the tapleaf hash.

```
x00570b222f03 TX SHA256 TOALTSTACK    # replaces: SIZE 32 NUMEQUALVERIFY TOALTSTACK
```

**Script size.** 953 B (stateful) and 1,160 B (stateless): each is 5 B more than in stages 3 and 4.

**Costs.**
- **Stateful:** 2,064 WU (516 vB), 11.12M varops (55%).
- **Stateless:** 7,409 WU (1,853 vB), 73.59M varops (100%); this signature needed 20 WU of padding.
- Binding costs +19.5k varops and takes the 33 B message item out of the witness.
- The second leaf adds 32 B to the control block.
- Rejected both in `txeval` and on regtest:
  - the same witness on another output;
  - the same witness in a changed transaction;
  - a signature made for the other leaf.

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
- A quantum-safe output type. That needs P2MR, which is assumed here (see [Security](#security)).
- Script has no loops. Every possible chain step must exist as code, so skipped steps still pay the unroll charge. A verifier sized for depth 255 pays 6.7M before it runs.

## Security

- **Outputs (the assumption).** The coins must be in a script-only output such as P2MR (BIP 360). P2MR commits to a script tree without a key, and accepts future leaf versions such as 0xC2.
  - In a P2TR output the output key is a curve point. An attacker who can compute discrete logarithms spends through the key path, whatever the leaves contain. A NUMS internal key does not help, because the attacker solves for the output key directly.
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

`GSR_ROOT` defaults to `../gsr-stark-verifier`, a checkout of the GSR node built in `build/`. The first `measure.py` run builds `gsr/build/txeval` with `gsr/tools/build_txeval.sh`. Outputs: `gsr/results.json` (with transaction hex and script hashes) and `gsr/results.md`.

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
