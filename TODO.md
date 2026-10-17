# TODO

- Synchronize the covenant-support BIP draft's runtime `OP_DEFINE` / `OP_INVOKE` section with the current static `OP_MACRO` / `OP_CALLMACRO` implementation before treating this backend as a stable protocol target.
- Decide whether an `OP_CALLMACRO` in an inactive branch should incur its reference/body-scan charge. The current node charges it, because unrolling is static. In stage 3 this is why a depth-255 verifier pays 6.7M of unroll charge even for a depth-1 signature (3a against 3b).
- Spend from a P2MR (BIP 360) output once a GSR branch supports it. Today's P2TR outputs keep a quantum-vulnerable key path.
- Lower the stateless verifier's unroll charge (18.25M of 73.6M). This would give it budget margin, so that fewer signatures need padding.

## Other post-quantum schemes

`gsr/estimates.py` prices these from measured unit costs (output in `gsr/estimates.md`). None is a verifier yet; spend sizes are estimates, with OP_TX binding as in stage 5.

- **Falcon-512 (FN-DSA), about 4.7 kvB, 186M varops.**
  - SHAKE256 hash-to-point costs 9 Keccak-f permutations, 130M varops.
  - The ring product is one Kronecker `MUL` (6.65M, measured); the rest is per-coefficient norm work (about 33k per coefficient, measured).
  - With a SHA-256 hash-to-point (not standard), it would be about 1.4 kvB.
  - To do: build it, both the SHAKE256 and the SHA-256 variants.
- **Keccak-f[1600]** is built and checked (`gsr/keccak.py`), at 14.4M varops per permutation, as much as about 2,800 SHA-256 calls on 64 bytes. To do: optimize rho/pi, which is 347k of each 600k round.
- **SLH-DSA-SHA2-128s, about 2.5 kvB, 101M varops.** It is the stateless SHRINCS verifier with 7 layers and 14 FORS trees of height 12. To do: build it by changing the parameters of stage 4.
- **SLH-DSA-SHAKE-128s.** About 2,250 Keccak-f calls, 32.5G varops: it does not fit a standard transaction.
- **XMSS-SHA2_10_256 (RFC 8391), about 1.1 kvB, 43M varops; XMSS-SHA2_10_192, about 0.85 kvB.**
  - Each chain step takes three hash calls (40k varops per step).
  - A worst-case signature needs padding.
- **Lamport, 256 bits, about 2.3 kvB, 8.4M varops.** Cheap to verify, but the signature is 8 KB, against WOTS+C's 514 B.
