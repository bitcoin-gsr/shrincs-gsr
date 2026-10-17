# TODO

- Synchronize the covenant-support BIP draft's runtime `OP_DEFINE` / `OP_INVOKE` section with the current static `OP_MACRO` / `OP_CALLMACRO` implementation before treating this backend as a stable protocol target.
- Decide whether an `OP_CALLMACRO` in an inactive branch should incur its reference/body-scan charge. The current node charges it, because unrolling is static. In stage 3 this is why a depth-255 verifier pays 6.7M of unroll charge even for a depth-1 signature (3a against 3b).
- Spend from a P2MR (BIP 360) output once a GSR branch supports it. Today's P2TR outputs keep a quantum-vulnerable key path.
- Lower the stateless verifier's unroll charge (18.25M of 73.6M). This would give it budget margin, so that fewer signatures need padding.
- Replace the Falcon-512 estimate with a verifier: Kronecker product by `MUL`, then a per-coefficient norm. Use SHAKE256 and, separately, a SHA-256 hash-to-point.
