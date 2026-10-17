Measured unit costs (varops):

    step                  16,398
    layer              7,799,603
    fors_tree13        1,050,560
    level                 75,040
    walk_skip            144,060
    xmss_walk_skip       190,160
    xmss_step             40,070
    xmss_node             61,662
    lamport_bit           32,484
    keccak_f          14,425,040
    falcon_coeff          32,221
    cat_1280              10,986
    mul2560            6,651,186
    sha256_76              6,494

| scheme | signatures | sig B | script B | varops | padding WU | tx WU | vsize vB | budget used | note |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| Lamport, 256 bits, n = 16 | 1 | 8,192 | 208 | 8.4M | 0 | 9,070 | 2,268 | 9% | 256 items of preimage || other hash; cheap to verify, large |
| XMSS-SHA2_10_256 (RFC 8391) | 1,024 | 2,500 | 1,500 | 42.7M | 0 | 4,419 | 1,105 | 98% | worst case (all digits 0): 62M varops, 1,562 vB |
| XMSS-SHA2_10_192 (SP 800-208) | 1,024 | 1,492 | 1,500 | 32.7M | 0 | 3,411 | 853 | 97% | worst case (all digits 0): 47M varops, 1,193 vB |
| SLH-DSA-SHA2-128s (FIPS 205) | 2^64 | 7,856 | 1,200 | 100.8M | 663 | 10,138 | 2,535 | 100% | the SHRINCS stateless verifier with d = 7 layers and k = 14, a = 12 FORS trees |
| SLH-DSA-SHAKE-128s (FIPS 205) | 2^64 | 7,856 | 2,600 | 32,542.9M | 3,243,468 | 3,254,343 | 813,586 | 100% | 2,256 Keccak-f calls; not a standard transaction |
| Falcon-512 (FN-DSA), SHAKE256 | 2^64 | 1,065 | 3,624 | 185.7M | 13,513 | 18,621 | 4,656 | 100% | 9 Keccak-f = 130M varops; arithmetic 56M |
| Falcon-512, SHA-256 hash-to-point (non-standard) | 2^64 | 1,065 | 2,224 | 56.2M | 1,964 | 5,672 | 1,418 | 100% | 35 SHA-256 calls replace SHAKE256; arithmetic 56M |
