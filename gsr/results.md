Node jmoik/bitcoin@ad6c16ff02 (gsr), SHRINCS 4cd63a6497. Every variant locks into one 43-byte output (172 WU, no varops); the table is the spend. Brackets: the inline form.

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

| spend | signature B | tx WU | vsize vB | against Schnorr |
|---|---:|---:|---:|---:|
| Schnorr key path (P2TR, not post-quantum) | 64 | 444 | 111 | 1.0× |
| SHRINCS stateful, native opcode | 660 | 1,128 | 282 | 2.5× |
| SHRINCS stateful, GSR Script (5a) | 660 | 2,064 | 516 | 4.6× |
| SHRINCS stateless, native opcode | 5,777 | 6,245 | 1,562 | 14.1× |
| SHRINCS stateless, GSR Script (5b) | 5,777 | 7,409 | 1,853 | 16.7× |
