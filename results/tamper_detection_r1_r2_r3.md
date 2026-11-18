# Experiment 1 - Tamper detection and verifiability (R1 vs R2 vs R3)

Workload: 96 MCP `tools/call` requests (seed 7), Merkle batch size 16,
5 randomised trials per scenario and regime. Every sweep is a fresh `watcher_agent` OS process
(separate OS process, mode=ro DB, own RPC client). The "Verification sweep (ms)" column is the watcher's own measured sweep time,
excluding process start-up. S6a is detected inline by the gateway (no watcher involved).

## Summary

| ID   | Scenario                                             | R1         | R2         | R3         |
|------|------------------------------------------------------|------------|------------|------------|
| S1   | Field modification (DENY->ALLOW, rules scrubbed)     | No (0%)    | Yes (100%) | Yes (100%) |
| S2   | Interior record deletion                             | Yes (100%) | Yes (100%) | Yes (100%) |
| S3   | Tail truncation / rollback of latest batch           | No (0%)    | No (0%)    | Yes (100%) |
| S4   | Record reordering / payload swap                     | No (0%)    | Yes (100%) | Yes (100%) |
| S5   | Merkle root forgery (chain + local roots recomputed) | No (0%)    | No (0%)    | Yes (100%) |
| S6a  | Tool rug-pull (downstream only, pins intact)         | Yes (100%) | Yes (100%) | Yes (100%) |
| S6b  | Tool rug-pull (insider also rewrites gateway pins)   | No (0%)    | No (0%)    | Yes (100%) |

## Overall

| Regime   | Trials detected   |   Overall detection (%) |   False alarms on clean log |   Audit records |
|----------|-------------------|-------------------------|-----------------------------|-----------------|
| R1       | 10/35             |                    28.6 |                           0 |             108 |
| R2       | 20/35             |                    57.1 |                           0 |             108 |
| R3       | 35/35             |                   100   |                           0 |             108 |

## Verification sweep cost on the clean log (ms, per check)

| Regime   | id continuity   | hash chain   | Merkle roots   | chain anchors   | manifest drift (incl. live server spawn)   |   total sweep |
|----------|-----------------|--------------|----------------|-----------------|--------------------------------------------|---------------|
| R1       | 0.59            | -            | -              | -               | -                                          |          1.94 |
| R2       | -               | 3.75         | -              | -               | -                                          |          5.87 |
| R3       | -               | 3.66         | 0.36           | 483.34          | 2093.51                                    |       2582.4  |

## Detail

| ID   | Regime   | Detected   |   Detection rate (%) | Detection mechanism                                                          |   Verification sweep (ms) |
|------|----------|------------|----------------------|------------------------------------------------------------------------------|---------------------------|
| S1   | R1       | No         |                    0 | -                                                                            |                      2.02 |
| S2   | R1       | Yes        |                  100 | SEQUENCE_GAP                                                                 |                      2.1  |
| S3   | R1       | No         |                    0 | -                                                                            |                      2.07 |
| S4   | R1       | No         |                    0 | -                                                                            |                      2.05 |
| S5   | R1       | No         |                    0 | -                                                                            |                      2.15 |
| S6a  | R1       | Yes        |                  100 | GATEWAY_PIN_MISMATCH (tools/list stripped)                                   |                      0.86 |
| S6b  | R1       | No         |                    0 | -                                                                            |                      2.05 |
| S1   | R2       | Yes        |                  100 | HASH_MISMATCH                                                                |                      5.52 |
| S2   | R2       | Yes        |                  100 | CHAIN_BREAK, SEQUENCE_GAP                                                    |                      5.44 |
| S3   | R2       | No         |                    0 | -                                                                            |                      5.07 |
| S4   | R2       | Yes        |                  100 | HASH_MISMATCH                                                                |                      5.53 |
| S5   | R2       | No         |                    0 | -                                                                            |                      5.59 |
| S6a  | R2       | Yes        |                  100 | GATEWAY_PIN_MISMATCH (tools/list stripped)                                   |                      0.86 |
| S6b  | R2       | No         |                    0 | -                                                                            |                      5.98 |
| S1   | R3       | Yes        |                  100 | ANCHOR_RECORDS_MISMATCH, HASH_MISMATCH, MERKLE_ROOT_MISMATCH                 |                   2637.69 |
| S2   | R3       | Yes        |                  100 | ANCHORED_RECORDS_MISSING, CHAIN_BREAK, MERKLE_BATCH_INCOMPLETE, SEQUENCE_GAP |                   2560.37 |
| S3   | R3       | Yes        |                  100 | ANCHORED_BATCH_MISSING, TAIL_TRUNCATION                                      |                   2589    |
| S4   | R3       | Yes        |                  100 | ANCHOR_RECORDS_MISMATCH, HASH_MISMATCH, MERKLE_ROOT_MISMATCH                 |                   2503.56 |
| S5   | R3       | Yes        |                  100 | ANCHOR_RECORDS_MISMATCH, ANCHOR_ROOT_MISMATCH                                |                   2543.36 |
| S6a  | R3       | Yes        |                  100 | GATEWAY_PIN_MISMATCH (tools/list stripped)                                   |                      0.89 |
| S6b  | R3       | Yes        |                  100 | MANIFEST_DRIFT, REGISTRY_PIN_REWRITTEN                                       |                   2564.04 |

R1 checks only id continuity, R2 only the hash chain, R3 the hash chain plus Merkle roots,
on-chain anchors and tool-manifest drift against the watcher's own snapshot.
