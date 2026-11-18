# Experiment 1 - Tamper detection and verifiability (R1 vs R2 vs R3)

Workload: 96 MCP `tools/call` requests (seed 7), Merkle batch size 16,
5 randomised trials per scenario and regime. Every sweep is a fresh `watcher_agent` OS process
(separate OS process, mode=ro DB, own RPC client). The "Verification sweep (ms)" column is the watcher's own measured sweep time,
excluding process start-up. S6a is detected inline by the gateway (no watcher involved).

## Summary

| ID   | Scenario                                                            | R1         | R2         | R3         |
|------|---------------------------------------------------------------------|------------|------------|------------|
| S1   | Field modification (DENY->ALLOW, rules scrubbed)                    | No (0%)    | Yes (100%) | Yes (100%) |
| S2   | Interior record deletion                                            | Yes (100%) | Yes (100%) | Yes (100%) |
| S3   | Tail truncation / rollback of latest batch                          | No (0%)    | No (0%)    | Yes (100%) |
| S4   | Record reordering / payload swap                                    | No (0%)    | Yes (100%) | Yes (100%) |
| S5   | Merkle root forgery (chain + local roots recomputed)                | No (0%)    | No (0%)    | Yes (100%) |
| S6a  | Tool rug-pull (downstream only, pins intact)                        | Yes (100%) | Yes (100%) | Yes (100%) |
| S6b  | Tool rug-pull (insider also rewrites gateway pins)                  | No (0%)    | No (0%)    | Yes (100%) |
| S7   | ML model/tokenizer tampering (insider also rewrites model manifest) | No (0%)    | No (0%)    | Yes (100%) |

## Overall

| Regime   | Trials detected   |   Overall detection (%) |   False alarms on clean log |   Audit records |
|----------|-------------------|-------------------------|-----------------------------|-----------------|
| R1       | 10/40             |                      25 |                           0 |             108 |
| R2       | 20/40             |                      50 |                           0 |             108 |
| R3       | 40/40             |                     100 |                           0 |             108 |

## Verification sweep cost on the clean log (ms, per check)

| Regime   | id continuity   | hash chain   | Merkle roots   | chain anchors   | manifest drift (incl. live server spawn)   | model integrity (re-hash 747 MB)   |   total sweep |
|----------|-----------------|--------------|----------------|-----------------|--------------------------------------------|------------------------------------|---------------|
| R1       | 0.68            | -            | -              | -               | -                                          | -                                  |          2.23 |
| R2       | -               | 4.26         | -              | -               | -                                          | -                                  |          6.17 |
| R3       | -               | 4.91         | 0.43           | 376.66          | 6166.21                                    | 3461.74                            |      10011.9  |

## Detail

| ID   | Regime   | Detected   |   Detection rate (%) | Detection mechanism                                                          |   Verification sweep (ms) |
|------|----------|------------|----------------------|------------------------------------------------------------------------------|---------------------------|
| S1   | R1       | No         |                    0 | -                                                                            |                      2.91 |
| S2   | R1       | Yes        |                  100 | SEQUENCE_GAP                                                                 |                      2.62 |
| S3   | R1       | No         |                    0 | -                                                                            |                      2.17 |
| S4   | R1       | No         |                    0 | -                                                                            |                      2.26 |
| S5   | R1       | No         |                    0 | -                                                                            |                      2.14 |
| S6a  | R1       | Yes        |                  100 | GATEWAY_PIN_MISMATCH (tools/list stripped)                                   |                      0.89 |
| S6b  | R1       | No         |                    0 | -                                                                            |                      2.25 |
| S7   | R1       | No         |                    0 | -                                                                            |                      5.35 |
| S1   | R2       | Yes        |                  100 | HASH_MISMATCH                                                                |                      6.16 |
| S2   | R2       | Yes        |                  100 | CHAIN_BREAK, SEQUENCE_GAP                                                    |                      6.09 |
| S3   | R2       | No         |                    0 | -                                                                            |                      5.67 |
| S4   | R2       | Yes        |                  100 | HASH_MISMATCH                                                                |                      6.69 |
| S5   | R2       | No         |                    0 | -                                                                            |                      7.38 |
| S6a  | R2       | Yes        |                  100 | GATEWAY_PIN_MISMATCH (tools/list stripped)                                   |                      0.92 |
| S6b  | R2       | No         |                    0 | -                                                                            |                      6.62 |
| S7   | R2       | No         |                    0 | -                                                                            |                     21.92 |
| S1   | R3       | Yes        |                  100 | ANCHOR_RECORDS_MISMATCH, HASH_MISMATCH, MERKLE_ROOT_MISMATCH                 |                   5937.35 |
| S2   | R3       | Yes        |                  100 | ANCHORED_RECORDS_MISSING, CHAIN_BREAK, MERKLE_BATCH_INCOMPLETE, SEQUENCE_GAP |                   6346.57 |
| S3   | R3       | Yes        |                  100 | ANCHORED_BATCH_MISSING, TAIL_TRUNCATION                                      |                   5735.33 |
| S4   | R3       | Yes        |                  100 | ANCHOR_RECORDS_MISMATCH, HASH_MISMATCH, MERKLE_ROOT_MISMATCH                 |                   5945.75 |
| S5   | R3       | Yes        |                  100 | ANCHOR_RECORDS_MISMATCH, ANCHOR_ROOT_MISMATCH                                |                   5889.01 |
| S6a  | R3       | Yes        |                  100 | GATEWAY_PIN_MISMATCH (tools/list stripped)                                   |                      0.9  |
| S6b  | R3       | Yes        |                  100 | MANIFEST_DRIFT, REGISTRY_PIN_REWRITTEN                                       |                   6243.13 |
| S7   | R3       | Yes        |                  100 | MODEL_FILE_TAMPERED                                                          |                   6891.99 |

R1 checks only id continuity, R2 only the hash chain, R3 the hash chain plus Merkle roots,
on-chain anchors, tool-manifest drift and ML model/tokenizer integrity against the watcher's own snapshots.
