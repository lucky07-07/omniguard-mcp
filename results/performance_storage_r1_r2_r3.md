# Experiment 2 - Latency and storage overhead (R1 vs R2 vs R3)

M = 500 MCP `tools/call` requests per regime (seed 11), Merkle batch size B = 16,
30 warm-up requests discarded. Chain: eth-tester/py-evm node over HTTP JSON-RPC. SQLite: WAL, synchronous=NORMAL, commit per event.
Latency is wall-clock time through `GatewayAgent.handle` (integrity, ABAC, ingress, downstream call,
egress, audit). R3 anchors synchronously in the request path, so a batch-sealing request carries the
Merkle build and the on-chain transaction.

## End-to-end request latency

| Regime   |   Mean (ms) |   p50 (ms) |   p95 (ms) |   p99 (ms) | Mean overhead vs R1   | p99 overhead vs R1   |
|----------|-------------|------------|------------|------------|-----------------------|----------------------|
| R1       |       0.511 |      0.475 |      0.721 |      0.892 | +0.0%                 | +0.0%                |
| R2       |       0.477 |      0.494 |      0.712 |      0.854 | -6.7%                 | -4.3%                |
| R3       |       8.037 |      0.541 |     94.438 |    138.187 | +1472.9%              | +15386.6%            |
| R3-async |       0.631 |      0.547 |      1.269 |      1.993 | +23.4%                | +123.4%              |

## Pipeline stage breakdown

| Stage (mean ms / request)   |     R1 |     R2 |     R3 |   R3-async |
|-----------------------------|--------|--------|--------|------------|
| tool_integrity              | 0.1293 | 0.1288 | 0.1448 |     0.1364 |
| security_engine             | 0.183  | 0.1834 | 0.2059 |     0.1938 |
| downstream_tool             | 0.0136 | 0.0138 | 0.0169 |     0.0171 |
| audit_total                 | 0.1382 | 0.1046 | 7.6158 |     0.2332 |
| hash_chain                  | 0      | 0.0177 | 0.0199 |     0.0188 |
| merkle_build_amortized      | 0      | 0      | 0.0305 |     0.0462 |
| anchor_tx_amortized         | 0      | 0      | 7.7168 |     0      |

"Security engine" = ABAC + ingress (canonicalization, structural analyzers, signatures, taint, DLP) + egress
inspection. Merkle and anchor rows are amortized over all requests.

## Per-batch cost (R3)

| Regime   |   Batches |   Merkle build / batch (ms) |   Anchor tx / batch (ms) |   Anchor tx p95 (ms) |
|----------|-----------|-----------------------------|--------------------------|----------------------|
| R1       |         0 |                       0     |                    0     |                0     |
| R2       |         0 |                       0     |                    0     |                0     |
| R3       |        33 |                       0.491 |                  116.921 |              147.06  |
| R3-async |        33 |                       0.745 |                  108.742 |              146.257 |

## Storage overhead

| Regime   |   Audit events |   SQLite bytes |   Bytes / event |   Merkle proof bytes |   Anchor txs |   Gas total |   Gas / event |   Calldata bytes |
|----------|----------------|----------------|-----------------|----------------------|--------------|-------------|---------------|------------------|
| R1       |            516 |         184320 |          357.21 |                    0 |            0 |           0 |           0   |                0 |
| R2       |            516 |         258048 |          500.09 |                    0 |            0 |           0 |           0   |                0 |
| R3       |            516 |         487424 |          944.62 |               200976 |           33 |     3375753 |        6542.2 |             4356 |
| R3-async |            516 |         487424 |          944.62 |               200976 |           33 |     3375741 |        6542.1 |             4356 |
