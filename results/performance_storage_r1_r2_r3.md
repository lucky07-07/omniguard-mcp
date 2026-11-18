# Experiment 2 - Latency and storage overhead (R1 vs R2 vs R3), fast path vs hybrid path

M = 500 MCP `tools/call` requests per workload and regime (seed 11), Merkle batch
size B = 16; 40 warm-up requests per workload (GPU included) discarded.
Chain: eth-tester/py-evm node over HTTP JSON-RPC. SQLite: WAL, synchronous=NORMAL, commit per event. Latency is wall-clock time through `GatewayAgent.handle`.

* **structured** - structured arguments and outputs only: deterministic fast path, never routed to the model.
* **unstructured** - free-text arguments (> 40 chars) or free-text tool outputs: hybrid path, ONNX classifier
  on the GPU after the deterministic checks pass (requests the deterministic engine already denies are not routed).

## Workload: structured

### End-to-end request latency

| Regime   |   Routed to ML |   Mean (ms) |   p50 |    p95 |     p99 | Mean vs R1   | p99 vs R1   |
|----------|----------------|-------------|-------|--------|---------|--------------|-------------|
| R1       |              0 |       0.642 | 0.567 |  1.091 |   1.502 | +0.0%        | +0.0%       |
| R2       |              0 |       0.636 | 0.596 |  1.108 |   1.426 | -1.0%        | -5.1%       |
| R3       |              0 |       6.483 | 0.642 | 67.852 | 111.425 | +909.1%      | +7315.9%    |
| R3-async |              0 |       0.84  | 0.744 |  1.677 |   2.701 | +30.7%       | +79.8%      |

### Pipeline stage breakdown

| Stage (mean ms / request)   |     R1 |     R2 |     R3 |   R3-async |
|-----------------------------|--------|--------|--------|------------|
| tool_integrity              | 0.1567 | 0.1619 | 0.1726 |     0.1681 |
| deterministic_engine        | 0.2462 | 0.2576 | 0.2741 |     0.2708 |
| ml_tokenize                 | 0      | 0      | 0      |     0      |
| ml_onnx_inference           | 0      | 0      | 0      |     0      |
| downstream_tool             | 0.0209 | 0.0218 | 0.0248 |     0.0408 |
| audit_total                 | 0.1615 | 0.1367 | 5.9475 |     0.2961 |
| hash_chain                  | 0      | 0.0242 | 0.0257 |     0.0253 |
| merkle_build_amortized      | 0      | 0      | 0.0364 |     0.0556 |
| anchor_tx_amortized         | 0      | 0      | 5.9009 |     0      |

"deterministic_engine" = ABAC + ingress + egress inspection excluding ML tokenization/inference; Merkle and anchor
rows are amortized over all requests.

### Per-batch cost (R3)

| Regime   |   Batches |   Merkle build / batch (ms) |   Anchor tx / batch (ms) |   Anchor tx p95 (ms) |
|----------|-----------|-----------------------------|--------------------------|----------------------|
| R3       |        32 |                       0.587 |                   92.201 |              147.514 |
| R3-async |        32 |                       0.897 |                   81.558 |              111.407 |

### Storage overhead

| Regime   |   Audit events |   SQLite bytes |   Bytes / event |   Merkle proof bytes |   Anchor txs |   Gas total |   Gas / event |   Calldata bytes |
|----------|----------------|----------------|-----------------|----------------------|--------------|-------------|---------------|------------------|
| R1       |            508 |         184320 |          362.83 |                    0 |            0 |           0 |           0   |                0 |
| R2       |            508 |         258048 |          507.97 |                    0 |            0 |           0 |           0   |                0 |
| R3       |            508 |         483328 |          951.43 |               198240 |           32 |     3273875 |        6444.6 |             4224 |
| R3-async |            508 |         483328 |          951.43 |               198240 |           32 |     3273947 |        6444.8 |             4224 |

## Workload: unstructured

### End-to-end request latency

| Regime   |   Routed to ML |   Mean (ms) |    p50 |    p95 |     p99 | Mean vs R1   | p99 vs R1   |
|----------|----------------|-------------|--------|--------|---------|--------------|-------------|
| R1       |            462 |      15.58  | 14.595 | 24.84  |  46.617 | +0.0%        | +0.0%       |
| R2       |            462 |      14.752 | 14.466 | 23.629 |  28.24  | -5.3%        | -39.4%      |
| R3       |            462 |      21.089 | 14.69  | 90.668 | 134.411 | +35.4%       | +188.3%     |
| R3-async |            462 |      16.809 | 16.538 | 26.626 |  29.538 | +7.9%        | -36.6%      |

ONNX inference when routed (execution provider **cuda**): mean 15.34 ms, p50 13.66, p95 23.00, p99 33.97 ms (R1 run).

### Pipeline stage breakdown

| Stage (mean ms / request)   |      R1 |      R2 |      R3 |   R3-async |
|-----------------------------|---------|---------|---------|------------|
| tool_integrity              |  0.1979 |  0.1873 |  0.1961 |     0.2174 |
| deterministic_engine        |  0.5384 |  0.5061 |  0.5231 |     0.569  |
| ml_tokenize                 |  0.2164 |  0.2039 |  0.2146 |     0.2277 |
| ml_onnx_inference           | 14.1765 | 13.4783 | 13.9661 |    15.3162 |
| downstream_tool             |  0.0432 |  0.0405 |  0.0414 |     0.0444 |
| audit_total                 |  0.2823 |  0.2191 |  6.0293 |     0.309  |
| hash_chain                  |  0      |  0.0371 |  0.0386 |     0.0409 |
| merkle_build_amortized      |  0      |  0      |  0.0427 |     0.0431 |
| anchor_tx_amortized         |  0      |  0      |  5.9208 |     0      |

"deterministic_engine" = ABAC + ingress + egress inspection excluding ML tokenization/inference; Merkle and anchor
rows are amortized over all requests.

### Per-batch cost (R3)

| Regime   |   Batches |   Merkle build / batch (ms) |   Anchor tx / batch (ms) |   Anchor tx p95 (ms) |
|----------|-----------|-----------------------------|--------------------------|----------------------|
| R3       |        32 |                       0.689 |                   92.512 |              130.35  |
| R3-async |        32 |                       0.696 |                   90.432 |              117.727 |

### Storage overhead

| Regime   |   Audit events |   SQLite bytes |   Bytes / event |   Merkle proof bytes |   Anchor txs |   Gas total |   Gas / event |   Calldata bytes |
|----------|----------------|----------------|-----------------|----------------------|--------------|-------------|---------------|------------------|
| R1       |            504 |         188416 |          373.84 |                    0 |            0 |           0 |           0   |                0 |
| R2       |            504 |         262144 |          520.13 |                    0 |            0 |           0 |           0   |                0 |
| R3       |            504 |         487424 |          967.11 |               196284 |           32 |     3273923 |        6495.9 |             4224 |
| R3-async |            504 |         487424 |          967.11 |               196284 |           32 |     3273911 |        6495.9 |             4224 |
