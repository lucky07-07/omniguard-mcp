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
| R1       |              0 |       0.641 | 0.591 |  0.998 |   1.26  | +0.0%        | +0.0%       |
| R2       |              0 |       0.742 | 0.668 |  1.226 |   2.008 | +15.8%       | +59.4%      |
| R3       |              0 |       6.604 | 0.674 | 69.549 | 118.114 | +929.8%      | +9271.9%    |
| R3-async |              0 |       0.892 | 0.796 |  1.736 |   2.594 | +39.1%       | +105.8%     |

### Pipeline stage breakdown

| Stage (mean ms / request)   |     R1 |     R2 |     R3 |   R3-async |
|-----------------------------|--------|--------|--------|------------|
| tool_integrity              | 0.1514 | 0.1784 | 0.1697 |     0.1748 |
| deterministic_engine        | 0.2485 | 0.2829 | 0.2785 |     0.2834 |
| ml_tokenize                 | 0      | 0      | 0      |     0      |
| ml_onnx_inference           | 0      | 0      | 0      |     0      |
| downstream_tool             | 0.0221 | 0.0274 | 0.0271 |     0.0349 |
| audit_total                 | 0.1626 | 0.1894 | 6.0621 |     0.33   |
| hash_chain                  | 0      | 0.0279 | 0.0267 |     0.0267 |
| merkle_build_amortized      | 0      | 0      | 0.0357 |     0.0549 |
| anchor_tx_amortized         | 0      | 0      | 5.982  |     0      |

"deterministic_engine" = ABAC + ingress + egress inspection excluding ML tokenization/inference; Merkle and anchor
rows are amortized over all requests.

### Per-batch cost (R3)

| Regime   |   Batches |   Merkle build / batch (ms) |   Anchor tx / batch (ms) |   Anchor tx p95 (ms) |
|----------|-----------|-----------------------------|--------------------------|----------------------|
| R3       |        32 |                       0.575 |                   93.468 |              138.554 |
| R3-async |        32 |                       0.886 |                   94.125 |              140.525 |

### Storage overhead

| Regime   |   Audit events |   SQLite bytes |   Bytes / event |   Merkle proof bytes |   Anchor txs |   Gas total |   Gas / event |   Calldata bytes |
|----------|----------------|----------------|-----------------|----------------------|--------------|-------------|---------------|------------------|
| R1       |            508 |         184320 |          362.83 |                    0 |            0 |           0 |           0   |                0 |
| R2       |            508 |         258048 |          507.97 |                    0 |            0 |           0 |           0   |                0 |
| R3       |            508 |         483328 |          951.43 |               198240 |           32 |     3273911 |        6444.7 |             4224 |
| R3-async |            508 |         483328 |          951.43 |               198240 |           32 |     3273911 |        6444.7 |             4224 |

## Workload: unstructured

### End-to-end request latency

| Regime   |   Routed to ML |   Mean (ms) |    p50 |    p95 |     p99 | Mean vs R1   | p99 vs R1   |
|----------|----------------|-------------|--------|--------|---------|--------------|-------------|
| R1       |            462 |      19.494 | 17.079 | 32.762 |  67.964 | +0.0%        | +0.0%       |
| R2       |            462 |      18.205 | 17.461 | 28.641 |  37.485 | -6.6%        | -44.9%      |
| R3       |            462 |      24.943 | 18.455 | 92.581 | 140.105 | +27.9%       | +106.2%     |
| R3-async |            462 |      20.125 | 19.624 | 32.413 |  38.995 | +3.2%        | -42.6%      |

ONNX inference when routed (execution provider **cuda**): mean 19.48 ms, p50 16.04, p95 32.24, p99 63.39 ms (R1 run).

### Pipeline stage breakdown

| Stage (mean ms / request)   |      R1 |      R2 |      R3 |   R3-async |
|-----------------------------|---------|---------|---------|------------|
| tool_integrity              |  0.2051 |  0.1877 |  0.1888 |     0.2011 |
| deterministic_engine        |  0.5469 |  0.7303 |  0.5312 |     0.5559 |
| ml_tokenize                 |  0.3411 |  0.2974 |  0.3062 |     0.3192 |
| ml_onnx_inference           | 18.0027 | 16.5988 | 17.4997 |    18.5787 |
| downstream_tool             |  0.0424 |  0.0421 |  0.0425 |     0.046  |
| audit_total                 |  0.2246 |  0.232  |  6.2562 |     0.3008 |
| hash_chain                  |  0      |  0.037  |  0.0375 |     0.0395 |
| merkle_build_amortized      |  0      |  0      |  0.0406 |     0.0413 |
| anchor_tx_amortized         |  0      |  0      |  6.1648 |     0      |

"deterministic_engine" = ABAC + ingress + egress inspection excluding ML tokenization/inference; Merkle and anchor
rows are amortized over all requests.

### Per-batch cost (R3)

| Regime   |   Batches |   Merkle build / batch (ms) |   Anchor tx / batch (ms) |   Anchor tx p95 (ms) |
|----------|-----------|-----------------------------|--------------------------|----------------------|
| R3       |        32 |                       0.655 |                   96.325 |              131.637 |
| R3-async |        32 |                       0.666 |                   88.126 |              117.577 |

### Storage overhead

| Regime   |   Audit events |   SQLite bytes |   Bytes / event |   Merkle proof bytes |   Anchor txs |   Gas total |   Gas / event |   Calldata bytes |
|----------|----------------|----------------|-----------------|----------------------|--------------|-------------|---------------|------------------|
| R1       |            504 |         192512 |          381.97 |                    0 |            0 |           0 |           0   |                0 |
| R2       |            504 |         262144 |          520.13 |                    0 |            0 |           0 |           0   |                0 |
| R3       |            504 |         487424 |          967.11 |               196284 |           32 |     3273899 |        6495.8 |             4224 |
| R3-async |            504 |         487424 |          967.11 |               196284 |           32 |     3273887 |        6495.8 |             4224 |
