# OmniGuard-MCP - experiment summary

Generated 2026-11-19 00:05:01 on Windows-11-10.0.26300-SP0 / Python 3.13.12, total runtime 12.0 min.

Hybrid model: `protectai/deberta-v3-base-prompt-injection-v2` (sha256 `f0ea7f239f765aed`...), provider **cuda**, frozen thresholds clean 896 / untrusted 328 (milli).

## External validation (held-out partition)

| Stream | n | Det. P | Det. R | Det. F1 | Hybrid P | Hybrid R | Hybrid F1 | Hybrid FPR |
|---|---|---|---|---|---|---|---|---|
| prompt_injection_ingress | 500 | 1.000 | 0.199 | 0.332 | 0.988 | 0.398 | 0.567 | 0.003 |
| prompt_injection_egress | 500 | 1.000 | 0.289 | 0.448 | 0.990 | 0.478 | 0.644 | 0.003 |
| jailbreak_ingress (contaminated) | 500 | 1.000 | 0.490 | 0.657 | 0.995 | 0.833 | 0.907 | 0.004 |
| sql_injection | 500 | 0.943 | 0.902 | 0.922 | 0.943 | 0.902 | 0.922 | 0.032 |
| command_injection | 500 | 1.000 | 0.836 | 0.911 | 1.000 | 0.836 | 0.911 | 0.000 |

## Tamper detection (trials detected)

| Regime | Detected | Rate |
|---|---|---|
| R1 | 10/40 | 25.0% |
| R2 | 20/40 | 50.0% |
| R3 | 40/40 | 100.0% |

## Latency (ms) by workload

| Workload | Regime | Routed to ML | Mean | p95 | p99 | Det. engine | ONNX infer | Bytes/event |
|---|---|---|---|---|---|---|---|---|
| structured | R1 | 0/500 | 0.642 | 1.091 | 1.502 | 0.246 | 0.000 | 362.83 |
| structured | R2 | 0/500 | 0.636 | 1.108 | 1.426 | 0.258 | 0.000 | 507.97 |
| structured | R3 | 0/500 | 6.483 | 67.852 | 111.425 | 0.274 | 0.000 | 951.43 |
| structured | R3-async | 0/500 | 0.840 | 1.677 | 2.701 | 0.271 | 0.000 | 951.43 |
| unstructured | R1 | 462/500 | 15.580 | 24.840 | 46.617 | 0.538 | 14.177 | 373.84 |
| unstructured | R2 | 462/500 | 14.752 | 23.629 | 28.240 | 0.506 | 13.478 | 520.13 |
| unstructured | R3 | 462/500 | 21.089 | 90.668 | 134.411 | 0.523 | 13.966 | 967.11 |
| unstructured | R3-async | 462/500 | 16.809 | 26.626 | 29.538 | 0.569 | 15.316 | 967.11 |

Details: `external_dataset_eval.md`, `ml_calibration.json`, `tamper_detection_r1_r2_r3.md`, `performance_storage_r1_r2_r3.md`.
