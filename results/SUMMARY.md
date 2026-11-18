# OmniGuard-MCP - experiment summary

Generated 2026-11-18 20:49:06 on Windows-11-10.0.26300-SP0 / Python 3.13.12, total runtime 3.7 min.

## External validation (held-out partition)

| Stream | n | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| prompt_injection_ingress | 500 | 1.000 | 0.199 | 0.332 | 0.000 |
| prompt_injection_egress | 500 | 1.000 | 0.289 | 0.448 | 0.000 |
| jailbreak_ingress | 500 | 1.000 | 0.490 | 0.657 | 0.000 |
| sql_injection | 500 | 0.943 | 0.902 | 0.922 | 0.032 |
| command_injection | 500 | 1.000 | 0.836 | 0.911 | 0.000 |

## Tamper detection (trials detected)

| Regime | Detected | Rate |
|---|---|---|
| R1 | 10/35 | 28.6% |
| R2 | 20/35 | 57.1% |
| R3 | 35/35 | 100.0% |

## Latency and storage

| Regime | Mean ms | p95 ms | p99 ms | Bytes/event | Gas/event |
|---|---|---|---|---|---|
| R1 | 0.511 | 0.721 | 0.892 | 357.21 | 0.0 |
| R2 | 0.477 | 0.712 | 0.854 | 500.09 | 0.0 |
| R3 | 8.037 | 94.438 | 138.187 | 944.62 | 6542.2 |
| R3-async | 0.631 | 1.269 | 1.993 | 944.62 | 6542.1 |

Details: `external_dataset_eval.md`, `tamper_detection_r1_r2_r3.md`, `performance_storage_r1_r2_r3.md`.
