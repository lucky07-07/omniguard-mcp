# OmniGuard-MCP - experiment summary

Generated 2026-11-19 01:27:10 on Windows-11-10.0.26300-SP0 / Python 3.13.12, total runtime 16.4 min.

## Engines

| Key | Engine | Model | Provider | Thresholds (milli) |
|---|---|---|---|---|
| v1.0 | v1.0 deterministic | - | - | - |
| v1.1 | v1.1 hybrid (ProtectAI DeBERTa v2) | protectai-deberta-v3-base-v2 | cuda | 896 / 328 |
| v1.2 | v1.2 hybrid (Horizon guard-base + cascade) | horizon-guard-base | cuda | 260 / 190 + rule-hit cascade |
| v1.2-small | ablation: v1.2 with Horizon guard-small | horizon-guard-small | cuda | 530 / 350 + rule-hit cascade |

## External validation (held-out; prompt-injection rows = official test split only)

| Stream | View | n | v1.0 F1 | v1.1 F1 | v1.2 F1 | v1.2-small F1 | v1.2 P / R |
|---|---|---|---|---|---|---|---|
| prompt_injection_ingress | clean | 95 | 0.295 | 0.556 | 0.844 | 0.776 | 1.000 / 0.731 |
| prompt_injection_egress | clean | 95 | 0.400 | 0.613 | 0.870 | 0.844 | 1.000 / 0.769 |
| jailbreak_ingress | clean | 214 | 0.687 | 0.906 ⚠ | 0.916 | 0.912 | 0.933 / 0.899 |
| sql_injection | full | 500 | 0.922 | 0.922 | 0.922 | 0.922 | 0.943 / 0.902 |
| command_injection | full | 500 | 0.911 | 0.911 | 0.911 | 0.911 | 1.000 / 0.836 |

⚠ = rows overlap that model's published training data.

## Tamper detection (trials detected)

| Regime | Detected | Rate |
|---|---|---|
| R1 | 10/40 | 25.0% |
| R2 | 20/40 | 50.0% |
| R3 | 40/40 | 100.0% |

## Latency (ms) by workload

| Workload | Regime | Routed to ML | Mean | p95 | p99 | Det. engine | ONNX infer | Bytes/event |
|---|---|---|---|---|---|---|---|---|
| structured | R1 | 0/500 | 0.641 | 0.998 | 1.260 | 0.248 | 0.000 | 362.83 |
| structured | R2 | 0/500 | 0.742 | 1.226 | 2.008 | 0.283 | 0.000 | 507.97 |
| structured | R3 | 0/500 | 6.604 | 69.549 | 118.114 | 0.279 | 0.000 | 951.43 |
| structured | R3-async | 0/500 | 0.892 | 1.736 | 2.594 | 0.283 | 0.000 | 951.43 |
| unstructured | R1 | 462/500 | 19.494 | 32.762 | 67.964 | 0.547 | 18.003 | 381.97 |
| unstructured | R2 | 462/500 | 18.205 | 28.641 | 37.485 | 0.730 | 16.599 | 520.13 |
| unstructured | R3 | 462/500 | 24.943 | 92.581 | 140.105 | 0.531 | 17.500 | 967.11 |
| unstructured | R3-async | 462/500 | 20.125 | 32.413 | 38.995 | 0.556 | 18.579 | 967.11 |

Details: `external_dataset_eval.md`, `ml_calibration.json`, `tamper_detection_r1_r2_r3.md`, `performance_storage_r1_r2_r3.md`.
