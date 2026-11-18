# OmniGuard-MCP threat model

## 1. System and trust boundaries

```
 AI agent (MCP client)                         untrusted input (prompts, web pages, tool output)
        |  JSON-RPC (stdio / HTTP, bearer token)
        v
+----------------------------------------------+      Trust boundary A: agent <-> gateway
| Agent 1  Gateway & information-flow firewall |
|   identity -> tool integrity -> ABAC ->      |
|   ingress engine -> downstream -> taint ->   |
|   egress engine/DLP -> audit dispatch        |
+--------------------+-------------------------+
        | in-process call                      |  JSON-RPC
        v                                      v
+---------------------------+        +-----------------------------+   Trust boundary B:
| Agent 2  Audit / Merkle / |        | Downstream MCP tool server  |   gateway <-> tool server
| anchoring (SQLite R1-R3)  |        | (reference server simulates |
+-------------+-------------+        |  every side effect)         |
              | anchorBatch() tx     +-----------------------------+
              v
       EVM chain (AuditAnchor.sol, write-once)  <-- read-only RPC --+
              ^                                                    |
              |                                    Trust boundary C: watcher is out-of-band
+-------------+--------------------------------------------------+ |
| Agent 3  Independent watcher: own OS process, mode=ro DB,       |-+
|          own RPC client, own manifest snapshot                  |
+-----------------------------------------------------------------+
```

| Component | Trusted for | Not trusted for |
|---|---|---|
| Agent (LLM) | nothing; treated as confused-deputy prone | every argument it sends |
| Tool output | nothing; may carry indirect prompt injection or secrets | anything that reaches the agent |
| Gateway | enforcing policy at request time | proving, after the fact, that its own log is intact |
| Audit DB | durability | integrity (an insider can edit it) |
| Chain | ordering and immutability of anchored roots | confidentiality (only roots are published) |
| Watcher | independent verification | prevention (it detects, it does not block) |
| ONNX model + tokenizer files | nothing until their SHA-256 matches the pin | anything if a single byte differs |
| Classifier output | an *additional* DENY signal on routed prose | allowing anything the deterministic rules denied |

## 2. Adversaries

1. **Malicious or manipulated agent input:** path traversal, SSRF, shell or SQL injection, encoded payloads, prompt injection in arguments.
2. **Malicious content returned by tools:** indirect prompt injection in web pages or files, secrets in outputs.
3. **Multi-step exfiltration:** reading something sensitive, then sending it out through a later outbound call.
4. **Malicious or compromised tool server:** rug-pull or tool-poisoning by changing a tool description or schema after it was approved.
5. **Insider with write access** to the audit database and the gateway's config, trying to rewrite history. They do *not* hold the chain anchorer's key and cannot modify the watcher's snapshots.
6. **Model supply-chain / tampering attacker:** swaps or patches the deployed ONNX weights or the tokenizer offline, for example to blind the classifier to chosen phrasings with a backdoor-style vocabulary remap.

## 3. Security guarantees

| ID | Guarantee | Mechanism | Holds under |
|---|---|---|---|
| G1 | A tool whose name, description or input schema differs from its pinned SHA-256 digest is never listed or executed. | `tool_integrity.py`, verified on every `tools/list` and `tools/call` | adversary 4 |
| G2 | A role can call only the tools and parameter shapes its policy allows; everything else is denied. | `abac.py` deny-by-default policy-as-code over canonicalized arguments | adversaries 1, 3 |
| G3 | Encoding (URL, nested URL, Base64, hex, `\x` escapes, HTML entities, Unicode compatibility forms, zero-width characters) does not hide a payload from the analyzers. | `canonicalizer.py` decodes to a fixed point (bounded depth); analyzers inspect every view | adversary 1 |
| G4 | Paths outside the workspace, private/loopback/link-local/metadata addresses (including decimal, hex, octal and IPv4-mapped forms), non-HTTP schemes, shell chaining/substitution and stacked/union/tautology/time-based SQL are denied structurally. | `analyzers.py` parsers | adversary 1 |
| G5 | Once a session has read sensitive data, no outbound tool runs in that session; taint labels never decrease. | `taint_tracker.py` + ABAC taint policy + engine rule `TAINT_SENSITIVE_TO_EGRESS` | adversary 3 |
| G6 | Known credential formats (AWS, GitHub, `sk-` keys, Slack, Google, PEM private keys, JWT, high-entropy assignments) are redacted from tool output and refused as arguments to outbound tools. | `EntropyDLP` | adversaries 2, 3 |
| G7 | Every decision is deterministic and explainable: same input + same taint state gives the same decision, risk score, rule list and `canonical_input_hash`. | no ML; weighted rules in `security_rules.yaml` | all |
| G8 | (R2/R3) Modifying, deleting, inserting or reordering any audit row is detected. | SHA-256 hash chain over row content | adversary 5 |
| G9 | (R3) Rolling back anchored batches, or forging records and then recomputing the chain *and* local Merkle roots, is detected. | Merkle roots anchored in a write-once contract; the watcher compares roots rebuilt from records with on-chain roots | adversary 5 |
| G10 | (R3) A rug-pull that also rewrites the gateway's pins is detected. | watcher re-hashes registry, observed, and live definitions against its own snapshot | adversaries 4 + 5 |
| G11 | The gateway never runs a model or tokenizer whose bytes differ from the pinned SHA-256 digests. It fails closed and refuses to start. | `ml_classifier.py` reads both files into memory, checks them with `hmac.compare_digest`, then builds the tokenizer and `InferenceSession` from those same verified bytes, so there is no check-then-use gap | adversary 6 |
| G12 | (R3) Offline model or tokenizer tampering, even when the insider also rewrites the gateway's model manifest, is detected. So is any decision logged by an unpinned model. | watcher re-hashes the deployed files against its own model snapshot; `model_sha16` is in every hybrid audit record and covered by the hash chain | adversaries 5 + 6 |
| G13 | The ML stage cannot weaken the deterministic one. It can only add a DENY to a payload the rules already allowed, and it never sees structured arguments or structured outputs. | routing order + `output_type` in the pinned tool manifest | all |
| G14 | Hybrid decisions are reproducible from the audit log. The classifier output is quantized to an integer `ml_score_milli` (0–1000) *before* it is compared with an integer threshold. The logged value is exactly the value the decision used. | `quantize_milli` + integer thresholds | all |

## 4. Limitations (stated explicitly)

### Hybrid ML stage

* **The classifier narrows the semantic gap; it does not close it.** On held-out `deepset/prompt-injections` rows, the hybrid engine catches more paraphrased injections than signatures alone, but recall is still well below 1 (`results/external_dataset_eval.md`). The model is an English-prose classifier, and German or other non-English injections are frequently missed.
* **Training-data contamination.** `jackhhao/jailbreak-classification` is in the model's published training set. Hybrid numbers on that stream are reported but flagged and must not be read as generalisation. The model card also lists eight unnamed MIT-licensed training sets, so overlap with other public corpora cannot be fully excluded.
* **Small calibration set.** Thresholds were chosen on 125 dev rows (86 routed). The precision target (0.99 clean / 0.95 untrusted) is met on dev, but the confidence interval is wide. The held-out FPR is the number to trust.
* **Routing is an attack surface.** Only prose is scored. Config-shaped text (≥ 80% `key=value` / comment lines), structured tool outputs, and payloads ≤ 40 characters skip the model. An attacker can format an injection as config lines to stay on the deterministic path, where only signatures and DLP apply. This trade-off is deliberate: the model fires at 990–1000 on ordinary `.env` and key files.
* **Adversarial ML.** A fixed public model can be probed offline for evasive phrasings. Integrity pinning prevents *changing* the model; it does not make the model robust.
* **Numerical determinism across providers.** CUDA and CPU kernels can differ in the last float bits. Quantizing to milli-units makes a decision flip possible only for scores within ±0.0005 of a threshold, and the provider is logged per record.
* **Upstream status.** The model's repository is archived by its authors. Pinning to a fixed revision and digest means updates are a deliberate re-pin and re-calibration, never silent.

### Deterministic stage and audit

* **Semantic prompt injection is not solved.** Canonicalization, structural parsers and taint tracking close the encoding, injection and multi-step exfiltration vectors listed above. Deterministic signatures still **cannot reliably detect novel or paraphrased indirect prompt injection**. External validation measures this directly: on held-out `deepset/prompt-injections` and `jackhhao/jailbreak-classification` samples the engine has high precision but recall well below 1 (see `results/external_dataset_eval.md`, which lists real false negatives). OmniGuard does **not** claim comprehensive semantic threat detection. Its defense for that class is containment: taint-based egress blocking (G5) and ABAC (G2) limit what a successfully injected agent can *do*.
* **Detection, not prevention, for audit tampering.** The watcher raises `TamperAlert`s; it cannot undo a modification or stop an insider. Response is out of scope.
* **Exposure window.** Records written since the last anchored batch (fewer than `B` records, or the async anchoring queue) are protected only by the hash chain. An insider can truncate that unanchored tail without R3 noticing. `unanchored_tail` in the watcher report makes the window visible. Smaller `B` shrinks it at higher gas cost.
* **R2 blind spots, by design:** a valid prefix of a hash chain is still valid (tail truncation), and an attacker who recomputes the chain produces a self-consistent forgery. These are exactly the gaps R3's anchoring closes, and the experiments measure them.
* **Development chain.** Experiments use an embedded eth-tester/py-evm chain (in-process, or a separate node process over JSON-RPC). It is not a decentralized ledger: whoever controls the node controls history. In deployment, anchor to a chain the insider does not control (public L1/L2 or a consortium chain), and keep the anchorer key outside the gateway host.
* **SSRF without DNS.** The validator is deliberately offline and deterministic. A hostname that *resolves* to a private address (DNS rebinding) is not caught. Production deployments should resolve-and-pin at the egress proxy.
* **SQL policy vs dataset labels.** The engine denies `DELETE`, DDL and stacked statements for the read-only `query_db` tool even when a dataset labels them benign. Those show up as false positives in the external metrics.
* **Signature evasion.** Rules are public by design (explainability). A motivated attacker can craft inputs below the threshold. The weighted scoring, taint multipliers and structural (non-signature) checks are intended to make that harder, not impossible.
* **Reference tool server.** All side effects in `sample_mcp_server.py` are simulated. Integration with real tools needs their own sandboxing.

## 5. Residual risk summary

| Threat | Residual risk | Why |
|---|---|---|
| Encoded or structural injection | Low | parser-based plus canonicalization (G3, G4) |
| Novel semantic or indirect prompt injection | **Medium** (hybrid) / Medium-High (deterministic-only) | pinned classifier on prose plus signatures; recall still well below 1, so containment (G2, G5) remains the backstop |
| Model or tokenizer tampering | Low | G11 (load-time, fail closed), G12 (out-of-band watcher) |
| Injection formatted to dodge ML routing | Medium | config-shaped / short / structured payloads get signatures + DLP only |
| Multi-step exfiltration via outbound tools | Low | monotone taint (G5) |
| Exfiltration via non-outbound side channels (e.g. encoding data into a file name) | Medium | only declared `outbound_egress` tools are taint-gated |
| Tool rug-pull | Low | G1, G10 |
| Audit tampering by insider | Low (anchored) / Medium (unanchored tail) | G8-G9, exposure window |
