# Detection Engine & Entity Taxonomy

The AEGF Rust detection service combines local machine-learning inference with high-speed deterministic pattern matching.

## 1. Local GLiNER ONNX Inference

GLiNER (Generalist and Lightweight Named Entity Recognition) performs zero-shot entity extraction via label conditioning:

- **Model Backbone:** `urchade/gliner_small-v2.1` exported and quantized to INT8 ONNX (`nexuswho/gliner-onnx-small`).
- **Dynamic Taxonomy:** Candidate entity labels (e.g. `person`, `email`, `medical_identifier`, `internal_project`) are supplied dynamically in the prompt prefix (`<<ENT>> label <<SEP>>`) at runtime.
- **Word Segmentation & Subtoken Pooling:** Input text is segmented into words preserving character start/end offsets. Subtokens are pooled using first-token indexing.
- **Span Representation:** Fixed-width candidate spans up to width 12 are projected through ONNX Runtime and scored with sigmoid probabilities.

## 2. Deterministic Detection

The deterministic engine provides zero-latency, high-precision detection for known credential and data formats:

- **API Keys:**
  - OpenAI (`sk-[a-zA-Z0-9_-]{20,}`)
  - Anthropic (`sk-ant-[a-zA-Z0-9_-]{20,}`)
  - GitHub Personal Access Tokens (`gh[pousr]_[A-Za-z0-9_]{36,}`)
  - AWS Access Keys (`\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b`)
  - Slack Tokens (`xox[baprs]-[0-9a-zA-Z-]{10,}`)
- **Private Key Blocks:** OpenSSH, RSA, EC, DSA, and PGP PEM headers.
- **JSON Web Tokens (JWT):** Three-part dot-separated base64 token formats.
- **Credit Cards:** Algorithmic validation via Luhn check (MOD 10). Numbers that fail Luhn validation are rejected as false positives.
- **Network Identifiers:** IPv4 and IPv6 addresses.
- **Contact Details:** International and national phone numbers; RFC-compatible email addresses.
- **Custom Organization Patterns:** Configurable through YAML without compiling source code.

## 3. Conflict Resolution

When multiple detectors match overlapping spans:

1. Higher confidence score wins.
2. If confidence is equal, deterministic pattern wins over ML (higher structural certainty).
3. If source is equal, longer span wins.
4. Earlier start offset wins ties.

## 4. Multilingual Entity Detection & Language Coverage

AEGF evaluates multilingual entity detection across English, Spanish, French, German, and Arabic. The table below presents empirical benchmark findings using `nexuswho/gliner-onnx-small` combined with AEGF deterministic detectors:

| Language           | Test Text                                           | Deterministic Hits                | ML Hits (`PERSON`)                      | Combined Recall | Verified Status                         |
| ------------------ | --------------------------------------------------- | --------------------------------- | --------------------------------------- | --------------- | --------------------------------------- |
| **English (`en`)** | `"Please reach out to John Smith..."`               | `EMAIL`, `API_KEY`, `PHONE`, etc. | `"John Smith"`                          | **0.90**        | **Verified Production**                 |
| **Spanish (`es`)** | `"El cliente Carlos Rodríguez solicitó..."`         | `EMAIL`                           | `"Carlos Rodríguez"`                    | **1.00**        | **Verified Production**                 |
| **French (`fr`)**  | `"Veuillez contacter Jean Dupont..."`               | `EMAIL`                           | `"Jean Dupont"`                         | **1.00**        | **Verified Production**                 |
| **German (`de`)**  | `"Bitte senden Sie die Rechnung an Hans Müller..."` | `EMAIL`                           | Missed (`Hans Müller` < threshold)      | **0.50**        | **Experimental** (Deterministic active) |
| **Arabic (`ar`)**  | `"يرجى مراسلة أحمد محمود على البريد..."`            | `EMAIL`                           | Missed (Script tokenization limitation) | **0.50**        | **Experimental** (Deterministic active) |

### Key Architectural Takeaways:

1. **Romance & Germanic Languages:** English, Spanish, and French show high entity recall on Latin-script names. German compound nouns and capitalization require lower classification thresholds or `gliner_multi` backbones.
2. **Non-Latin Scripts (e.g. Arabic):** The compact English-centric `gliner-small` backbone uses a WordPiece/BPE tokenizer primarily vocabulary-indexed for Latin characters. For full non-Latin script coverage, deployments should configure the larger `urchade/gliner_multi` multilingual backbone.
3. **Safety Fallback:** While ML entity extraction varies by script, deterministic pattern detectors (email, international phone, API tokens, JWTs, credit cards) operate uniformly across all languages.
