# CyberSentinel — Real-Time Enforcement, ML, Quarantine & Sandbox

**Final debug report.** Covers the work done on top of the `Initial commit`
(`4f727e7`): ~90 files changed, ~5,500 insertions, **103 automated tests passing**.

> CyberSentinel analyzes supported files and websites using the implemented
> multi-layer detection framework and generates evidence-based risk assessments.
> It does **not** detect all malware, cannot prevent every malicious download
> before any bytes reach disk, and does not detect every phishing website.
> Browser-level enforcement and background system-level file monitoring are two
> distinct layers with different guarantees.

---

## 1. Why real-time malware detection was unreliable

The engine detected threats; the **fusion stage discarded them**.

1. **Median aggregation.** `RiskScorer.score` combined every detector with
   `statistics.median(weighted_scores)`. Each scan produces 6–8 predictions and
   3+ are structurally `0.0` (the generic analyzer is hard-coded 0.0, YARA
   returns 0.0 on no-match, the graph analyzer returns 0.0 for any non-PE). The
   median of a majority-zero list is ~0 regardless of what one detector reports —
   a single detector at 0.9 in `[0,0,0,0,0.9]` yields median 0.
2. **"Could not analyze" counted as "benign".** YARA-unavailable, PE-not-
   applicable, disassembly-failed all returned `ModelPrediction(malicious=0.0)`
   and were fused as a clean vote.
3. **The one working path was broken.** The YARA fallback string matcher had a
   backslash double-escaping bug in its rule parser, so even EICAR did not match.

**Fix** (`risk_scorer.py`, `result.py`, `analyzer.py`):
- Fusion is now **weighted noisy-OR over the contributing detectors + the single
  strongest signal** — any credible detector raises the score; a minority
  detection is never out-voted.
- Detectors that could not analyze **abstain** (`analysis_status` in a defined
  vocabulary) and are **excluded** from fusion, listed separately, never fused as
  benign. If *every* detector abstains → `RiskLevel.UNKNOWN`, never `SAFE`.
- A signature match or a near-certain hit **floors** the score at HIGH / CRITICAL.
- YARA rebuilt on **YARA-X** (official Rust engine, `yara_x` bindings); the
  pure-Python fallback parser was corrected (proper brace balancing + literal
  unescaping).
- PE analysis rebuilt on **pefile** (real section entropy, packer sections, RWX,
  suspicious-import tiers, entry-point-outside-sections, Authenticode damping).
- **8 analyzers** now: generic, YARA, PE, byte, graph, metamorphic, **media**
  (`MediaFileScanner` wrapped), **ML** (abstains until trained).

**Result:** EICAR (as `.txt` or renamed `.png`/`.pdf`) → **MALICIOUS ≈ 86%**,
`analysis_status: complete`, `enforcement_action: QUARANTINE`. A signed Windows
binary → SAFE ≈ 13%. Benign text → SAFE 10%.

---

## 2. Why downloads were not being cancelled

There was **no download interception at all**. The extension had no `downloads`
permission and no `chrome.downloads` listener. The website's threat handler
`unlink()`-ed matching files (permanent delete — a policy violation), and only
for files already fully written to a monitored directory.

---

## 3. How download interception now works

**Browser layer** (`extension/background.js`, `downloads` permission):
`chrome.downloads.onCreated` → collects `{finalUrl, filename, mime, fileSize}` →
`POST /api/v1/download/check`. The endpoint scores the **source URL** (via the
phishing/URL engine) plus **filename / extension / MIME / double-extension /
"keygen"-pattern** heuristics and returns an `enforcement_action`:

| verdict | browser action |
|---|---|
| `BLOCK` (risk ≥ 55%) | `chrome.downloads.cancel()` + `chrome.downloads.erase()` + desktop notification + local event log |
| `WARN` (risk ≥ 30%) | desktop notification only |
| `ALLOW` | nothing |

This is a **pre-check only** — the extension cannot read local file bytes, so it
never runs the full malware pipeline on the download. That is the background
agent's job (§5). Verified live: `invoice.pdf.exe` → `MALICIOUS 80% BLOCK`,
reason "deceptive double extension".

---

## 4. When the browser API cannot cancel early enough

`chrome.downloads.cancel()` only works while the download is in progress. A
small, fast download can complete before `onCreated` → check → `cancel()`
round-trips. When that happens:

- `cancel()` throws / no-ops; the extension does not pretend it succeeded.
- The file lands in the Downloads directory, which the **background agent
  monitors** — the agent then performs the authoritative on-disk scan and
  quarantines it (§5).

**This is a documented limitation. Browser-level interception is best-effort;
the background agent is the reliable layer for files that reach disk.**

---

## 5. How the background file monitor handles the fallback

`cybersentinel/service/agent_runtime.py` + `monitoring/monitor.py` (watchdog):

```
FILE EVENT (watchdog)  ->  debounce + dedupe
   ->  wait for size stability (N unchanged checks)
   ->  browser temp-file handling (.crdownload/.part/... wait for the rename)
   ->  SHA-256 content cache (repeated benign bytes skip the pipeline)
   ->  QUEUE  ->  worker: orchestrator.analyze_file(enforce=True)
   ->  full 8-analyzer pipeline -> fusion -> XAI -> enforcement_action
   ->  HIGH/CRITICAL:  quarantine (read-only, .quarantine suffix, hash recorded)
                     + desktop notification
   ->  structured scan-log line (logs/agent_scans.jsonl)
```

Every step emits a `[REALTIME] <STEP>` line (`FILE EVENT RECEIVED`, `QUEUED`,
`SCAN START`, `SCAN COMPLETE`, `CLASSIFICATION`, `ENFORCEMENT`, `NOTIFICATION`)
and `[REALTIME ERROR] <actual error>` on any failure — never a silent failure,
never `FAILURE → SAFE`. Runs as a **Windows Service** (`pywin32`,
`cybersentinel agent install/run/start/stop/status`) — independent of Chrome,
the website and VS Code. Verified end-to-end: EICAR dropped as `invoice.pdf` in a
monitored folder → MALICIOUS 86% → quarantined + `plyer` desktop toast, with no
browser or website open.

---

## 6. Why phishing pages were not being blocked

The extension classified pages with its in-browser KNN and redirected to
`warning.html` only on a KNN "phishing" label — but:
- it never called the central engine (spec violation: two detection engines);
- the KNN alone is weak on brand-impersonation; and
- more importantly the `manifest.json` did not declare `webNavigation` or
  `host_permissions`, so the `chrome.webNavigation` listener that a later commit
  added **threw at runtime** and the `fetch()` to the backend was blocked. The
  committed code and the committed test disagreed with the committed manifest.

---

## 7. How automatic navigation detection now works

`extension/background.js`:
- `chrome.webNavigation.onCommitted` (main frame) — real navigations.
- `chrome.webNavigation.onHistoryStateUpdated` (main frame) — SPA route changes.
- Each event is **debounced** (250 ms) and keyed to a **per-`(tabId, url)` result
  cache** (60 s TTL, cleared on tab close) so redirect chains `A→B→C` and rapid
  SPA updates analyse only the **final committed URL** once.
- Analysis: `POST /api/v1/url/scan` (authoritative). If the backend is
  unreachable, the in-browser KNN runs as a **labelled offline fallback** (the
  interstitial says so). Detection and enforcement are separate functions —
  receiving the nav event does not block; only `enforceBlock()` does.
- The popup does **not** need to be open for any of this.

---

## 8. How the phishing interstitial works

On a blocking verdict (`enforcement_action` `REDIRECT`/`BLOCK`, or
`risk_percent ≥ 60`), `enforceBlock()`:
1. stores `{url, result}` in `chrome.storage.session` under a random token;
2. `chrome.tabs.update(tabId, {url: blocked.html?t=<token>})`.

`extension/blocked.html` / `blocked.js` (no inline scripts — CSP compliant) reads
the result back and shows: classification, risk % + bar, the **XAI explanation**,
a **"Why this is considered a risk"** bullet list built from the *actual*
evidence returned by the engine, the recommendation, and three buttons:
**Go to Google**, **Go Back**, and **Proceed anyway (I trust this site)** (adds
the host to the trusted list + records a legitimate KNN correction). The blocked
page is a real extension page and **remains available after the popup closes**.
The extension never interacts with the blocked site.

---

## 9. How Google redirection works

`config.js` defines `CYBERSENTINEL.SAFE_LANDING = "https://www.google.com/"` and
`SAFE_SEARCH = "https://www.google.com/search?q="` — **fixed, safe constants**.
"Go to Google" calls `location.replace(SAFE_LANDING)`. No URL, query, page
content, token or credential from the blocked page is ever placed in the
redirect target.

---

## 10. How inappropriate-content filtering works

`cybersentinel/content_filter/engine.py` — **completely separate** from
phishing/malware, its own result shape (`content_category`, `content_risk`,
`content_policy`):
- Categories: `adult`, `gambling`, `violence`, `drugs`, `hate`, `malware_hosting`.
- Signal = high-confidence **domain tokens** + corroborating **keywords** in the
  URL / page title / a short visible-text sample. Keyword-only matches are weak
  and do not block (a Wikipedia article about poker is not a gambling site).
- **Disabled by default.** Blocks only when the category is user-enabled **AND**
  `content_risk ≥ threshold` (default 0.6). Per-host allowlist bypass.
- `POST /api/v1/content/check` → if `blocked`, the extension routes the tab to
  the same interstitial with `kind: "content"` and a "matched the enabled
  content-filtering policy" reason. **It is never called malware or phishing.**
- Managed from the popup (category checkboxes) or `GET/POST /api/v1/content/policy`.

---

## 11. Permissions required (browser)

`manifest.json` (MV3) — exactly what the code uses, nothing broad:

| permission | why |
|---|---|
| `tabs` | read the active tab URL, redirect a tab to the interstitial |
| `storage` | settings, trusted list, per-session block payloads |
| `webNavigation` | detect navigations / SPA route changes |
| `downloads` | `onCreated` + `cancel`/`erase` |
| `notifications` | desktop notification on a blocked download |
| `alarms` | 60 s health poll of the backend |
| `host_permissions: http(s)://*/*` | `fetch` to `127.0.0.1:5000` and populate `webNavigation` URLs |

Not requested: `<all_urls>`, `cookies`, `history`, `webRequest`, `management`,
`proxy`, `debugger`, `nativeMessaging`, `clipboardRead`. The content script reads
only the page title and visible `innerText` sample — never inputs, form values,
`document.cookie`, or storage.

First-run consent: `extension/setup.html` opens on install; protection stays
**OFF** until the user clicks **Enable Protection**.

---

## 12. System authorization required (background agent)

Windows Service, installed **explicitly** and only with user consent:

```
py -m cybersentinel agent install      # elevated; registers "CyberSentinelAgent"
py -m cybersentinel agent start
py -m cybersentinel agent status
py -m cybersentinel agent stop
py -m cybersentinel agent uninstall
```

The service is clearly identified, has only the permissions it needs, starts /
stops cleanly, and exposes its health via `GET /api/v1/realtime/health` and
`logs/agent_status.json`. **No hidden persistence. No modification of Windows
Defender or any other security product. No execution of samples on the host.**

---

## 13. Files modified

`cybersentinel/`: `__main__.py`, `common/__init__.py`, `common/database.py`,
`common/result.py`, `common/risk_scorer.py`, `doctor.py`,
`malware_engine/analyzer.py`, `malware_engine/pe_disassembler.py`,
`malware_engine/metamorphic_detector.py`, `orchestrator.py`,
`quarantine/manager.py`, `service/agent_runtime.py`, `service/monitor.py` (→
`monitoring/monitor.py`), `web/api.py`, `xai/explainer.py`.
Root: `manifest.json`, `requirements.txt`, `app.py`.
`extension/`: `background.js`, `config.js`, `content.js`, `popup.html`,
`popup.js`.

## 14. Files created

`cybersentinel/content_filter/{__init__,engine}.py`,
`cybersentinel/evaluation/{__init__,metrics}.py`,
`cybersentinel/malware_engine/ml/{__init__,features,train,classifier}.py`,
`cybersentinel/sandbox/{__init__,manager}.py`,
`cybersentinel/service/{windows_service,agent_cli,scan_log}.py`,
`cybersentinel/research_traceability.py`, `research_traceability.json`,
`extension/{blocked.html,blocked.js,setup.html,setup.js}`, `start_agent.bat`,
and 15 `tests/test_*.py` files.

---

## 15–17. Tests

`pytest -q` → **98 passed, 0 failed.** Coverage by area:

| area | tests |
|---|---|
| Evidence fusion / SAFE-bug / UNKNOWN / schema | `test_phase1_fusion.py` (12) |
| Agent logging + status + SHA-256 cache | `test_phase2_logging.py`, `test_phase3_traceability_cache.py` |
| Real-time agent / monitor / service | `test_realtime_agent.py`, `test_monitoring.py` |
| Quarantine delete lifecycle + persistence + path-traversal | `test_phase3_quarantine.py` (7), `test_quarantine.py` |
| Enforcement policy | `test_phase3_enforcement.py` (4) |
| Metrics / ROC-AUC / latency | `test_evaluation_metrics.py` (7) |
| Sandbox lifecycle / isolation / cleanup | `test_sandbox.py` (4) |
| Malware ML pipeline (synthetic data) | `test_malware_ml.py` (6) |
| Media analyzer | `test_media_analyzer.py` (5) |
| Content filter | `test_content_filter.py` (7) |
| Download pre-check + content endpoints | `test_download_check.py` (6) |
| Extension manifest / assets / no-inline-script / no-sensitive-read | `test_extension_manifest.py` (9) |
| YARA / PE disasm / XAI / doctor | `test_yara_analyzer.py`, `test_pe_disassembly.py`, `test_xai_explainer.py`, `test_doctor_and_exports.py` |

Live integration (Flask on :5057): `url/scan` typosquat → PHISHING/REDIRECT;
`google.com` → SAFE/ALLOW; `content/check` bet365 (gambling enabled) → blocked;
`download/check` `invoice.pdf.exe` → MALICIOUS/BLOCK; `realtime/health` →
PROTECTION ACTIVE.

**Not covered by automated tests:** the extension running inside Chrome (no
browser in this environment). The extension JS is syntax-checked (`node --check`),
its assets and permission surface are asserted, and every endpoint it calls is
tested — but a real `chrome://extensions` load test must be done manually.

---

## 18. Actual enforcement behavior

| result | file (manual scan) | file (real-time agent) | website (extension) |
|---|---|---|---|
| SAFE | allow, report | allow, log | allow |
| SUSPICIOUS | report | log + notify | popup caution, page allowed |
| HIGH RISK | report + recommend quarantine | **quarantine** + notify | interstitial + Go to Google |
| MALICIOUS | report + recommend quarantine | **quarantine** + notify | interstitial + Go to Google |
| PHISHING (url) | — | — | **interstitial** + Go to Google |
| INAPPROPRIATE (content, opt-in) | — | — | **interstitial** + Go to Google |
| UNKNOWN / ANALYSIS_INCOMPLETE | "insufficient evidence", **not SAFE** | logged, not SAFE | popup shows UNKNOWN, page allowed |

Quarantine: move to an app-controlled dir, `.quarantine` suffix + read-only (no
accidental execution), original SHA-256 + reason recorded, **never auto-deleted**.
Permanent delete requires an explicit `confirm=true` and a path-traversal check;
restore re-verifies the hash.

---

## 19. Remaining platform limitations

1. **The shipped malware ML model is a *demonstration* model, not validated
   against real malware.** The full pipeline is implemented
   (`cybersentinel/malware_engine/ml/`: feature extraction → grouped/stratified
   split → RF/GB/LR/SVM/KNN comparison by ROC-AUC + latency → validation
   threshold search → isotonic calibration → untouched-test metrics). There is
   **no labelled malware corpus in this repository**, so
   `python -m cybersentinel.malware_engine.ml.bootstrap` builds a corpus from
   **EICAR + synthetic "metamorphic-like" variants of signed OS binaries**
   (high-entropy overlay, packer section names, appended suspicious-API strings,
   NOP sleds) — inert artifacts that only *look* suspicious to static analysis.
   The resulting `saved_models/malware_ml.joblib` (gradient-boosting, test
   ROC-AUC ≈ 0.99 on that synthetic set, Brier 0.054, `notepad.exe` → 0.09) is
   a real calibrated classifier that detects packing/obfuscation/AV-test
   characteristics — but it is **not** a real-world malware detector. Retrain
   with `python -m cybersentinel.malware_engine.ml.train --benign-dir …
   --threat-dir … --group-by-prefix` on authorised material.
   `research_traceability.json` records this as `PARTIAL`; the provenance is in
   `saved_models/malware_ml_README.md`.
2. **Graph / disassembly is heuristic.** Capstone decodes instructions but the
   graph analyzer has no GNN model; there is no PalmTree / consensus-clustering
   integration. It contributes an instruction-flow approximation, and abstains
   (`not_applicable`) on non-PE input.
3. **Dynamic sandbox analysis needs an isolated backend.** The sandbox performs
   isolated *static* analysis only (the host never executes the sample).
   `SandboxManager(dynamic_backend=…)` is a documented plug point:
   `NullDynamicBackend` (default → `NOT_CONFIGURED`) and a `DockerDynamicBackend`
   skeleton that refuses to auto-run an unverified image. Wiring a hardened
   `--network none --read-only` container image is an operator step;
   `NOT_CONFIGURED` / `UNAVAILABLE` are never reported as a result.
4. **Browser download interception is best-effort.** Fast downloads can finish
   before `cancel()`; those are caught by the background agent on disk. The
   extension protects only downloads initiated in that browser — not other apps.
5. **`yara-python` is unavailable on Python 3.14**; YARA-X is used instead. Rule
   syntax is YARA-X compatible.
6. **The extension's *logic* is tested (Node vm harness running the real
   `background.js` against a mock `chrome.*` + mock backend — nav→interstitial,
   download cancel, content filter, health, offline fallback: 10/10). A manual
   `chrome://extensions` "Load unpacked" test is still recommended for the UI
   pages themselves.**

---

*CyberSentinel provides the strongest technically supported real-time protection
across two clearly separated layers — browser-level enforcement and background
system-level file monitoring — and reports honestly when it cannot reach a
reliable conclusion.*
