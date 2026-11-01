# DEBT//SCORER living spec

## What it does
DEBT//SCORER is a cybersecurity command center for scanning pasted source, uploaded files, and bounded GitHub repositories. It detects Python, JavaScript/TypeScript, SQL, C/C++, and Arduino/ESP32 patterns without executing untrusted code, then stores transparent security-debt results in MongoDB.

## Data model
- `ScanResult`: string id, detected language, optional filename and repository URL, scanned-file count, persistence mode, source code, 0–100 security score, risk level, vulnerabilities, summary, security debt, score breakdown, AI mode/explanation, line count, and UTC created timestamp
- `Vulnerability`: title, severity, CWE, OWASP-style category, line, optional source filename, evidence, explanation, recommendation, secure replacement, exploitability, and deterministic/AI source label
- `ScanSummary`: history-safe projection with id, language, filename, score, risk, finding count, and timestamp

## Key flows
1. Landing page → Code scanner → paste/load preset/upload file or enter a GitHub repository URL → POST `/api/scans` or `/api/scans/github` → dashboard
2. Dashboard shows gauge, severity counters, line-highlighted evidence, per-file repository paths, transparent breakdown, and AI context
3. Finding details shows evidence, category, explanation, recommendation, and copyable secure replacement
4. Scan history searches stored scans and links to dashboard/report
5. Security report is a print-optimized page using the browser print dialog to export PDF

## Analysis engine
Python uses AST rules for executable syntax and falls back to regex rules for invalid Python; other supported languages use deterministic regex rules. Rules cover hardcoded secrets, command/SQL injection, XSS, weak crypto, unsafe deserialization, path traversal, SSRF, insecure auth, missing validation, excessive permissions, dependency pinning, and IoT communication/firmware configuration. The score is the capped sum of severity impact, sensitive-data exposure, repeated patterns, complexity, and dependency risk. `LIVE_AI` is opt-in and only generates contextual explanation; it never creates findings or changes the deterministic score. GitHub scanning accepts canonical HTTPS repository URLs, uses the REST API with a codeload ZIP fallback for rate limits, and caps archives at 25 MB, source files at 40, and source bytes at 120 KB. If MongoDB is unavailable, up to 100 scan results are held in process memory and marked ephemeral.

## Integrations
Set `LLM_API_KEY` on the backend to enable live AI. `LLM_BASE_URL` defaults to `https://api.openai.com/v1`; `LLM_MODEL` defaults to `gpt-4o-mini`. Live mode sends source code to that provider. Set `GITHUB_TOKEN` on the backend to enable access to private repositories and higher GitHub API limits; public repositories can be scanned without it. Never place either credential in frontend configuration.

## Auth and roles
No authentication or role gates in this MVP. Scan history is shared demo data in the pod database.
