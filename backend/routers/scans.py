import asyncio
import logging
import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pymongo.errors import PyMongoError

from lib.ast_analysis import analyze_python_ast
from lib.db import db
from lib.github_scan import GitHubScanError, fetch_repository_files
from lib.live_ai import LiveAIError, explain_scan
from models.scans import (
    GitHubScanCreate,
    ScanCreate,
    ScanResult,
    ScanSummary,
    ScoreBreakdown,
    Vulnerability,
)


router = APIRouter(prefix="/scans", tags=["scans"])
logger = logging.getLogger(__name__)
_memory_scans: dict[str, ScanResult] = {}
_memory_scan_limit = 100


async def store_scan(result: ScanResult) -> None:
    try:
        await asyncio.wait_for(db.scans.insert_one(result.model_dump()), timeout=2.0)
    except (PyMongoError, asyncio.TimeoutError) as error:
        result.storage_mode = "EPHEMERAL"
        _memory_scans[result.id] = result
        while len(_memory_scans) > _memory_scan_limit:
            _memory_scans.pop(next(iter(_memory_scans)))
        logger.warning("MongoDB unavailable; keeping scan %s in process memory: %s", result.id, error)


LANGUAGE_ALIASES = {
    "python": "Python",
    "py": "Python",
    "javascript": "JavaScript",
    "js": "JavaScript",
    "typescript": "TypeScript",
    "ts": "TypeScript",
    "sql": "SQL",
    "c": "C",
    "cpp": "C++",
    "c++": "C++",
    "arduino": "Arduino / ESP32",
    "esp32": "Arduino / ESP32",
    "c/c++": "C++",
}


def detect_language(code: str, requested: str, file_name: str | None) -> str:
    requested_key = requested.strip().lower()
    if requested_key not in {"", "auto"}:
        return LANGUAGE_ALIASES.get(requested_key, requested.strip())
    suffix = (file_name or "").lower().rsplit(".", 1)[-1]
    if suffix in {"py"}:
        return "Python"
    if suffix in {"js", "jsx"}:
        return "JavaScript"
    if suffix in {"ts", "tsx"}:
        return "TypeScript"
    if suffix in {"sql"}:
        return "SQL"
    if suffix in {"ino", "h", "hpp", "cpp", "cc", "c"}:
        return "Arduino / ESP32" if any(token in code for token in ("WiFi", "Arduino", "ESP32", "MQTT")) else "C++"
    if re.search(r"(^|\n)\s*(import |from |def |class )", code):
        return "Python"
    if re.search(r"(const |let |function |=>|require\()", code):
        return "JavaScript"
    if re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", code, re.IGNORECASE):
        return "SQL"
    return "C++" if re.search(r"(#include|std::|void setup\s*\()", code) else "Plain Text"


def line_for(lines: list[str], match: re.Match[str]) -> tuple[int, str]:
    line_number = match.string[: match.start()].count("\n") + 1
    return line_number, lines[line_number - 1].strip()[:240]


def make_vulnerability(
    lines: list[str],
    pattern: str,
    title: str,
    severity: str,
    cwe: str,
    owasp: str,
    explanation: str,
    recommendation: str,
    secure_fix: str,
    exploitability: str,
    seen: set[tuple[str, int]],
    source: str = "DETERMINISTIC",
) -> list[Vulnerability]:
    findings: list[Vulnerability] = []
    code = "\n".join(lines)
    for match in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
        line, evidence = line_for(lines, match)
        fingerprint = (title, line)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        findings.append(
            Vulnerability(
                id=str(uuid.uuid4()),
                title=title,
                severity=severity,  # type: ignore[arg-type]
                cwe=cwe,
                owasp_category=owasp,
                line=line,
                evidence=evidence,
                explanation=explanation,
                recommendation=recommendation,
                secure_fix=secure_fix,
                exploitability=exploitability,
                source=source,  # type: ignore[arg-type]
            )
        )
    return findings


def analyze_code(code: str, language: str, file_name: str | None) -> ScanResult:
    detected_language = detect_language(code, language, file_name)
    lines = code.splitlines() or [""]
    seen: set[tuple[str, int]] = set()
    findings: list[Vulnerability] = []

    rules = [
        (r"(?:password|passwd|api[_-]?key|secret|token|wifi_password|wifi_ssid)\s*[=:]\s*['\"][^'\"]{3,}", "Hardcoded secret", "HIGH", "CWE-798", "A07: Identification and Authentication Failures", "Credentials are embedded in source and can be extracted from repositories, firmware, or build artifacts.", "Move the value to a secret manager or injected environment variable and rotate the exposed credential.", "password = os.environ.get('APP_PASSWORD')", "HIGH"),
        (r"(?:os\.system|subprocess\.(?:run|call|Popen)|child_process\.exec|system)\s*\(", "Command injection surface", "CRITICAL", "CWE-78", "A03: Injection", "A shell or system command is reachable from code that may accept untrusted input, allowing arbitrary command execution.", "Use an argument array with shell execution disabled and validate each argument against an allow-list.", "subprocess.run([\"tool\", validated_arg], shell=False, check=True)", "HIGH"),
        (r"(?:execute|executemany|query)\s*\([^\n]*(?:\+|f['\"]|format\(|%s)", "SQL injection", "CRITICAL", "CWE-89", "A03: Injection", "SQL is assembled with string interpolation or concatenation, so attacker-controlled values can alter the query.", "Use parameterized queries and pass untrusted values separately from the SQL statement.", "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))", "HIGH"),
        (r"(?:innerHTML|dangerouslySetInnerHTML|document\.write)\s*=|res\.send\(\s*(?:req\.|request\.)", "Cross-site scripting", "HIGH", "CWE-79", "A03: Injection", "Untrusted data is written into an HTML sink without an escaping or sanitization boundary.", "Render text through the framework's safe primitives or sanitize HTML with a strict allow-list.", "element.textContent = untrusted_value", "HIGH"),
        (r"(?:md5|sha1|des|rc4|createHash\(['\"](?:md5|sha1)['\"])", "Weak cryptography", "MEDIUM", "CWE-327", "A02: Cryptographic Failures", "A deprecated or collision-prone primitive is used for security-sensitive data.", "Use a modern authenticated construction such as Argon2id for passwords or AES-GCM for encryption.", "hashlib.sha256(value.encode()).hexdigest()", "MEDIUM"),
        (r"(?:pickle\.loads?|yaml\.load\s*\(|eval\s*\(|new Function\s*\()", "Unsafe deserialization", "CRITICAL", "CWE-502", "A08: Software and Data Integrity Failures", "The application may execute attacker-controlled serialized data as code or instantiate unsafe objects.", "Use a safe, schema-validated format such as JSON and reject unexpected types before processing.", "payload = ScanPayload.model_validate_json(raw_json)", "HIGH"),
        (r"(?:open|readFile|readFileSync)\s*\([^\n]*(?:request|req\.|user|params|query)", "Path traversal", "HIGH", "CWE-22", "A01: Broken Access Control", "A user-controlled path reaches file access without a canonicalization and containment check.", "Resolve the path under a fixed base directory and reject traversal outside that directory.", "safe_path = (BASE_DIR / filename).resolve(); safe_path.relative_to(BASE_DIR)", "HIGH"),
        (r"(?:requests\.(?:get|post)|axios\.(?:get|post)|fetch)\s*\([^\n]*(?:url|req\.|request|user)", "Server-side request forgery", "HIGH", "CWE-918", "A10: Server-Side Request Forgery", "A remote destination is influenced by user input and could reach internal services or metadata endpoints.", "Allow-list hosts, block private IP ranges after DNS resolution, and use an outbound proxy with timeouts.", "assert urlparse(target).hostname in ALLOWED_HOSTS", "MEDIUM"),
        (r"(?:verify_signature\s*=\s*False|jwt\.decode\([^\n]*verify_signature|debug\s*=\s*True)", "Insecure authentication configuration", "HIGH", "CWE-287", "A07: Identification and Authentication Failures", "Authentication checks are disabled or development settings may expose privileged behavior in production.", "Enforce signature verification, disable debug mode, and fail closed when configuration is missing.", "claims = jwt.decode(token, key, algorithms=[\"RS256\], options={\"verify_signature\": True})", "HIGH"),
        (r"(?:request\.(?:args|form|json)|req\.(?:query|body|params))\s*\[", "Missing input validation", "MEDIUM", "CWE-20", "A04: Insecure Design", "External input is read directly without an obvious type, length, or allow-list validation boundary.", "Validate request data against a strict schema before business logic or file/database access.", "payload = RequestModel.model_validate(request.json)", "MEDIUM"),
        (r"(?:chmod\s*\([^\n]*0o?777|permissions?\s*[=:]\s*['\"](?:777|world-writable))", "Excessive file permissions", "HIGH", "CWE-732", "A01: Broken Access Control", "World-writable permissions can let another process alter executable or sensitive files.", "Create files with least-privilege permissions and set an explicit owner and mode.", "os.chmod(path, 0o600)", "MEDIUM"),
        (r"(?:pip install|npm install)\s+[^\n]*(?:@latest|\*|git\+)", "Insecure dependency pinning", "MEDIUM", "CWE-829", "A06: Vulnerable and Outdated Components", "A floating or remote dependency makes builds non-reproducible and increases supply-chain risk.", "Pin reviewed versions, verify lockfiles, and run dependency vulnerability checks in CI.", "pip install package==1.2.3", "MEDIUM"),
        (r"(?:mqtt://|WiFiClient\s+|client\.setServer\([^\n]*1883)", "Unencrypted IoT communication", "HIGH", "CWE-319", "A02: Cryptographic Failures", "Device traffic may travel without transport encryption, exposing credentials and commands on the network.", "Use TLS MQTT on port 8883 with certificate validation and device-specific credentials.", "mqtt.setServer(broker, 8883); mqtt.setCallback(callback)", "HIGH"),
        (r"(?:ArduinoOTA|OTA|Update\.begin)\s*\(|(?:WIFI|SSID|PASSWORD)\s*[=:]\s*['\"]", "Insecure firmware configuration", "HIGH", "CWE-798", "IoT / Firmware Security", "Firmware contains hardcoded connectivity material or update logic without a visible trust boundary.", "Provision per-device secrets, sign firmware, and require authenticated, rollback-safe OTA updates.", "const char* wifi_ssid = get_provisioned_secret(\"wifi_ssid\");", "HIGH"),
    ]
    if detected_language == "Python":
        ast_findings, parsed = analyze_python_ast(code, seen)
        findings.extend(ast_findings)
        if not parsed:
            for rule in rules:
                findings.extend(make_vulnerability(lines, *rule, seen))
    else:
        for rule in rules:
            findings.extend(make_vulnerability(lines, *rule, seen))

    severity_weights = {"CRITICAL": 24, "HIGH": 14, "MEDIUM": 7, "LOW": 3}
    severity_impact = sum(severity_weights[f.severity] for f in findings)
    sensitive_data = min(12, sum(5 for f in findings if f.title in {"Hardcoded secret", "Insecure firmware configuration"}))
    titles = [f.title for f in findings]
    repeated = max(0, len(titles) - len(set(titles))) * 4
    complexity = min(8, max(0, len(lines) // 80))
    dependency_risk = 6 if any(f.title == "Insecure dependency pinning" for f in findings) else 0
    total = min(100, severity_impact + sensitive_data + repeated + complexity + dependency_risk)
    risk = "CRITICAL" if total >= 80 else "HIGH" if total >= 55 else "MEDIUM" if total >= 25 else "LOW"
    if not findings:
        summary = "No deterministic security rules matched this source. Keep dependency checks and review gates enabled before shipping."
        debt = "Low immediate security debt. Continue validating inputs, secrets, and third-party dependencies in CI."
    else:
        top = ", ".join(dict.fromkeys(f.title for f in findings[:3]))
        summary = f"{len(findings)} deterministic finding(s) require review. Highest-priority signals: {top}."
        debt = f"Security debt is driven by {len(findings)} finding(s), including {sum(1 for f in findings if f.severity in {'CRITICAL', 'HIGH'})} high-impact issue(s)."
    ai_explanation = (
        f"[Mock AI Mode] The deterministic pass identified {len(findings)} finding(s) in {detected_language}. "
        "The assistant explanation is intentionally grounded in rule evidence; no source code was executed and no live model key was used."
    )
    return ScanResult(
        id=str(uuid.uuid4()),
        language=detected_language,
        file_name=file_name,
        source_code=code,
        security_score=total,
        risk_level=risk,  # type: ignore[arg-type]
        vulnerabilities=findings,
        summary=summary,
        security_debt=debt,
        breakdown=ScoreBreakdown(
            severity_impact=severity_impact,
            sensitive_data_exposure=sensitive_data,
            repeated_patterns=repeated,
            complexity=complexity,
            dependency_risk=dependency_risk,
            total=total,
        ),
        ai_explanation=ai_explanation,
        line_count=len(lines),
        created_at=datetime.now(timezone.utc),
    )


@router.post("", response_model=ScanResult)
async def create_scan(payload: ScanCreate):
    result = analyze_code(payload.code, payload.language, payload.file_name)
    if payload.ai_mode == "LIVE_AI":
        try:
            result.ai_explanation = await explain_scan(
                payload.code, result.language, result.vulnerabilities
            )
        except LiveAIError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        result.ai_mode = "LIVE_AI"
    await store_scan(result)
    return result


@router.post("/github", response_model=ScanResult)
async def create_github_scan(payload: GitHubScanCreate):
    try:
        repository_name, repository_url, files = await fetch_repository_files(
            payload.repository_url
        )
    except GitHubScanError as error:
        raise HTTPException(status_code=error.status_code, detail=str(error)) from error

    findings: list[Vulnerability] = []
    source_parts: list[str] = []
    total_lines = 0
    for path, code in files.items():
        source_parts.append(f"# --- {path} ---\n{code}")
        header_lines = 1
        for finding in analyze_code(code, "auto", path).vulnerabilities:
            finding.line += total_lines + header_lines
            finding.file_name = path
            findings.append(finding)
        total_lines += header_lines + len(code.splitlines() or [""]) + 1

    source_code = "\n".join(source_parts)
    severity_weights = {"CRITICAL": 24, "HIGH": 14, "MEDIUM": 7, "LOW": 3}
    severity_impact = sum(severity_weights[finding.severity] for finding in findings)
    sensitive_data = min(
        12,
        sum(5 for finding in findings if finding.title in {"Hardcoded secret", "Insecure firmware configuration"}),
    )
    titles = [finding.title for finding in findings]
    repeated = max(0, len(titles) - len(set(titles))) * 4
    complexity = min(8, max(0, total_lines // 80))
    dependency_risk = 6 if any(finding.title == "Insecure dependency pinning" for finding in findings) else 0
    total = min(100, severity_impact + sensitive_data + repeated + complexity + dependency_risk)
    risk = "CRITICAL" if total >= 80 else "HIGH" if total >= 55 else "MEDIUM" if total >= 25 else "LOW"
    summary = (
        f"{len(findings)} deterministic finding(s) across {len(files)} source file(s)."
        if findings
        else f"No deterministic rules matched {len(files)} source file(s). Review dependencies and keep CI security checks enabled."
    )
    debt = (
        f"Security debt is driven by {len(findings)} finding(s), including "
        f"{sum(finding.severity in {'CRITICAL', 'HIGH'} for finding in findings)} high-impact issue(s)."
        if findings
        else "Low immediate security debt. Continue validating inputs, secrets, and dependencies in CI."
    )
    result = ScanResult(
        id=str(uuid.uuid4()),
        language="GitHub repository",
        file_name=repository_name,
        source_code=source_code,
        security_score=total,
        risk_level=risk,  # type: ignore[arg-type]
        vulnerabilities=findings,
        summary=summary,
        security_debt=debt,
        breakdown=ScoreBreakdown(
            severity_impact=severity_impact,
            sensitive_data_exposure=sensitive_data,
            repeated_patterns=repeated,
            complexity=complexity,
            dependency_risk=dependency_risk,
            total=total,
        ),
        ai_explanation=(
            f"[Mock AI Mode] Deterministic analysis scanned {len(files)} files from {repository_name}. "
            "Source was fetched as text only and was never executed."
        ),
        line_count=len(source_code.splitlines()),
        created_at=datetime.now(timezone.utc),
        repository_url=repository_url,
        files_scanned=len(files),
    )
    if payload.ai_mode == "LIVE_AI":
        try:
            result.ai_explanation = await explain_scan(
                source_code, result.language, result.vulnerabilities
            )
        except LiveAIError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        result.ai_mode = "LIVE_AI"

    await store_scan(result)
    return result


@router.get("", response_model=list[ScanSummary])
async def list_scans():
    try:
        documents = await asyncio.wait_for(
            db.scans.find({}, {"source_code": 0, "vulnerabilities": 0})
            .sort("created_at", -1)
            .to_list(100),
            timeout=2.0,
        )
    except (PyMongoError, asyncio.TimeoutError):
        documents = []
    summaries = [ScanSummary(**document) for document in documents]
    summaries.extend(
        ScanSummary(
            id=scan.id,
            language=scan.language,
            file_name=scan.file_name,
            security_score=scan.security_score,
            risk_level=scan.risk_level,
            vulnerability_count=len(scan.vulnerabilities),
            created_at=scan.created_at,
        )
        for scan in _memory_scans.values()
    )
    return sorted(summaries, key=lambda scan: scan.created_at, reverse=True)[:100]


@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    if scan_id in _memory_scans:
        return _memory_scans[scan_id]
    try:
        document = await asyncio.wait_for(db.scans.find_one({"id": scan_id}), timeout=2.0)
    except (PyMongoError, asyncio.TimeoutError):
        document = None
    if not document:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResult(**document)
