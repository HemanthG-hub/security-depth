import ast
import uuid

from models.scans import Vulnerability


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _contains_name(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id.lower() in names for child in ast.walk(node))


def analyze_python_ast(
    code: str, seen: set[tuple[str, int]]
) -> tuple[list[Vulnerability], bool]:
    lines = code.splitlines() or [""]
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return [], False

    findings: list[Vulnerability] = []

    def add(
        node: ast.AST,
        title: str,
        severity: str,
        cwe: str,
        owasp: str,
        explanation: str,
        recommendation: str,
        secure_fix: str,
        exploitability: str,
    ) -> None:
        line = getattr(node, "lineno", 1)
        fingerprint = (title, line)
        if fingerprint in seen:
            return
        seen.add(fingerprint)
        findings.append(
            Vulnerability(
                id=str(uuid.uuid4()),
                title=title,
                severity=severity,  # type: ignore[arg-type]
                cwe=cwe,
                owasp_category=owasp,
                line=line,
                evidence=lines[line - 1].strip()[:240],
                explanation=explanation,
                recommendation=recommendation,
                secure_fix=secure_fix,
                exploitability=exploitability,
                source="DETERMINISTIC",
            )
        )

    class SecurityVisitor(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign) -> None:
            names = {
                target.id.lower()
                for item in node.targets
                for target in ast.walk(item)
                if isinstance(target, ast.Name)
            }
            if names.intersection(
                {
                    "password", "passwd", "api_key", "apikey", "secret", "token",
                    "access_token", "client_secret", "wifi_password", "wifi_ssid",
                }
            ) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) >= 3:
                add(
                    node,
                    "Hardcoded secret",
                    "HIGH",
                    "CWE-798",
                    "A07: Identification and Authentication Failures",
                    "A credential-like variable is assigned a string literal in source code.",
                    "Move the value to a secret manager or injected environment variable and rotate the exposed credential.",
                    "password = os.environ.get('APP_PASSWORD')",
                    "HIGH",
                )
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.lower() == "debug" and isinstance(node.value, ast.Constant) and node.value.value is True:
                    add(
                        node,
                        "Insecure authentication configuration",
                        "HIGH",
                        "CWE-489",
                        "A05: Security Misconfiguration",
                        "Debug mode is enabled by a literal true value.",
                        "Disable debug mode in production and fail closed when environment configuration is missing.",
                        "app.run(debug=os.environ.get('DEBUG') == '1')",
                        "HIGH",
                    )
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            target_name = (
                node.target.id.lower()
                if isinstance(node.target, ast.Name)
                else node.target.attr.lower()
                if isinstance(node.target, ast.Attribute)
                else ""
            )
            if target_name in {
                "password", "passwd", "api_key", "apikey", "secret", "token",
                "access_token", "client_secret", "wifi_password", "wifi_ssid",
            } and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) >= 3:
                add(
                    node,
                    "Hardcoded secret",
                    "HIGH",
                    "CWE-798",
                    "A07: Identification and Authentication Failures",
                    "A credential-like variable is assigned a string literal in source code.",
                    "Move the value to a secret manager or injected environment variable and rotate the exposed credential.",
                    "password = os.environ.get('APP_PASSWORD')",
                    "HIGH",
                )
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            name = _call_name(node.func).lower()
            if name in {"os.system", "system"} or (
                name in {"subprocess.run", "subprocess.call", "subprocess.popen"}
                and any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords)
            ):
                add(
                    node,
                    "Command injection surface",
                    "CRITICAL",
                    "CWE-78",
                    "A03: Injection",
                    "A shell command is executed directly or with shell parsing enabled.",
                    "Pass a validated argument list and keep shell execution disabled.",
                    "subprocess.run([\"tool\", validated_arg], shell=False, check=True)",
                    "HIGH",
                )
            if name.rsplit(".", 1)[-1] in {"execute", "executemany", "query"} and node.args:
                if isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                    add(
                        node,
                        "SQL injection",
                        "CRITICAL",
                        "CWE-89",
                        "A03: Injection",
                        "A SQL query is assembled with Python interpolation or concatenation.",
                        "Use parameterized queries and pass untrusted values separately from the SQL statement.",
                        "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
                        "HIGH",
                    )
            safe_yaml_loader = any(
                keyword.arg == "Loader"
                and _call_name(keyword.value).endswith(("SafeLoader", "CSafeLoader"))
                for keyword in node.keywords
            )
            if name in {"eval", "exec", "pickle.load", "pickle.loads"} or (name == "yaml.load" and not safe_yaml_loader):
                add(
                    node,
                    "Unsafe deserialization",
                    "CRITICAL",
                    "CWE-502",
                    "A08: Software and Data Integrity Failures",
                    "A dynamic evaluator or unsafe deserializer can execute or construct attacker-controlled data.",
                    "Use a safe, schema-validated format and reject unexpected input types.",
                    "payload = Model.model_validate_json(raw_json)",
                    "HIGH",
                )
            if name in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
                add(
                    node,
                    "Weak cryptography",
                    "MEDIUM",
                    "CWE-327",
                    "A02: Cryptographic Failures",
                    "A deprecated hash primitive is used.",
                    "Use a modern construction appropriate to the purpose, such as Argon2id for passwords.",
                    "hashlib.sha256(value.encode()).hexdigest()",
                    "MEDIUM",
                )
            request_method = name.rsplit(".", 1)[-1]
            url_argument = node.args[1] if request_method == "request" and len(node.args) > 1 else node.args[0] if node.args else None
            if name.startswith(("requests.", "httpx.")) and request_method in {"get", "post", "put", "delete", "request"} and url_argument is not None and not isinstance(url_argument, ast.Constant):
                add(
                    node,
                    "Server-side request forgery",
                    "HIGH",
                    "CWE-918",
                    "A10: Server-Side Request Forgery",
                    "A request destination is computed dynamically and may be influenced by untrusted input.",
                    "Allow-list hosts, block private IP ranges after DNS resolution, and use an outbound proxy with timeouts.",
                    "assert urlparse(target).hostname in ALLOWED_HOSTS",
                    "MEDIUM",
                )
            if name in {"open", "pathlib.path.open"} and node.args and _contains_name(
                node.args[0], {"request", "req", "user", "user_id", "user_input", "filename", "filepath"}
            ):
                add(
                    node,
                    "Path traversal",
                    "HIGH",
                    "CWE-22",
                    "A01: Broken Access Control",
                    "A user-controlled path reaches file access without a visible containment check.",
                    "Resolve the path beneath a fixed base directory and reject traversal outside it.",
                    "safe_path = (BASE_DIR / filename).resolve(); safe_path.relative_to(BASE_DIR)",
                    "HIGH",
                )
            if name == "os.chmod" and len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and node.args[1].value in {0o777, "777"}:
                add(
                    node,
                    "Excessive file permissions",
                    "HIGH",
                    "CWE-732",
                    "A01: Broken Access Control",
                    "A file is assigned world-writable permissions.",
                    "Create files with least-privilege permissions and set an explicit owner and mode.",
                    "os.chmod(path, 0o600)",
                    "MEDIUM",
                )
            verification_disabled = any(
                keyword.arg == "verify" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False
                for keyword in node.keywords
            ) or any(
                keyword.arg == "options"
                and isinstance(keyword.value, ast.Dict)
                and any(
                    isinstance(key, ast.Constant)
                    and key.value == "verify_signature"
                    and isinstance(value, ast.Constant)
                    and value.value is False
                    for key, value in zip(keyword.value.keys, keyword.value.values)
                )
                for keyword in node.keywords
            )
            debug_enabled = any(
                keyword.arg == "debug" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                for keyword in node.keywords
            )
            if (name == "jwt.decode" and verification_disabled) or debug_enabled:
                add(
                    node,
                    "Insecure authentication configuration",
                    "HIGH",
                    "CWE-287",
                    "A07: Identification and Authentication Failures",
                    "JWT signature verification is explicitly disabled.",
                    "Enforce signature verification and fail closed when key configuration is missing.",
                    "claims = jwt.decode(token, key, algorithms=[\"RS256\"])",
                    "HIGH",
                )
            self.generic_visit(node)

        def visit_Subscript(self, node: ast.Subscript) -> None:
            if isinstance(node.value, ast.Attribute) and node.value.attr in {"args", "form", "json"} and isinstance(node.value.value, ast.Name) and node.value.value.id in {"request", "req"}:
                add(
                    node,
                    "Missing input validation",
                    "MEDIUM",
                    "CWE-20",
                    "A04: Insecure Design",
                    "Request data is accessed directly without a visible schema or allow-list boundary.",
                    "Validate request data against a strict schema before business logic or file/database access.",
                    "payload = RequestModel.model_validate(request.json)",
                    "MEDIUM",
                )
            self.generic_visit(node)

    SecurityVisitor().visit(tree)
    return findings, True