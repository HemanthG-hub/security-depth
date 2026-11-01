from lib.ast_analysis import analyze_python_ast
import httpx

from lib.github_scan import (
    GitHubScanError,
    _default_branch_from_page,
    _extract_source_files,
    _translate_github_http_error,
    parse_repository_url,
)


def test_python_ast_ignores_vulnerable_text_in_comments():
    findings, parsed = analyze_python_ast(
        "# subprocess.run(command, shell=True)\n# password = 'example-secret'\nprint('ok')\n",
        set(),
    )

    assert parsed is True
    assert findings == []


def test_python_ast_reports_executable_shell_and_interpolated_sql():
    code = "subprocess.run('grep ' + value, shell=True)\ncursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"

    findings, parsed = analyze_python_ast(code, set())

    assert parsed is True
    assert {(finding.title, finding.line) for finding in findings} == {
        ("Command injection surface", 1),
        ("SQL injection", 2),
    }


def test_python_ast_falls_back_when_source_is_invalid():
    findings, parsed = analyze_python_ast("def broken(:\n", set())

    assert parsed is False
    assert findings == []


def test_python_ast_handles_annotated_secrets_and_user_paths():
    code = "password: str = 'secret-value'\nopen('/srv/files/' + user_id)\napp.run(debug=True)\n"

    findings, parsed = analyze_python_ast(code, set())

    assert parsed is True
    assert {(finding.title, finding.line) for finding in findings} == {
        ("Hardcoded secret", 1),
        ("Path traversal", 2),
        ("Insecure authentication configuration", 3),
    }


def test_repository_url_accepts_only_github_repository_roots():
    assert parse_repository_url("https://github.com/example/project.git") == (
        "example",
        "project",
        "https://github.com/example/project",
    )

    for url in (
        "http://github.com/example/project",
        "https://github.com.evil.example/example/project",
        "https://github.com/example/project/tree/main",
    ):
        try:
            parse_repository_url(url)
        except GitHubScanError as error:
            assert error.status_code == 422
        else:
            raise AssertionError(f"Expected invalid repository URL: {url}")


def test_github_rate_limit_error_suggests_token_configuration():
    response = httpx.Response(
        403,
        json={"message": "API rate limit exceeded for this address."},
        request=httpx.Request("GET", "https://api.github.com/repos/example/project"),
    )
    error = httpx.HTTPStatusError("rate limited", request=response.request, response=response)

    translated = _translate_github_http_error(error)

    assert translated.status_code == 429
    assert "GITHUB_TOKEN" in str(translated)


def test_github_archive_fallback_parses_branch_and_extracts_limited_sources():
    import io
    import json
    import zipfile

    embedded_data = json.dumps({"payload": {"repository": {"defaultBranch": "main"}}})
    page = f'<script data-target="react-app.embeddedData">{embedded_data}</script>'
    archive_stream = io.BytesIO()
    with zipfile.ZipFile(archive_stream, "w") as source_zip:
        source_zip.writestr("project-main/src/app.py", "password = 'sample-secret'\n")
        source_zip.writestr("project-main/node_modules/ignored.py", "eval(payload)\n")
        source_zip.writestr("project-main/README.md", "not source")

    assert _default_branch_from_page(page) == "main"
    assert _extract_source_files(archive_stream.getvalue()) == {
        "src/app.py": "password = 'sample-secret'\n"
    }