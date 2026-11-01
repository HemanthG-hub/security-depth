import asyncio
import base64
import json
import os
import re
import zipfile
from html.parser import HTMLParser
from io import BytesIO
from pathlib import PurePosixPath
from urllib.parse import quote, urlparse

import httpx


MAX_FILES = 40
MAX_FILE_BYTES = 120_000
MAX_TOTAL_BYTES = 120_000
MAX_ARCHIVE_BYTES = 25_000_000
SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".sql", ".c", ".cc", ".cpp",
    ".h", ".hpp", ".ino",
}
SKIP_PARTS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv"}


class GitHubScanError(Exception):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class _EmbeddedDataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._capturing = False
        self._parts: list[str] = []
        self.payloads: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script" and dict(attrs).get("data-target") == "react-app.embeddedData":
            self._capturing = True

    def handle_data(self, data: str) -> None:
        if self._capturing:
            self._parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._capturing:
            self.payloads.append("".join(self._parts))
            self._parts.clear()
            self._capturing = False


def _find_default_branch(value: object) -> str | None:
    if isinstance(value, dict):
        branch = value.get("defaultBranch")
        if isinstance(branch, str) and branch:
            return branch
        for nested in value.values():
            branch = _find_default_branch(nested)
            if branch:
                return branch
    elif isinstance(value, list):
        for nested in value:
            branch = _find_default_branch(nested)
            if branch:
                return branch
    return None


def _default_branch_from_page(page: str) -> str | None:
    parser = _EmbeddedDataParser()
    parser.feed(page)
    for payload in parser.payloads:
        try:
            branch = _find_default_branch(json.loads(payload))
        except json.JSONDecodeError:
            continue
        if branch:
            return branch
    return None


def _extract_source_files(archive: bytes) -> dict[str, str]:
    files: dict[str, str] = {}
    total_bytes = 0
    try:
        with zipfile.ZipFile(BytesIO(archive)) as source_zip:
            for entry in source_zip.infolist():
                path = PurePosixPath(entry.filename)
                parts = path.parts
                if (
                    entry.is_dir()
                    or path.is_absolute()
                    or ".." in parts
                    or len(parts) < 2
                    or any(part.lower() in SKIP_PARTS for part in parts)
                    or path.suffix.lower() not in SOURCE_EXTENSIONS
                    or entry.file_size < 1
                    or entry.file_size > MAX_FILE_BYTES
                    or total_bytes + entry.file_size > MAX_TOTAL_BYTES
                ):
                    continue
                try:
                    content = source_zip.read(entry).decode("utf-8")
                except (UnicodeDecodeError, RuntimeError, zipfile.BadZipFile):
                    continue
                relative_path = "/".join(parts[1:])
                files[relative_path] = content
                total_bytes += entry.file_size
                if len(files) >= MAX_FILES:
                    break
    except zipfile.BadZipFile as error:
        raise GitHubScanError("GitHub returned an invalid source archive.") from error
    return files


def _translate_github_http_error(error: httpx.HTTPStatusError) -> GitHubScanError:
    response = error.response
    try:
        message = response.json().get("message", "")
    except (ValueError, AttributeError):
        message = ""
    if response.status_code == 403 and "rate limit" in str(message).lower():
        return GitHubScanError(
            "GitHub's unauthenticated API rate limit is exhausted. Configure GITHUB_TOKEN in backend/.env and restart the backend.",
            429,
        )
    return GitHubScanError(
        "GitHub rejected the scan request. Check repository access and API limits."
    )


async def _fetch_repository_archive(
    owner: str,
    repository: str,
    canonical_url: str,
    headers: dict[str, str],
) -> tuple[str, str, dict[str, str]]:
    archive_headers = {"User-Agent": headers["User-Agent"]}
    if "Authorization" in headers:
        archive_headers["Authorization"] = headers["Authorization"]

    try:
        async with httpx.AsyncClient(
            timeout=30.0, follow_redirects=True, headers=archive_headers
        ) as client:
            page_response = await client.get(
                canonical_url, headers={"Accept": "text/html"}
            )
            if page_response.status_code == 404:
                raise GitHubScanError("Repository not found or not accessible.", 404)
            page_response.raise_for_status()
            default_branch = _default_branch_from_page(page_response.text)
            if not default_branch:
                raise GitHubScanError("Could not determine the repository's default branch.")

            archive_url = (
                f"https://codeload.github.com/{quote(owner)}/{quote(repository)}"
                f"/zip/refs/heads/{quote(default_branch, safe='/')}"
            )
            async with client.stream("GET", archive_url) as response:
                if response.status_code == 404:
                    raise GitHubScanError("The repository's default branch archive was not found.", 404)
                response.raise_for_status()
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > MAX_ARCHIVE_BYTES:
                    raise GitHubScanError("Repository archive exceeds the 25 MB fallback limit.", 413)
                archive = bytearray()
                async for chunk in response.aiter_bytes():
                    archive.extend(chunk)
                    if len(archive) > MAX_ARCHIVE_BYTES:
                        raise GitHubScanError("Repository archive exceeds the 25 MB fallback limit.", 413)

        files = _extract_source_files(bytes(archive))
    except GitHubScanError:
        raise
    except httpx.HTTPError as error:
        raise GitHubScanError("Could not download the GitHub source archive.") from error
    except ValueError as error:
        raise GitHubScanError("GitHub returned an invalid archive size.") from error

    if not files:
        raise GitHubScanError("No supported source files fit within the scan limits.", 422)
    return f"{owner}/{repository}", canonical_url, files


def parse_repository_url(repository_url: str) -> tuple[str, str, str]:
    parsed = urlparse(repository_url.strip())
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or len(parts) != 2
        or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts)
    ):
        raise GitHubScanError(
            "Enter a repository URL in the form https://github.com/owner/repository.",
            422,
        )
    owner, repository = parts
    repository = repository.removesuffix(".git")
    if not owner or not repository:
        raise GitHubScanError("The repository URL is invalid.", 422)
    return owner, repository, f"https://github.com/{owner}/{repository}"


async def fetch_repository_files(repository_url: str) -> tuple[str, str, dict[str, str]]:
    owner, repository, canonical_url = parse_repository_url(repository_url)
    token = os.environ.get("GITHUB_TOKEN")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "debt-scorer-security-scanner",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    base = f"https://api.github.com/repos/{quote(owner)}/{quote(repository)}"

    try:
        async with httpx.AsyncClient(timeout=20.0, headers=headers) as client:
            repository_response = await client.get(base)
            if repository_response.status_code == 404:
                raise GitHubScanError("Repository not found or not accessible with the configured token.", 404)
            repository_response.raise_for_status()
            default_branch = repository_response.json().get("default_branch")
            if not isinstance(default_branch, str) or not default_branch:
                raise GitHubScanError("GitHub did not return a default branch.")

            tree_url = f"{base}/git/trees/{quote(default_branch, safe='/')}"
            tree_response = await client.get(tree_url, params={"recursive": "1"})
            tree_response.raise_for_status()
            tree = tree_response.json()
            if tree.get("truncated"):
                raise GitHubScanError("This repository is too large to enumerate safely.", 413)

            candidates = []
            total_bytes = 0
            for entry in tree.get("tree", []):
                path = entry.get("path", "")
                parts = path.split("/")
                size = entry.get("size")
                if (
                    entry.get("type") != "blob"
                    or not isinstance(size, int)
                    or size < 1
                    or size > MAX_FILE_BYTES
                    or any(part.lower() in SKIP_PARTS for part in parts)
                    or os.path.splitext(path)[1].lower() not in SOURCE_EXTENSIONS
                    or total_bytes + size > MAX_TOTAL_BYTES
                ):
                    continue
                candidates.append((path, entry["sha"], size))
                total_bytes += size
                if len(candidates) >= MAX_FILES:
                    break

            if not candidates:
                raise GitHubScanError("No supported source files fit within the scan limits.", 422)

            semaphore = asyncio.Semaphore(5)

            async def fetch_blob(path: str, sha: str, expected_size: int) -> tuple[str, str]:
                async with semaphore:
                    response = await client.get(f"{base}/git/blobs/{quote(sha)}")
                    response.raise_for_status()
                    blob = response.json()
                    if blob.get("encoding") != "base64" or blob.get("size") != expected_size:
                        raise GitHubScanError("GitHub returned an unexpected source file format.")
                    try:
                        content = base64.b64decode(blob["content"], validate=False).decode("utf-8")
                    except (KeyError, ValueError, UnicodeDecodeError) as error:
                        raise GitHubScanError(f"Could not decode source file: {path}") from error
                    return path, content

            files = await asyncio.gather(
                *(fetch_blob(path, sha, size) for path, sha, size in candidates)
            )
    except GitHubScanError:
        raise
    except httpx.HTTPStatusError as error:
        translated = _translate_github_http_error(error)
        if translated.status_code == 429:
            return await _fetch_repository_archive(
                owner, repository, canonical_url, headers
            )
        raise translated from error
    except httpx.HTTPError as error:
        raise GitHubScanError("GitHub could not be reached. Try again later.") from error

    return f"{owner}/{repository}", canonical_url, dict(files)