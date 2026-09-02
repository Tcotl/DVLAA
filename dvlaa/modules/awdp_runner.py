"""Restricted patch-package runner used by the AWDP practice track.

The competition manual describes a Docker-based ``update.sh`` workflow.  The
range deliberately does not execute learner-provided shell scripts in the
application container.  Instead it creates a disposable per-session source
tree, accepts only the documented file operations (``cp``, ``mv`` and ``rm``),
and applies those operations through Python after validating every archive
member and path.  This preserves the hands-on package format without exposing
the host runtime to arbitrary shell execution.
"""

from __future__ import annotations

import io
import os
import re
import shlex
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from ..content.awdp_challenges import (
    fixed_patch_files,
    vulnerability_contract,
    vulnerable_source_files,
)
from .awdp_js_sandbox import verify_repaired_service_source


ALLOWED_COMMANDS = frozenset({"cp", "mv", "rm"})
MAX_ARCHIVE_MEMBERS = 80
MAX_UNPACKED_BYTES = 8 * 1024 * 1024
MAX_SCRIPT_BYTES = 64 * 1024


class PatchPackageError(ValueError):
    """A patch archive cannot be safely applied to the isolated source tree."""


def build_vulnerable_source_archive(challenge_id: int = 1) -> bytes:
    """Create the source attachment distributed from the AWDP challenge page."""
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for relative_name, content in vulnerable_source_files(challenge_id).items():
            encoded = content.encode("utf-8")
            info = tarfile.TarInfo(relative_name)
            info.size = len(encoded)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(encoded))
    return data.getvalue()


def build_fixed_patch_archive(challenge_id: int = 1) -> bytes:
    """Create the known-good repair package shown in the AWDP writeup."""
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for relative_name, content in fixed_patch_files(challenge_id).items():
            encoded = content.encode("utf-8")
            info = tarfile.TarInfo(relative_name)
            info.size = len(encoded)
            info.mode = 0o755 if relative_name == "update.sh" else 0o644
            archive.addfile(info, io.BytesIO(encoded))
    return data.getvalue()


def _write_baseline(project_root: Path, challenge_id: int = 1) -> None:
    project_root.mkdir(parents=True, exist_ok=True)
    for relative_name, content in vulnerable_source_files(challenge_id).items():
        destination = project_root / relative_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")


def _require_relative_path(name: str) -> Path:
    candidate = Path(name)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise PatchPackageError("压缩包包含越界路径")
    if not candidate.parts:
        raise PatchPackageError("压缩包路径为空")
    return candidate


def _safe_extract(archive_path: Path, destination: Path) -> None:
    try:
        archive = tarfile.open(archive_path, mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise PatchPackageError("补丁包必须是有效的 tar.gz 文件") from exc

    with archive:
        members = archive.getmembers()
        if not members:
            raise PatchPackageError("补丁包为空")
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise PatchPackageError("补丁包文件数量超过限制")

        total_size = 0
        for member in members:
            _require_relative_path(member.name)
            if member.issym() or member.islnk() or member.isdev():
                raise PatchPackageError("补丁包不允许软链接、硬链接或设备文件")
            if not (member.isfile() or member.isdir()):
                raise PatchPackageError("补丁包包含不支持的文件类型")
            total_size += max(0, member.size)
            if total_size > MAX_UNPACKED_BYTES:
                raise PatchPackageError("补丁包解压后超过隔离工作区限制")

        for member in members:
            member_path = destination / _require_relative_path(member.name)
            if member.isdir():
                member_path.mkdir(parents=True, exist_ok=True)
                continue
            member_path.parent.mkdir(parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is None:
                raise PatchPackageError("补丁包文件读取失败")
            with extracted, member_path.open("wb") as target:
                shutil.copyfileobj(extracted, target)
            os.chmod(member_path, 0o644)


def _under(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve()
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise PatchPackageError("补丁脚本访问了隔离工作区之外的路径") from exc
    return resolved


def _resolve_patch_path(
    raw_value: str,
    *,
    project_root: Path,
    bundle_root: Path,
    source: bool,
) -> Path:
    raw = str(raw_value).strip()
    if not raw:
        raise PatchPackageError("补丁脚本包含空路径")
    if raw.startswith("/app/lib/"):
        return _under(project_root, project_root / raw.removeprefix("/app/lib/"))
    if raw == "/app/lib":
        return _under(project_root, project_root)
    if raw.startswith("/"):
        raise PatchPackageError("补丁脚本只能访问 /app/lib 下的目标路径")

    relative = _require_relative_path(raw)
    bundle_candidate = _under(bundle_root, bundle_root / relative)
    project_candidate = _under(project_root, project_root / relative)
    if source and bundle_candidate.exists():
        return bundle_candidate
    return project_candidate


def _reject_shell_operators(line: str) -> None:
    if re.search(r"(?:;|&&|\|\||\||`|\$\(|>|<)", line):
        raise PatchPackageError("update.sh 只允许单条 cp、mv、rm 文件操作")


def _command_arguments(tokens: list[str], command: str) -> list[str]:
    values = list(tokens[1:])
    options: list[str] = []
    while values and values[0].startswith("-"):
        options.append(values.pop(0))
    if command in {"cp", "mv"}:
        if len(values) != 2:
            raise PatchPackageError(f"{command} 必须包含源文件和目标文件")
        if any(option not in {"-f", "-n"} for option in options):
            raise PatchPackageError(f"{command} 只支持 -f 或 -n 选项")
    elif command == "rm":
        if len(values) != 1:
            raise PatchPackageError("rm 必须只删除一个文件")
        if any(option != "-f" for option in options):
            raise PatchPackageError("rm 只支持 -f 选项，不能递归删除目录")
    return values


def _is_safe_shell_setup(tokens: list[str]) -> bool:
    """Accept common fail-fast shell setup lines without enabling commands.

    Competition patch scripts are commonly generated with ``set -euo
    pipefail`` (or an equivalent ``set -e`` line).  These declarations do not
    touch the filesystem, but rejecting them makes otherwise valid packages
    fail before their whitelisted ``cp``/``mv``/``rm`` operations are read.
    Keep the grammar deliberately narrow: only the standard errexit,
    nounset, and pipefail options are accepted, with no positional arguments.
    """
    if not tokens or tokens[0] != "set":
        return False
    args = tokens[1:]
    if not args:
        return False
    # ``set -e``, ``set -eu`` and ``set -euo pipefail`` are the forms most
    # often emitted by patch examples.  ``-o`` spellings are accepted too.
    flags = ""
    index = 0
    while index < len(args) and args[index].startswith("-") and args[index] != "-":
        option = args[index]
        if option == "--":
            return index == len(args) - 1
        if option.startswith("-o") and len(option) > 2:
            value = option[2:]
            if value not in {"errexit", "nounset", "pipefail"}:
                return False
            flags += {"errexit": "e", "nounset": "u", "pipefail": "o"}[value]
        else:
            for flag in option[1:]:
                if flag not in "euo":
                    return False
                flags += flag
        index += 1

    # In ``set -euo pipefail``, bash treats the final word as the argument to
    # the attached ``-o`` option.  The separated ``set -e -u -o pipefail``
    # form is handled below as well.
    if index < len(args):
        if len(args) != index + 1 or args[index] not in {"errexit", "nounset", "pipefail"}:
            return False
        if "o" not in flags:
            return False
        flags = flags.replace("o", "", 1) + "o"
        index += 1
    return index == len(args) and bool(flags) and set(flags).issubset({"e", "u", "o"})


def _apply_update_script(script: Path, project_root: Path, bundle_root: Path) -> list[str]:
    try:
        content = script.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise PatchPackageError("update.sh 必须为 UTF-8 文本") from exc
    if len(content.encode("utf-8")) > MAX_SCRIPT_BYTES:
        raise PatchPackageError("update.sh 超过大小限制")

    operations = 0
    logs: list[str] = []
    for number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("#!"):
            continue
        _reject_shell_operators(line)
        try:
            tokens = shlex.split(line, posix=True, comments=True)
        except ValueError as exc:
            raise PatchPackageError(f"update.sh 第 {number} 行语法无效") from exc
        if not tokens:
            continue
        command = tokens[0]
        if command == "set" and _is_safe_shell_setup(tokens):
            continue
        if command not in ALLOWED_COMMANDS:
            raise PatchPackageError(f"update.sh 第 {number} 行使用了未授权命令：{command}")
        args = _command_arguments(tokens, command)

        if command in {"cp", "mv"}:
            source = _resolve_patch_path(args[0], project_root=project_root, bundle_root=bundle_root, source=True)
            target = _resolve_patch_path(args[1], project_root=project_root, bundle_root=bundle_root, source=False)
            if not source.is_file():
                raise PatchPackageError(f"update.sh 第 {number} 行源文件不存在")
            if target == project_root or target.is_dir():
                raise PatchPackageError(f"update.sh 第 {number} 行目标必须为文件")
            target.parent.mkdir(parents=True, exist_ok=True)
            if command == "cp":
                shutil.copy2(source, target)
            else:
                shutil.move(str(source), str(target))
            logs.append(f"{command} {args[0]} -> {args[1]}")
        else:
            target = _resolve_patch_path(args[0], project_root=project_root, bundle_root=bundle_root, source=False)
            if target == project_root or target.is_dir():
                raise PatchPackageError(f"update.sh 第 {number} 行只能删除文件")
            target.unlink(missing_ok=True)
            logs.append(f"rm {args[0]}")
        operations += 1

    if not operations:
        raise PatchPackageError("update.sh 没有可执行的补丁文件操作")
    return logs


WEB_SERVICE_PATH = Path("src/web_service.js")


def _strip_js_comments(source: str) -> str:
    """Remove JavaScript comments before static service-boundary checks.

    Static inspection runs before the source is executed in the separate,
    bounded QuickJS worker. Ignoring comments makes it possible to document a
    previous defect without changing the structural verdict, while executable
    string literals and routes remain visible to the source contract.
    """
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"(^|\s)//[^\r\n]*", r"\1", source)


def _contains_source_marker(source: str, marker: str) -> bool:
    """Match source markers while tolerating harmless whitespace changes."""
    if marker in source:
        return True
    return re.sub(r"\s+", "", marker) in re.sub(r"\s+", "", source)


def _strip_js_strings(source: str) -> str:
    """Mask JavaScript string contents while retaining executable tokens.

    A marker placed in a quoted string must not satisfy a handler requirement
    such as ``return store.getAuthorized(...)``. Preserve quote delimiters and
    newlines so the result remains useful for structural regex checks while
    replacing literal contents with spaces. Runtime execution occurs only in
    the separate restricted QuickJS worker after this inspection.
    """
    characters = list(source)
    quote = ""
    escaped = False
    for index, character in enumerate(characters):
        if not quote:
            if character in {"'", '"', "`"}:
                quote = character
            continue
        if escaped:
            if character != "\n":
                characters[index] = " "
            escaped = False
            continue
        if character == "\\":
            characters[index] = " "
            escaped = True
            continue
        if character == quote:
            quote = ""
            continue
        if character != "\n":
            characters[index] = " "
    return "".join(characters)


def _find_matching_brace(source: str, opening_index: int) -> int | None:
    """Find a function body's closing brace without evaluating JavaScript."""
    depth = 0
    quote = ""
    escaped = False
    for index in range(opening_index, len(source)):
        character = source[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {"'", '"', "`"}:
            quote = character
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                return None
    return None


def _extract_js_function(source: str, name: str) -> tuple[str, str] | None:
    """Return one declared function's parameter list and executable body."""
    declaration = re.search(
        rf"\b(?:async\s+)?function\s+{re.escape(name)}\s*\((?P<params>[^)]*)\)\s*\{{",
        source,
        re.S,
    )
    if declaration is None:
        return None
    opening_index = declaration.end() - 1
    closing_index = _find_matching_brace(source, opening_index)
    if closing_index is None:
        return None
    return declaration.group("params"), source[opening_index + 1:closing_index]


def _has_patterns(source: str, requirements: tuple[tuple[str, re.Pattern[str]], ...]) -> list[str]:
    """List human-readable structural requirements missing from executable code."""
    return [label for label, pattern in requirements if pattern.search(source) is None]


def _has_balanced_js_delimiters(source: str) -> bool:
    """Reject malformed source before accepting it as a deployable service.

    This is not a JavaScript interpreter.  It catches the common cases that
    would make an uploaded handler non-loadable, while the per-handler
    contracts below verify the meaningful security and business operations.
    """
    code = _strip_js_strings(source)
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    for character in code:
        if character in "([{":
            stack.append(character)
        elif character in ")]}":
            if not stack or stack.pop() != pairs[character]:
                return False
    return not stack


# A marker check alone is not sufficient: a learner could rename a variable
# while retaining the same dangerous Web/API route.  These conservative forms
# cover the concrete service boundaries distributed with the labs.  They are
# intentionally static; submitted code is never evaluated in the Flask
# process.
_WEB_DANGEROUS_PATTERNS: dict[int, tuple[re.Pattern[str], ...]] = {
    1: (re.compile(r"\b(?:response|body|result|data)\s*\.\s*runtime_verifier\s*=", re.I),),
    2: (re.compile(r"\b(?:preview|response|result)\s*\.\s*migration_verifier\s*=", re.I),),
    3: (re.compile(r"\b(?:preview|response|result)\s*\.\s*kb_verification_code\s*=", re.I),),
    4: (re.compile(r"\bcode_runner\b", re.I),),
    5: (re.compile(r"\badmin_api_key\b", re.I),),
    6: (re.compile(r"\b(?:request|body)\s*\.\s*(?:body\s*\.\s*)?role\b", re.I),),
    7: (
        re.compile(r"\bfollowRedirects\s*:\s*true\b", re.I),
        re.compile(r"\bhttp\s*\.\s*get\s*\(\s*url\b", re.I),
    ),
    8: (re.compile(r"\bdb\s*\.\s*execute\s*\(", re.I),),
    9: (re.compile(r"\brepository\s*\.\s*find\s*\(", re.I),),
    10: (re.compile(r"\bexecutionStore\s*\.\s*stop\s*\(\s*String\s*\(", re.I),),
}


_RUNTIME_SECRET_REFERENCE = re.compile(
    r"(?:\b(?:runtimeFlag|runtime_flag|challengeFlag|challenge_flag|RUNTIME_FLAG)\b"
    r"|\b(?:runtime|services)\s*\.\s*(?:verifier|runtimeVerifier|flag)\b"
    r"|\bprocess\s*\.\s*env\b)",
    re.I,
)


_JS_RE_FLAGS = re.I | re.S

# A candidate needs a real handler body, not just the marker strings required
# by the public repair contract.  The requirements intentionally focus on
# authorization/data-boundary operations and the normal business result of
# each lab.  They run against a version of the source with string contents
# masked, so source comments or a quoted "solution" cannot satisfy them.
_HANDLER_REQUIREMENTS: dict[int, tuple[tuple[str, re.Pattern[str]], ...]] = {
    1: (
        ("读取 request.body", re.compile(r"\brequest\s*\.\s*body\b", _JS_RE_FLAGS)),
        ("构造交接响应对象", re.compile(r"\b(?:const|let|var)\s+(?:response|result|payload)\s*=\s*\{", _JS_RE_FLAGS)),
        ("保留 handoff/serviceHours/policy 业务字段", re.compile(r"\bhandoff\s*:[\s\S]{0,320}?\bserviceHours\s*:[\s\S]{0,320}?\bpolicy\s*:", _JS_RE_FLAGS)),
        ("对 includeRuntimePolicy 执行脱敏分支", re.compile(r"\bif\s*\([^)]*includeRuntimePolicy[^)]*\)[\s\S]{0,320}?\b(?:response|result|payload)\s*\.\s*policy\s*=", _JS_RE_FLAGS)),
        ("返回交接响应", re.compile(r"\breturn\s+(?:response|result|payload)\s*;", _JS_RE_FLAGS)),
    ),
    2: (
        ("从请求读取 ticketId", re.compile(r"\brequest\s*\.\s*body\s*\.\s*ticketId\b", _JS_RE_FLAGS)),
        ("通过 ticketStore 查询工单", re.compile(r"\bticketStore\s*\.\s*get\s*\(", _JS_RE_FLAGS)),
        ("拒绝不存在的工单", re.compile(r"\bif\s*\(\s*!\s*ticket\s*\)\s*throw\b", _JS_RE_FLAGS)),
        ("按数据边界处理外部备注", re.compile(r"\bsanitizeExternalNote\s*\(\s*ticket\s*\.\s*note\s*\)", _JS_RE_FLAGS)),
        ("返回迁移预览业务字段", re.compile(r"\breturn\s*\{[\s\S]{0,420}?\bticketId\s*:[\s\S]{0,260}?\bcustomer\s*:[\s\S]{0,260}?\bmigrationStatus\s*:[\s\S]{0,260}?\bnextStep\s*:", _JS_RE_FLAGS)),
    ),
    3: (
        ("处理文档注释为非可信数据", re.compile(r"\buntrustedAnnotation\s*\(\s*document\s*\.\s*annotation\s*\)", _JS_RE_FLAGS)),
        ("返回知识库引用字段", re.compile(r"\breturn\s*\{[\s\S]{0,300}?\bid\s*:[\s\S]{0,220}?\btitle\s*:[\s\S]{0,220}?\bexcerpt\s*:", _JS_RE_FLAGS)),
        ("从正文构造摘要", re.compile(r"\bString\s*\(\s*document\s*\.\s*body", _JS_RE_FLAGS)),
    ),
    4: (
        ("读取工具请求参数", re.compile(r"\brequest\s*\.\s*body\b", _JS_RE_FLAGS)),
        ("按调用者角色授权", re.compile(r"\bactor\s*\.\s*role\b", _JS_RE_FLAGS)),
        ("限制 diagnostics 工具", re.compile(r"\bbody\s*\.\s*tool\s*!==?\s*[\"']\s*[\"']", _JS_RE_FLAGS)),
        ("越权请求会抛出错误", re.compile(r"\bthrow\s+new\s+Error\s*\(", _JS_RE_FLAGS)),
        ("保留 diagnostics 业务调用", re.compile(r"\breturn\s+tools\s*\.\s*diagnostics\s*\(\s*actor\s*\.\s*id\s*\)", _JS_RE_FLAGS)),
    ),
    5: (
        ("保留公开 health 路由", re.compile(r"\bpath\s*===?\s*[\"']\s*[\"'][\s\S]{0,240}?\breturn\s*\{[\s\S]{0,140}?\bstatus\s*:", _JS_RE_FLAGS)),
        ("受保护路由经过 requireApiKey", re.compile(r"\bflowStore\s*\.\s*getAuthorized\s*\(\s*requireApiKey\s*\(\s*request\s*\)\s*,\s*path\s*\)", _JS_RE_FLAGS)),
    ),
    6: (
        ("从请求读取 appId", re.compile(r"\brequest\s*\.\s*body[\s\S]{0,100}?\.\s*appId\b", _JS_RE_FLAGS)),
        ("按会话角色授权", re.compile(r"\brequest\s*\.\s*session\s*\.\s*role\s*!==?\s*[\"']\s*[\"']", _JS_RE_FLAGS)),
        ("校验租户归属", re.compile(r"\bappStore\s*\.\s*belongsToTenant\s*\(\s*request\s*\.\s*session\s*\.\s*tenant\s*,\s*appId\s*\)", _JS_RE_FLAGS)),
        ("限制非管理员导出为公开应用", re.compile(r"\bappStore\s*\.\s*isPublic\s*\(\s*appId\s*\)", _JS_RE_FLAGS)),
        ("保留 DSL 导出", re.compile(r"\breturn\s+appStore\s*\.\s*exportDsl\s*\(\s*appId\s*\)", _JS_RE_FLAGS)),
    ),
    7: (
        ("解析并固定远端地址", re.compile(r"\bawait\s+resolver\s*\.\s*resolvePinned\s*\(", _JS_RE_FLAGS)),
        ("校验公开 HTTPS 目的地", re.compile(r"\bif\s*\(\s*!\s*isPublicHttps\s*\(\s*target\s*\)\s*\)\s*throw\b", _JS_RE_FLAGS)),
        ("使用固定目标抓取", re.compile(r"\breturn\s+http\s*\.\s*getPinned\s*\(\s*target\s*,[\s\S]{0,240}?\bfollowRedirects\s*:\s*false", _JS_RE_FLAGS)),
    ),
    8: (
        ("读取报表语句", re.compile(r"\brequest\s*\.\s*body[\s\S]{0,100}?\.\s*statement\b", _JS_RE_FLAGS)),
        ("使用表列白名单解析", re.compile(r"\bparser\s*\.\s*allowlistedSelect\s*\(\s*statement\s*,", _JS_RE_FLAGS)),
        ("使用只读查询接口", re.compile(r"\breturn\s+db\s*\.\s*readOnly\s*\(\s*query\s*\)", _JS_RE_FLAGS)),
    ),
    9: (
        ("从会话派生租户", re.compile(r"\b(?:const|let|var)\s+tenant\s*=\s*request\s*\.\s*session\s*\.\s*tenant\b", _JS_RE_FLAGS)),
        ("拒绝跨租户请求", re.compile(r"\bquery\s*\.\s*tenantId[\s\S]{0,100}?!==?\s*tenant[\s\S]{0,160}?\bthrow\s+new\s+Error\s*\(", _JS_RE_FLAGS)),
        ("通过 ACL 感知的查询返回文档", re.compile(r"\breturn\s+repository\s*\.\s*findAuthorized\s*\(\s*tenant\s*,[\s\S]{0,220}?request\s*\.\s*session\s*\.\s*userId", _JS_RE_FLAGS)),
    ),
    10: (
        ("先读取执行记录", re.compile(r"\bexecutionStore\s*\.\s*get\s*\(", _JS_RE_FLAGS)),
        ("校验执行团队归属", re.compile(r"\bexecution\s*\.\s*team\s*!==?\s*request\s*\.\s*session\s*\.\s*team\b", _JS_RE_FLAGS)),
        ("拒绝无权停止", re.compile(r"\bthrow\s+new\s+Error\s*\(", _JS_RE_FLAGS)),
        ("使用已授权记录停止执行", re.compile(r"\breturn\s+executionStore\s*\.\s*stop\s*\(\s*execution\s*\.\s*id\s*\)", _JS_RE_FLAGS)),
    ),
}


_HELPER_REQUIREMENTS: dict[int, tuple[str, tuple[tuple[str, re.Pattern[str]], ...]]] = {
    2: ("sanitizeExternalNote", (
        ("接收外部备注参数", re.compile(r"\bnote\b", _JS_RE_FLAGS)),
        ("将备注转换为数据字符串", re.compile(r"\breturn\s+String\s*\(\s*note\b", _JS_RE_FLAGS)),
    )),
    3: ("untrustedAnnotation", (
        ("接收 annotation 参数", re.compile(r"\bannotation\b", _JS_RE_FLAGS)),
        ("将注释封装为数据对象", re.compile(r"\breturn\s*\{[\s\S]{0,180}?\bvalue\s*:\s*String\s*\(\s*annotation\b", _JS_RE_FLAGS)),
    )),
    5: ("requireApiKey", (
        ("读取请求头", re.compile(r"\brequest\s*\.\s*headers\b", _JS_RE_FLAGS)),
        ("缺失密钥时拒绝", re.compile(r"\bif\s*\(\s*!\s*apiKey\s*\)\s*throw\s+new\s+Error\s*\(", _JS_RE_FLAGS)),
        ("返回已验证密钥", re.compile(r"\breturn\s+apiKey\s*;", _JS_RE_FLAGS)),
    )),
}


_HELPER_PARAMETER_PATTERNS: dict[int, re.Pattern[str]] = {
    2: re.compile(r"\bnote\b"),
    3: re.compile(r"\bannotation\b"),
    5: re.compile(r"\brequest\b"),
}


def _verify_service_capabilities(source: str, markers: tuple[str, ...]) -> list[str]:
    """Ensure declared Web operations remain in the service capability list."""
    declaration = re.search(
        r"\b(?:const|let|var)\s+SERVICE_CAPABILITIES\s*=\s*\[(?P<items>[\s\S]*?)\]\s*;",
        source,
        re.S,
    )
    if declaration is None:
        return ["缺少 SERVICE_CAPABILITIES 操作声明"]
    items = declaration.group("items")
    return [f"操作声明缺少 {marker}" for marker in markers if marker not in items]


def _verify_handler_structure(source: str, challenge_id: int, handler: str) -> list[str]:
    """Validate that one exported handler still performs meaningful work."""
    extracted = _extract_js_function(source, handler)
    if extracted is None:
        return [f"缺少完整的 {handler}() 函数体"]
    parameters, body = extracted
    executable = _strip_js_strings(body)
    if not executable.strip() or not re.search(r"\b(?:return|throw|if|const|let|var)\b", executable):
        return [f"{handler}() 没有可执行的服务逻辑"]

    errors = _has_patterns(executable, _HANDLER_REQUIREMENTS.get(challenge_id, ()))
    if errors:
        return [f"{handler}() 未满足：{label}" for label in errors]

    helper_contract = _HELPER_REQUIREMENTS.get(challenge_id)
    if helper_contract is not None:
        helper_name, helper_requirements = helper_contract
        helper = _extract_js_function(source, helper_name)
        if helper is None:
            return [f"缺少 {helper_name}() 辅助处理器"]
        helper_parameters, helper_body = helper
        parameter_pattern = _HELPER_PARAMETER_PATTERNS[challenge_id]
        if parameter_pattern.search(helper_parameters) is None:
            return [f"{helper_name}() 未接收预期的外部输入参数"]
        helper_errors = _has_patterns(_strip_js_strings(helper_body), helper_requirements)
        if helper_errors:
            return [f"{helper_name}() 未满足：{label}" for label in helper_errors]

    return []


def _exports_handler(source: str, handler: str) -> bool:
    """Check the CommonJS export using executable source rather than strings."""
    code = _strip_js_strings(source)
    export = re.search(r"\bmodule\s*\.\s*exports\s*=\s*\{(?P<body>[^}]*)\}", code, re.S)
    return export is not None and re.search(rf"\b{re.escape(handler)}\b", export.group("body")) is not None


def _analyze_patched_source(project_root: Path, challenge_id: int = 1) -> tuple[str, list[str]]:
    """Validate the submitted Web/API service source without running it."""
    contract = vulnerability_contract(challenge_id)
    if contract.get("language") == "python":
        return _analyze_patched_python_source(project_root, challenge_id)
    if contract.get("language") == "text":
        return _analyze_patched_text_source(project_root, challenge_id)
    service_source = project_root / WEB_SERVICE_PATH
    if not service_source.is_file():
        return "check_failed", ["业务检查失败：src/web_service.js 不存在，目标 Web 服务无法启动。"]

    source = _strip_js_comments(service_source.read_text(encoding="utf-8", errors="replace"))
    if not source.strip():
        return "check_failed", ["业务检查失败：src/web_service.js 为空。"]
    if not _has_balanced_js_delimiters(source):
        return "check_failed", ["业务检查失败：src/web_service.js 的括号或函数体不完整，服务无法加载。"]
    if not contract["vulnerable_markers"] or not contract["fixed_markers"]:
        return "check_failed", ["题目配置缺少 Web 服务漏洞或修复契约。"]

    remaining = [
        marker for marker in contract["vulnerable_markers"]
        if _contains_source_marker(source, marker)
    ]
    if remaining:
        return "exp_exploit_success", [
            "漏洞回归失败：目标 Web 服务仍保留易受攻击的响应或授权边界。",
            "仍发现：" + "、".join(remaining[:4]),
        ]

    if _RUNTIME_SECRET_REFERENCE.search(source):
        return "exp_exploit_success", [
            "漏洞回归失败：修复后的 Web 服务仍可访问或序列化运行时校验字段。",
        ]

    dangerous_patterns = _WEB_DANGEROUS_PATTERNS.get(challenge_id, ())
    matched_patterns = [pattern.pattern for pattern in dangerous_patterns if pattern.search(source)]
    if matched_patterns:
        return "exp_exploit_success", [
            "漏洞回归失败：修复源码仍保留题目对应的危险 Web/API 调用形态。",
            "仍发现危险模式：" + "；".join(matched_patterns[:3]),
        ]

    missing = [
        marker for marker in contract["fixed_markers"]
        if not _contains_source_marker(source, marker)
    ]
    if missing:
        return "check_failed", [
            "防守源码检查失败：没有实现题目要求的服务端边界修复。",
            "缺少：" + "、".join(missing[:4]),
        ]

    service_markers = tuple(contract.get("service_markers", ()))
    capability_errors = _verify_service_capabilities(source, service_markers)
    if capability_errors:
        return "check_failed", [
            "业务检查失败：补丁没有在 SERVICE_CAPABILITIES 中保留目标 Web 服务的正常操作边界。",
            "；".join(capability_errors[:4]),
        ]

    handlers = tuple(contract.get("handler", ()))
    for handler in handlers:
        structure_errors = _verify_handler_structure(source, challenge_id, handler)
        if structure_errors:
            return "check_failed", [
                "业务检查失败：修复包仅包含标记或不完整服务逻辑。",
                "；".join(structure_errors[:4]),
            ]
        if not _exports_handler(source, handler):
            return "check_failed", [f"业务检查失败：{handler}() 未通过模块导出供 Web 路由使用。"]

    return "candidate_safe", [
        "Web 服务源码检查通过：运行时校验字段未出现在已部署的服务边界中。",
        "Web 服务契约通过：路由处理器、授权/数据边界与正常业务操作均保留。",
    ]


def _analyze_patched_text_source(project_root: Path, challenge_id: int) -> tuple[str, list[str]]:
    """非 Python 服务源（如 JS）的通用静态契约检查：只做标记与保留性校验。"""
    contract = vulnerability_contract(challenge_id)
    source_path = Path(str(contract.get("source_path") or ""))
    service_source = project_root / source_path
    if not service_source.is_file():
        return "check_failed", [f"业务检查失败：{source_path.as_posix()} 不存在，目标服务无法启动。"]
    source = service_source.read_text(encoding="utf-8", errors="replace")
    if not source.strip():
        return "check_failed", [f"业务检查失败：{source_path.as_posix()} 为空。"]

    remaining = [marker for marker in contract["vulnerable_markers"] if marker in source]
    if remaining:
        return "exp_exploit_success", [
            "漏洞回归失败：目标服务仍保留易受攻击的响应或授权边界。",
            "仍发现：" + "、".join(remaining[:4]),
        ]
    missing = [marker for marker in contract["fixed_markers"] if marker not in source]
    if missing:
        return "check_failed", [
            "防守源码检查失败：没有实现题目要求的服务端边界修复。",
            "缺少：" + "、".join(missing[:4]),
        ]
    for marker in contract.get("service_markers", ()):
        if marker not in source:
            return "check_failed", [
                "业务检查失败：修复包删除了正常业务能力，目标服务无法继续提供服务。",
                f"缺少业务能力：{marker}",
            ]
    for handler in contract.get("handler", ()):
        if handler and handler not in source:
            return "check_failed", [f"业务检查失败：服务实现 {handler} 缺失或被重命名。"]
    return "candidate_safe", [
        "服务源码检查通过：易受攻击的边界已移除，正常业务能力保留。",
        "服务契约通过：服务实现与业务能力完整。",
    ]


def _analyze_patched_python_source(project_root: Path, challenge_id: int) -> tuple[str, list[str]]:
    """决赛题目的 Python 服务源码静态契约检查。

    决赛补丁目标是承载"遗留决策"授权条款的服务文件；检查要求该条款被移除、
    服务端授权语义保留、业务动作清单完整，且整个源码包可通过语法编译。
    """
    contract = vulnerability_contract(challenge_id)
    source_path = Path(str(contract.get("source_path") or ""))
    service_source = project_root / source_path
    if not service_source.is_file():
        return "check_failed", [f"业务检查失败：{source_path.as_posix()} 不存在，目标服务无法启动。"]

    source = service_source.read_text(encoding="utf-8", errors="replace")
    if not source.strip():
        return "check_failed", [f"业务检查失败：{source_path.as_posix()} 为空。"]
    try:
        compile(source, source_path.as_posix(), "exec")
    except SyntaxError as exc:
        return "check_failed", [f"业务检查失败：{source_path.as_posix()} 存在语法错误（第 {exc.lineno} 行），服务无法加载。"]

    if not contract["vulnerable_markers"] or not contract["fixed_markers"]:
        return "check_failed", ["题目配置缺少服务端漏洞或修复契约。"]

    remaining = [marker for marker in contract["vulnerable_markers"] if marker in source]
    if remaining:
        return "exp_exploit_success", [
            "漏洞回归失败：目标服务仍保留把不可信文本措辞当作授权的遗留决策分支。",
            "仍发现：" + "、".join(remaining[:4]),
        ]

    missing = [marker for marker in contract["fixed_markers"] if marker not in source]
    if missing:
        return "check_failed", [
            "防守源码检查失败：没有保留题目要求的服务端授权语义。",
            "缺少：" + "、".join(missing[:4]),
        ]

    # 业务动作清单必须仍然完整（处理函数与动作分发保留）。
    for marker in contract.get("service_markers", ()):
        if marker not in source:
            return "check_failed", [
                "业务检查失败：修复包删除了正常业务动作，目标服务无法继续提供服务。",
                f"缺少业务动作：{marker}",
            ]

    for handler in contract.get("handler", ()):
        if handler and handler not in source:
            return "check_failed", [f"业务检查失败：服务定义 {handler} 缺失或被重命名。"]

    return "candidate_safe", [
        "服务源码检查通过：遗留措辞授权分支已移除，服务端授权语义保留。",
        "服务契约通过：业务动作清单与服务定义完整。",
    ]


def _service_contract(challenge_id: int) -> dict[str, Any]:
    """Return the public deployment contract for a verified Web service."""
    contract = vulnerability_contract(challenge_id)
    return {
        "source_path": str(contract.get("source_path") or WEB_SERVICE_PATH),
        "handlers": list(contract.get("handler", ())),
        "operations": list(contract.get("service_markers", ())),
        "fixed_markers": list(contract.get("fixed_markers", ())),
    }


def evaluate_patch_archive(archive_path: Path, session_root: Path, challenge_id: int = 1) -> dict[str, Any]:
    """Apply a submitted archive and verify its Web handler in a disposable worktree.

    A repair first passes the source-contract checks, then its exported
    JavaScript handler is executed in a bounded QuickJS context against both
    vulnerability and normal-business probes.  The caller runs the separate
    HTTP fixture regression only after this function reports
    ``candidate_safe``.
    """
    session_root.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="awdp-check-", dir=session_root))
    project_root = workspace / "app" / "lib"
    bundle_root = workspace / "bundle"
    result: dict[str, Any] = {
        "status": "check_failed",
        "logs": [],
        "workspace": str(workspace),
    }
    try:
        _write_baseline(project_root, challenge_id)
        bundle_root.mkdir(parents=True, exist_ok=True)
        _safe_extract(archive_path, bundle_root)
        script = bundle_root / "update.sh"
        if not script.is_file():
            raise PatchPackageError("补丁包根目录缺少必需的 update.sh")
        operations = _apply_update_script(script, project_root, bundle_root)
        status, analysis_logs = _analyze_patched_source(project_root, challenge_id)
        logs = operations + analysis_logs
        if status == "candidate_safe" and vulnerability_contract(challenge_id).get("language") not in {"python", "text"}:
            service_source = project_root / WEB_SERVICE_PATH
            runtime_ok, runtime_logs = verify_repaired_service_source(
                service_source.read_text(encoding="utf-8", errors="replace"),
                challenge_id,
            )
            logs.extend(runtime_logs)
            if not runtime_ok:
                status = "check_failed"
        result.update({"status": status, "logs": logs})
        if status == "candidate_safe":
            active_root = session_root / "active-source"
            if active_root.exists():
                shutil.rmtree(active_root)
            shutil.copytree(project_root, active_root)
            result["active_source"] = str(active_root)
            result["service_contract"] = _service_contract(challenge_id)
        return result
    except PatchPackageError as exc:
        result["logs"] = [f"补丁包检查失败：{exc}"]
        return result
    except OSError as exc:
        result["logs"] = [f"隔离工作区错误：{exc}"]
        return result
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
