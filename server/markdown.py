"""Markdown / 纯文本清洗。

QQ 的 Markdown 支持标题、加粗/斜体、链接、列表、引用、分割线、行内代码，
不支持颜色、表格与 HTML 标签；这里只输出最小公共子集，避免整条消息静默失效。
"""

from __future__ import annotations

import re

_HTML_TAG = re.compile(r"<[^>]+>")
_IMAGE = re.compile(r"!\[([^\]]*)\]\(([^)]*)\)")
_BARE_IMAGE = re.compile(r"\[!\(([^)]*)\)\]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BLANK_LINES = re.compile(r"\n{3,}")
_TRUNCATION_SUFFIX = "\n…（内容过长已截断）"


def strip_html(text: str) -> str:
    """去掉 HTML 标签，保留标签内文字。"""
    return _HTML_TAG.sub("", text)


def degrade_tables(content: str) -> str:
    """把 Markdown 表格降级为「- **列**：值」列表（QQ Markdown 不支持表格）。

    以第一行为表头，第二行分隔线被丢弃，其后每一行渲染成一条列表项。
    """
    out: list[str] = []
    header: list[str] | None = None
    for line in content.split("\n"):
        stripped = line.strip()
        is_row = (
            stripped.startswith("|")
            and stripped.endswith("|")
            and "|" in stripped[1:-1]
        )
        if is_row:
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if all(c and set(c) <= set("-: ") for c in cells):
                continue  # 分隔行
            if header is None:
                header = cells
                continue
            pairs = [
                (header[i] if i < len(header) else f"列{i + 1}", value)
                for i, value in enumerate(cells)
                if value
            ]
            if pairs:
                out.append("- " + "，".join(f"**{k}**：{v}" for k, v in pairs))
            continue
        header = None
        out.append(line)
    return "\n".join(out)


def sanitize_markdown(text: str, *, max_len: int | None = None) -> str:
    """清洗 Markdown 并按需截断。"""
    if not text:
        return ""
    content = text.replace("\r\n", "\n").replace("\r", "\n")
    content = strip_html(content)
    content = _IMAGE.sub(lambda m: f"（图片：{m.group(1)}）" if m.group(1) else "（图片）", content)
    content = _BARE_IMAGE.sub("（图片）", content)
    content = degrade_tables(content)
    content = _CONTROL.sub("", content)
    content = _BLANK_LINES.sub("\n\n", content).strip()
    if max_len and len(content) > max_len:
        content = content[: max_len - len(_TRUNCATION_SUFFIX)] + _TRUNCATION_SUFFIX
    return content


def sanitize_text(text: str, *, max_len: int | None = None) -> str:
    """清洗纯文本：去控制字符、压缩空白、按需截断。"""
    if not text:
        return ""
    content = text.replace("\r\n", "\n").replace("\r", "\n")
    content = strip_html(content)
    content = _CONTROL.sub("", content)
    content = _BLANK_LINES.sub("\n\n", content).strip()
    if max_len and len(content) > max_len:
        content = content[: max_len - len(_TRUNCATION_SUFFIX)] + _TRUNCATION_SUFFIX
    return content
