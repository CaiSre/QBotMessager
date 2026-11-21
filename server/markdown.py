"""Markdown / 纯文本清洗。

QQ 的 Markdown 支持标题、加粗/斜体、链接、列表、引用、分割线、行内代码，
不支持颜色、表格与 HTML 标签；这里只输出最小公共子集，避免整条消息静默失效。
"""

from __future__ import annotations

import re

_IMAGE = re.compile(r"!\[([^\]]*)\]\(([^)]*)\)")
_BARE_IMAGE = re.compile(r"\[!\(([^)]*)\)\]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BLANK_LINES = re.compile(r"\n{3,}")
_TRUNCATION_SUFFIX = "\n…（内容过长已截断）"

# 正则清洗前允许的最大输入长度。图片正则 `!\[([^\]]*)\]\(([^)]*)\)` 在
# 大量 `![` 上会退化为平方级，因此必须先限定输入再清洗。
_MAX_SCAN = 20_000


def _bound(text: str, max_len: int | None) -> str:
    """清洗前的长度上限；最终输出仍会按 max_len 精确截断。"""
    cap = min(max_len * 2, _MAX_SCAN) if max_len else _MAX_SCAN
    if len(text) <= cap:
        return text
    return text[:cap]


def strip_html(text: str) -> str:
    """去掉 HTML 标签，保留标签内文字（线性扫描，避免正则回溯）。"""
    if "<" not in text:
        return text
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        lt = text.find("<", i)
        if lt < 0:
            out.append(text[i:])
            break
        out.append(text[i:lt])
        gt = text.find(">", lt + 1)
        if gt < 0:
            # 没有闭合的 '>'：保留剩余文本，不再当作标签
            out.append(text[lt:])
            break
        if gt == lt + 1:
            # "<>" 不是标签
            out.append("<")
            i = lt + 1
            continue
        i = gt + 1
    return "".join(out)


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
    content = _bound(text.replace("\r\n", "\n").replace("\r", "\n"), max_len)
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
    content = _bound(text.replace("\r\n", "\n").replace("\r", "\n"), max_len)
    content = strip_html(content)
    content = _CONTROL.sub("", content)
    content = _BLANK_LINES.sub("\n\n", content).strip()
    if max_len and len(content) > max_len:
        content = content[: max_len - len(_TRUNCATION_SUFFIX)] + _TRUNCATION_SUFFIX
    return content
