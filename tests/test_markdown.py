"""Markdown 清洗与表格降级。"""

from __future__ import annotations

from server.markdown import degrade_tables, sanitize_markdown, sanitize_text


def test_degrades_table_to_list() -> None:
    content = "指标|值\n|磁盘|90%|\n|CPU|12%|\n"
    # 首行不是表格行，会被原样保留
    assert degrade_tables(content).startswith("指标|值")

    table = "|指标|值|\n|---|:---:|\n|磁盘|90%|\n|CPU|12%|"
    assert degrade_tables(table) == "- **指标**：磁盘，**值**：90%\n- **指标**：CPU，**值**：12%"


def test_strips_html_and_images() -> None:
    content = '<font color="warning">警告</font>\n![图](https://img.example.com/a.png)'
    cleaned = sanitize_markdown(content)
    assert "<font" not in cleaned
    assert "警告" in cleaned
    assert "（图片：图）" in cleaned
    assert "https://img.example.com/a.png" not in cleaned


def test_truncates_with_suffix() -> None:
    cleaned = sanitize_markdown("a" * 100, max_len=20)
    assert cleaned.endswith("（内容过长已截断）")
    assert len(cleaned) == 20


def test_sanitize_text_removes_control_chars_and_blank_lines() -> None:
    raw = "第一行\x00\n\n\n\n第二行\r\n"
    assert sanitize_text(raw) == "第一行\n\n第二行"
