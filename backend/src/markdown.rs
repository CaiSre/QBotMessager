//! Markdown / 纯文本清洗。
//!
//! QQ 的 Markdown 支持标题、加粗/斜体、链接、列表、引用、分割线、行内代码，
//! 不支持颜色、表格与 HTML 标签；这里只输出最小公共子集，避免整条消息静默失效。
//!
//! 语义按字符计数；超长内容截断并追加固定后缀（上限过小时仅截断）。

use std::sync::OnceLock;

use regex::{Captures, Regex};

/// 清洗前的最大扫描长度。
///
/// 图片正则 `!\[([^\]]*)\]\(([^)]*)\)` 在大量 `![` 上会退化为平方级，
/// 因此必须先限定输入再清洗。
const MAX_SCAN: usize = 20_000;

/// 超长截断后缀。
const TRUNCATION_SUFFIX: &str = "\n…（内容过长已截断）";

fn image_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"!\[([^\]]*)\]\(([^)]*)\)").expect("图片正则"))
}

fn bare_image_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[!\(([^)]*)\)\]").expect("裸图片正则"))
}

fn link_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[([^\]\n]*)\]\(([^)\s]*)\)").expect("链接正则"))
}

fn control_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]").expect("控制字符正则"))
}

fn blank_lines_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\n{3,}").expect("空行正则"))
}

/// 清洗前的长度上限；最终输出仍会按 `max_len` 精确截断。
fn bound(text: &str, max_len: Option<usize>) -> String {
    let cap = match max_len {
        Some(max_len) => max_len.saturating_mul(2).min(MAX_SCAN),
        None => MAX_SCAN,
    };
    if text.chars().count() <= cap {
        return text.to_string();
    }
    text.chars().take(cap).collect()
}

/// 构造安全的 Markdown 链接。
///
/// 标签里的 `\ [ ] ( )` 会被转义，避免外部标题注入额外链接；目标只接受
/// `http/https`，其它协议或不含主机的地址降级为纯文本标签。
pub fn markdown_link(label: &str, url: &str) -> String {
    let label = escape_link_label(label);
    match safe_link_url(url) {
        Some(url) => format!("[{label}]({url})"),
        None => label,
    }
}

/// 转义链接标签中的 Markdown 元字符，并去掉换行/控制字符。
fn escape_link_label(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for ch in label.chars() {
        match ch {
            '\r' | '\n' => out.push(' '),
            '\\' | '[' | ']' | '(' | ')' => {
                out.push('\\');
                out.push(ch);
            }
            _ if ch.is_control() => {}
            _ => out.push(ch),
        }
    }
    out
}

/// 链接目标是否安全：只允许 http/https，且不含空白、控制字符或可截断语法的字符。
fn safe_link_url(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty()
        || raw.chars().any(|ch| {
            ch.is_whitespace()
                || ch.is_control()
                || matches!(ch, '\\' | '(' | ')' | '<' | '>' | '"' | '\'')
        })
    {
        return None;
    }
    let parsed = url::Url::parse(raw).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return None;
    }
    Some(raw.to_string())
}

fn is_safe_link_url(raw: &str) -> bool {
    safe_link_url(raw).is_some()
}

/// 去掉 HTML 标签，保留标签内文字（线性扫描，避免正则回溯）。
pub fn strip_html(text: &str) -> String {
    if !text.contains('<') {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0usize;
    while index < bytes.len() {
        let Some(lt) = text[index..].find('<').map(|offset| index + offset) else {
            out.push_str(&text[index..]);
            break;
        };
        out.push_str(&text[index..lt]);
        let Some(gt) = text[lt + 1..].find('>').map(|offset| lt + 1 + offset) else {
            // 没有闭合的 '>'：保留剩余文本，不再当作标签
            out.push_str(&text[lt..]);
            break;
        };
        if gt == lt + 1 {
            // "<>" 不是标签
            out.push('<');
            index = lt + 1;
            continue;
        }
        index = gt + 1;
    }
    out
}

/// 把 Markdown 表格降级为「- **列**：值」列表（QQ Markdown 不支持表格）。
///
/// 以第一行为表头，第二行分隔线被丢弃，其后每一行渲染成一条列表项。
pub fn degrade_tables(content: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut header: Option<Vec<String>> = None;
    for line in content.split('\n') {
        let stripped = line.trim();
        // 首尾都是 ASCII 的 '|'，按字节切片必定落在字符边界上。
        let is_row = if stripped.len() >= 2 && stripped.starts_with('|') && stripped.ends_with('|')
        {
            let inner = &stripped[1..stripped.len() - 1];
            inner.contains('|')
        } else {
            false
        };
        if is_row {
            let cells: Vec<String> = stripped
                .trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().to_string())
                .collect();
            if cells
                .iter()
                .all(|cell| !cell.is_empty() && cell.chars().all(|c| "-: ".contains(c)))
            {
                // 分隔行
                continue;
            }
            if header.is_none() {
                header = Some(cells);
                continue;
            }
            let header_cells = header.as_ref().expect("表头已存在");
            let pairs: Vec<String> = cells
                .iter()
                .enumerate()
                .filter(|(_, value)| !value.is_empty())
                .map(|(index, value)| {
                    let name = match header_cells.get(index) {
                        Some(name) => name.clone(),
                        None => format!("列{}", index + 1),
                    };
                    format!("**{name}**：{value}")
                })
                .collect();
            if !pairs.is_empty() {
                out.push(format!("- {}", pairs.join("，")));
            }
            continue;
        }
        header = None;
        out.push(line.to_string());
    }
    out.join("\n")
}

/// 清洗 Markdown 并按需截断。
pub fn sanitize_markdown(text: &str, max_len: Option<usize>) -> String {
    if text.is_empty() {
        return String::new();
    }
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut content = bound(&normalized, max_len);
    content = strip_html(&content);
    content = image_regex()
        .replace_all(&content, |caps: &Captures| {
            let alt = &caps[1];
            if alt.is_empty() {
                "（图片）".to_string()
            } else {
                format!("（图片：{alt}）")
            }
        })
        .into_owned();
    content = bare_image_regex()
        .replace_all(&content, "（图片）")
        .into_owned();
    content = link_regex()
        .replace_all(&content, |caps: &Captures| {
            let label = &caps[1];
            if is_safe_link_url(&caps[2]) {
                caps[0].to_string()
            } else {
                label.to_string()
            }
        })
        .into_owned();
    content = degrade_tables(&content);
    content = control_regex().replace_all(&content, "").into_owned();
    content = blank_lines_regex()
        .replace_all(&content, "\n\n")
        .into_owned();
    let content = content.trim();
    truncate(content, max_len)
}

/// 清洗纯文本：去控制字符、压缩空白、按需截断。
pub fn sanitize_text(text: &str, max_len: Option<usize>) -> String {
    if text.is_empty() {
        return String::new();
    }
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut content = bound(&normalized, max_len);
    content = strip_html(&content);
    content = control_regex().replace_all(&content, "").into_owned();
    content = blank_lines_regex()
        .replace_all(&content, "\n\n")
        .into_owned();
    let content = content.trim();
    truncate(content, max_len)
}

/// 清洗标题：去控制字符并按字符截断。
///
/// 标题不参与 Markdown/HTML 语义，不做标签与图片降级，
/// 只保证不含控制字符且长度可控，作为整体预算的一部分。
pub fn sanitize_title(input: &str, max_chars: usize) -> String {
    if input.is_empty() {
        return String::new();
    }
    let normalized = input.replace("\r\n", "\n").replace('\r', "\n");
    let cleaned = control_regex().replace_all(&normalized, "");
    cleaned.trim().chars().take(max_chars).collect()
}

/// 超长时截断并追加固定后缀，保证最终输出不超过 `max_len` 字符。
///
/// 上限不大于后缀长度时无法同时容纳正文与后缀，仅保留正文截断。
pub fn truncate(content: &str, max_len: Option<usize>) -> String {
    let Some(max_len) = max_len else {
        return content.to_string();
    };
    let chars: Vec<char> = content.chars().collect();
    if chars.len() <= max_len {
        return content.to_string();
    }
    let suffix_len = TRUNCATION_SUFFIX.chars().count();
    if max_len <= suffix_len {
        return chars[..max_len].iter().collect();
    }
    let end = max_len.saturating_sub(suffix_len).min(chars.len());
    let mut out: String = chars[..end].iter().collect();
    out.push_str(TRUNCATION_SUFFIX);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn degrades_table_to_list() {
        let content = "指标|值\n|磁盘|90%|\n|CPU|12%|\n";
        // 首行不是表格行，会被原样保留
        assert!(degrade_tables(content).starts_with("指标|值"));

        let table = "|指标|值|\n|---|:---:|\n|磁盘|90%|\n|CPU|12%|";
        assert_eq!(
            degrade_tables(table),
            "- **指标**：磁盘，**值**：90%\n- **指标**：CPU，**值**：12%"
        );
    }

    #[test]
    fn strips_html_and_images() {
        let content = "<font color=\"warning\">警告</font>\n![图](https://img.example.com/a.png)";
        let cleaned = sanitize_markdown(content, None);
        assert!(!cleaned.contains("<font"));
        assert!(cleaned.contains("警告"));
        assert!(cleaned.contains("（图片：图）"));
        assert!(!cleaned.contains("https://img.example.com/a.png"));
    }

    #[test]
    fn truncates_with_suffix() {
        let cleaned = sanitize_markdown(&"a".repeat(100), Some(20));
        assert!(cleaned.ends_with("（内容过长已截断）"));
        assert_eq!(cleaned.chars().count(), 20);
    }

    #[test]
    fn tiny_limit_truncates_without_suffix() {
        // 上限不大于后缀长度时无法同时容纳正文与后缀，仅保留正文截断。
        let cleaned = sanitize_markdown("内容", Some(1));
        assert_eq!(cleaned, "内");
    }

    #[test]
    fn sanitize_title_strips_control_chars_and_caps_length() {
        assert_eq!(sanitize_title("  告警\x00\n标题  ", 100), "告警\n标题");
        assert_eq!(sanitize_title(&"字".repeat(10), 4), "字字字字");
        assert_eq!(sanitize_title("", 10), "");
    }

    #[test]
    fn sanitize_text_removes_control_chars_and_blank_lines() {
        let raw = "第一行\x00\n\n\n\n第二行\r\n";
        assert_eq!(sanitize_text(raw, None), "第一行\n\n第二行");
    }

    #[test]
    fn strip_html_keeps_inner_text() {
        assert_eq!(strip_html("<b>粗体</b>"), "粗体");
        assert_eq!(strip_html("a < b"), "a < b");
        assert_eq!(strip_html("<>"), "<>");
        assert_eq!(strip_html("<b>未闭合"), "未闭合");
        assert_eq!(strip_html("<b未闭合"), "<b未闭合");
        assert_eq!(strip_html("没有标签"), "没有标签");
    }

    #[test]
    fn bare_image_becomes_placeholder() {
        assert_eq!(sanitize_markdown("[!(https://x/y.png)]", None), "（图片）");
    }

    #[test]
    fn markdown_link_escapes_labels_and_rejects_unsafe_urls() {
        assert_eq!(
            markdown_link("修复 [Bug](x)", "https://github.com/o/r/pull/1"),
            "[修复 \\[Bug\\]\\(x\\)](https://github.com/o/r/pull/1)"
        );
        assert_eq!(markdown_link("点我", "javascript:alert"), "点我");
        assert_eq!(markdown_link("点我", "data:text/html,x"), "点我");
        assert_eq!(markdown_link("点我", ""), "点我");
        assert_eq!(
            markdown_link("点我", "https://example.com/a?b=1"),
            "[点我](https://example.com/a?b=1)"
        );
    }

    #[test]
    fn sanitize_markdown_neutralizes_unsafe_link_schemes() {
        assert_eq!(sanitize_markdown("[点我](javascript:alert)", None), "点我");
        assert_eq!(sanitize_markdown("[点我](data:text/html,x)", None), "点我");
        assert_eq!(
            sanitize_markdown("[点我](https://example.com/x)", None),
            "[点我](https://example.com/x)"
        );
    }

    #[test]
    fn table_with_missing_header_column_gets_positional_name() {
        let table = "|a|b|\n|-|-|\n|1|2|3|";
        assert_eq!(degrade_tables(table), "- **a**：1，**b**：2，**列3**：3");
    }

    #[test]
    fn text_truncation_uses_same_suffix() {
        let cleaned = sanitize_text(&"字".repeat(100), Some(30));
        assert!(cleaned.ends_with("（内容过长已截断）"));
        assert_eq!(cleaned.chars().count(), 30);
    }

    #[test]
    fn blank_lines_collapse_to_two() {
        assert_eq!(sanitize_markdown("a\n\n\n\n\nb", None), "a\n\nb");
    }

    #[test]
    fn no_truncation_without_limit() {
        let long = "a".repeat(50_000);
        let cleaned = sanitize_markdown(&long, None);
        assert_eq!(cleaned.chars().count(), 20_000);
    }
}
