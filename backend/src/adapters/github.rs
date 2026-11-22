//! GitHub Webhook 负载解析。
//!
//! 事件类型来自 `X-GitHub-Event` 请求头而不是负载本身，因此 `parse` 需要 `event`
//! 参数；协议与 `server/adapters/github.py` 一一对应。常见事件使用专门格式，
//! 其余事件走通用格式，保证任何事件类型都会生成消息。

use serde_json::{Map, Value};

use super::base::{Adapter, AdapterError, FMT_MARKDOWN, UnifiedMessage};

/// 推送事件最多展示的提交数。
const PUSH_COMMIT_LIMIT: usize = 5;
/// Release 说明的最大展示长度。
const RELEASE_NOTES_LIMIT: usize = 500;
/// 通用格式主体的最大展示长度。
const SUBJECT_LIMIT: usize = 80;

const PR_ACTIONS: &[(&str, &str)] = &[
    ("opened", "打开"),
    ("closed", "关闭"),
    ("reopened", "重新打开"),
    ("ready_for_review", "标记为可评审"),
    ("synchronize", "更新了提交"),
    ("review_requested", "请求评审"),
    ("review_request_removed", "撤销评审请求"),
    ("edited", "编辑"),
    ("labeled", "添加标签"),
    ("unlabeled", "移除标签"),
];

const ISSUE_ACTIONS: &[(&str, &str)] = &[
    ("opened", "打开"),
    ("closed", "关闭"),
    ("reopened", "重新打开"),
    ("edited", "编辑"),
    ("assigned", "指派"),
    ("unassigned", "取消指派"),
    ("labeled", "添加标签"),
    ("unlabeled", "移除标签"),
    ("milestoned", "设置里程碑"),
    ("demilestoned", "移除里程碑"),
];

const RELEASE_ACTIONS: &[(&str, &str)] = &[
    ("published", "发布"),
    ("created", "创建"),
    ("edited", "编辑"),
    ("prereleased", "预发布"),
    ("released", "发布"),
    ("unpublished", "取消发布"),
    ("deleted", "删除"),
];

const CONCLUSIONS: &[(&str, &str)] = &[
    ("success", "成功"),
    ("failure", "失败"),
    ("cancelled", "已取消"),
    ("skipped", "已跳过"),
    ("timed_out", "超时"),
    ("action_required", "需要处理"),
    ("neutral", "中性"),
    ("stale", "过期"),
];

const WORKFLOW_STATUS: &[(&str, &str)] = &[
    ("queued", "排队中"),
    ("in_progress", "进行中"),
    ("pending", "等待中"),
    ("waiting", "等待中"),
    ("requested", "已请求"),
    ("completed", "已完成"),
];

/// 通用事件的动作文案（等价于 Python 三个动作表合并后再补充的 `_ACTION_LABELS`）。
const EXTRA_ACTION_LABELS: &[(&str, &str)] = &[
    ("created", "创建"),
    ("deleted", "删除"),
    ("updated", "更新"),
    ("added", "添加"),
    ("removed", "移除"),
    ("completed", "完成"),
    ("in_progress", "进行中"),
    ("queued", "排队中"),
    ("waiting", "等待中"),
    ("requested", "请求"),
    ("rerequested", "重新请求"),
    ("submitted", "提交"),
    ("dismissed", "驳回"),
    ("approved", "通过"),
    ("changes_requested", "请求修改"),
    ("commented", "评论"),
    ("resolved", "已解决"),
    ("unresolved", "未解决"),
    ("started", "开始"),
    ("stopped", "停止"),
    ("granted", "授权"),
    ("revoked", "撤销"),
    ("transferred", "转移"),
    ("renamed", "重命名"),
    ("archived", "归档"),
    ("unarchived", "取消归档"),
    ("publicized", "设为公开"),
    ("privatized", "设为私有"),
    ("pinned", "置顶"),
    ("unpinned", "取消置顶"),
    ("locked", "锁定"),
    ("unlocked", "解锁"),
];

/// 事件展示名；未列出的新事件直接使用 `X-GitHub-Event` 原值。
const EVENT_LABELS: &[(&str, &str)] = &[
    ("branch_protection_configuration", "分支保护配置"),
    ("branch_protection_rule", "分支保护规则"),
    ("check_run", "检查运行"),
    ("check_suite", "检查套件"),
    ("code_scanning_alert", "代码扫描告警"),
    ("commit_comment", "提交评论"),
    ("create", "创建引用"),
    ("custom_property", "自定义属性"),
    ("custom_property_values", "自定义属性值"),
    ("delete", "删除引用"),
    ("dependabot_alert", "Dependabot 告警"),
    ("deploy_key", "部署密钥"),
    ("deployment", "部署"),
    ("deployment_protection_rule", "部署保护规则"),
    ("deployment_review", "部署评审"),
    ("deployment_status", "部署状态"),
    ("discussion", "讨论"),
    ("discussion_comment", "讨论评论"),
    ("fork", "Fork"),
    ("github_app_authorization", "GitHub App 授权"),
    ("gollum", "Wiki 页面"),
    ("installation", "App 安装"),
    ("installation_repositories", "App 仓库变更"),
    ("installation_target", "App 安装目标"),
    ("issue_comment", "Issue 评论"),
    ("issue_dependencies", "Issue 依赖"),
    ("issue_relates_to", "Issue 关联"),
    ("issues", "Issue"),
    ("label", "标签"),
    ("marketplace_purchase", "Marketplace 购买"),
    ("member", "成员"),
    ("membership", "成员关系"),
    ("merge_group", "合并组"),
    ("meta", "Meta"),
    ("milestone", "里程碑"),
    ("org_block", "组织封禁"),
    ("organization", "组织"),
    ("package", "包"),
    ("page_build", "Pages 构建"),
    ("personal_access_token_request", "个人访问令牌请求"),
    ("ping", "Ping"),
    ("project", "项目"),
    ("project_card", "项目卡片"),
    ("project_column", "项目列"),
    ("projects_v2", "项目"),
    ("projects_v2_item", "项目条目"),
    ("projects_v2_status_update", "项目状态更新"),
    ("public", "仓库公开"),
    ("pull_request", "Pull Request"),
    ("pull_request_review", "PR 评审"),
    ("pull_request_review_comment", "PR 评审评论"),
    ("pull_request_review_thread", "PR 评审线程"),
    ("push", "推送"),
    ("registry_package", "注册表包"),
    ("release", "Release"),
    ("repository", "仓库"),
    ("repository_advisory", "仓库安全公告"),
    ("repository_dispatch", "仓库分发"),
    ("repository_import", "仓库导入"),
    ("repository_ruleset", "仓库规则集"),
    ("repository_vulnerability_alert", "仓库漏洞告警"),
    ("secret_scanning_alert", "密钥扫描告警"),
    ("secret_scanning_alert_location", "密钥扫描位置"),
    ("secret_scanning_scan", "密钥扫描"),
    ("security_advisory", "安全公告"),
    ("security_and_analysis", "安全与分析"),
    ("sponsorship", "赞助"),
    ("star", "Star"),
    ("status", "提交状态"),
    ("sub_issues", "子 Issue"),
    ("team", "团队"),
    ("team_add", "团队添加"),
    ("watch", "Watch"),
    ("workflow_dispatch", "工作流手动触发"),
    ("workflow_job", "工作流任务"),
    ("workflow_run", "工作流运行"),
];

/// 通用格式从负载中提取可读主体与链接的候选字段（顺序与 Python 一致）。
const SUBJECT_FIELDS: &[(&str, &[&str])] = &[
    ("pull_request", &["title"]),
    ("issue", &["title"]),
    ("release", &["name", "tag_name"]),
    ("discussion", &["title"]),
    ("comment", &["body"]),
    ("check_run", &["name"]),
    ("check_suite", &["head_branch"]),
    ("workflow_run", &["name"]),
    ("workflow_job", &["name"]),
    ("deployment", &["environment", "description"]),
    ("deployment_status", &["description", "state"]),
    ("forkee", &["full_name"]),
    ("member", &["login"]),
    ("organization", &["login"]),
    ("team", &["name"]),
    ("project", &["name"]),
    ("projects_v2", &["title"]),
    ("projects_v2_item", &["title", "name"]),
    ("package", &["name"]),
    ("registry_package", &["name"]),
    ("security_advisory", &["summary"]),
    ("repository_advisory", &["summary"]),
    ("secret_scanning_alert", &["secret_type_display_name"]),
];

/// GitHub 适配器。
#[derive(Debug, Default, Clone, Copy)]
pub struct GitHubAdapter;

impl GitHubAdapter {
    /// 构造适配器。
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for GitHubAdapter {
    fn platform(&self) -> &'static str {
        "github"
    }

    fn parse(&self, payload: &Value, event: &str) -> Result<UnifiedMessage, AdapterError> {
        let Some(payload) = payload.as_object() else {
            return Err(AdapterError::payload("负载必须是 JSON 对象"));
        };
        let event = event.trim().to_lowercase();
        if event.is_empty() {
            return Err(AdapterError::payload("缺少 X-GitHub-Event 请求头"));
        }
        match event.as_str() {
            "ping" => Ok(ping_message(payload)),
            "push" => Ok(push_message(payload)),
            "pull_request" => Ok(pull_request_message(payload)),
            "issues" => Ok(issues_message(payload)),
            "release" => Ok(release_message(payload)),
            "workflow_job" => Ok(workflow_job_message(payload)),
            "workflow_run" => workflow_run_message(payload),
            _ => Ok(generic_message(payload, &event)),
        }
    }
}

fn ping_message(payload: &Map<String, Value>) -> UnifiedMessage {
    let repo = repo(payload);
    let zen = stripped(payload, "zen");
    let mut body = if repo.is_empty() {
        "Webhook 已接入".to_string()
    } else {
        format!("Webhook 已接入仓库 {repo}")
    };
    if !zen.is_empty() {
        body.push_str(&format!("\n\n{zen}"));
    }
    markdown_message(
        "GitHub Webhook 接入成功".to_string(),
        body,
        "ping".to_string(),
    )
}

fn push_message(payload: &Map<String, Value>) -> UnifiedMessage {
    let repo = repo(payload);
    let branch = short_ref(raw_str(payload, "ref"));
    let actor = actor(payload);
    let commits = payload
        .get("commits")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    if payload.get("deleted").is_some_and(truthy) {
        return markdown_message(
            format!("{repo} 删除分支"),
            format!("**{actor}** 删除了 `{branch}`"),
            "push".to_string(),
        );
    }

    let mut lines: Vec<String> = Vec::new();
    for commit in commits.iter().take(PUSH_COMMIT_LIMIT) {
        let commit = commit.as_object();
        let sha = commit
            .and_then(|map| map.get("id"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let sha = take_chars(sha, 7);
        let message = commit
            .and_then(|map| map.get("message"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let message = message.split('\n').next().unwrap_or_default().trim();
        let author = commit
            .and_then(|map| map.get("author"))
            .and_then(Value::as_object)
            .and_then(|map| map.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim();
        let mut item = if sha.is_empty() {
            format!("- {message}")
        } else {
            format!("- `{sha}` {message}")
        };
        if !author.is_empty() {
            item.push_str(&format!(" — {author}"));
        }
        lines.push(item);
    }
    if commits.len() > PUSH_COMMIT_LIMIT {
        lines.push(format!(
            "- …另有 {} 条提交",
            commits.len() - PUSH_COMMIT_LIMIT
        ));
    }

    let mut head = format!("**{actor}** 推送了 {} 个提交到 `{branch}`", commits.len());
    if payload.get("created").is_some_and(truthy) {
        head.push_str("（新建分支）");
    }
    if payload.get("forced").is_some_and(truthy) {
        head.push_str("（强制推送）");
    }
    let mut body = std::iter::once(head)
        .chain(lines)
        .collect::<Vec<String>>()
        .join("\n");
    let compare = stripped(payload, "compare");
    if !compare.is_empty() {
        body.push_str(&format!("\n\n[查看对比]({compare})"));
    }
    markdown_message(format!("{repo} 推送 {branch}"), body, "push".to_string())
}

fn pull_request_message(payload: &Map<String, Value>) -> UnifiedMessage {
    let action = stripped(payload, "action");
    let pr = payload.get("pull_request").and_then(Value::as_object);
    let repo = repo(payload);
    let actor = actor(payload);
    let number = object_field(payload, "pull_request")
        .and_then(|map| map.get("number"))
        .filter(|value| truthy(value))
        .or_else(|| payload.get("number").filter(|value| truthy(value)))
        .map(value_text)
        .unwrap_or_default();
    let title_text = pr
        .and_then(|map| map.get("title"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let title_text = if title_text.is_empty() {
        "（无标题）".to_string()
    } else {
        title_text
    };
    let url = pr
        .and_then(|map| map.get("html_url"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();

    let merged = pr.and_then(|map| map.get("merged")).is_some_and(truthy);
    let (label, actor) = if action == "closed" && merged {
        let merged_by = pr
            .and_then(|map| map.get("merged_by"))
            .and_then(Value::as_object)
            .and_then(|map| map.get("login"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim();
        let actor = if merged_by.is_empty() {
            actor
        } else {
            merged_by.to_string()
        };
        ("合并".to_string(), actor)
    } else {
        let label = lookup(PR_ACTIONS, &action)
            .map(str::to_string)
            .unwrap_or_else(|| action_or_update(&action));
        (label, actor)
    };

    let link = link_text(&title_text, &url);
    let source = format!(
        "pull_request.{}",
        if action.is_empty() {
            "unknown"
        } else {
            action.as_str()
        }
    );
    markdown_message(
        format!("{repo} PR #{number}"),
        format!("**{actor}** {label}：{link}"),
        source,
    )
}

fn issues_message(payload: &Map<String, Value>) -> UnifiedMessage {
    let action = stripped(payload, "action");
    let issue = payload.get("issue").and_then(Value::as_object);
    let repo = repo(payload);
    let actor = actor(payload);
    let number = object_field(payload, "issue")
        .and_then(|map| map.get("number"))
        .filter(|value| truthy(value))
        .or_else(|| payload.get("number").filter(|value| truthy(value)))
        .map(value_text)
        .unwrap_or_default();
    let title_text = issue
        .and_then(|map| map.get("title"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let title_text = if title_text.is_empty() {
        "（无标题）".to_string()
    } else {
        title_text
    };
    let url = issue
        .and_then(|map| map.get("html_url"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let label = lookup(ISSUE_ACTIONS, &action)
        .map(str::to_string)
        .unwrap_or_else(|| action_or_update(&action));

    let link = link_text(&title_text, &url);
    let source = format!(
        "issues.{}",
        if action.is_empty() {
            "unknown"
        } else {
            action.as_str()
        }
    );
    markdown_message(
        format!("{repo} Issue #{number}"),
        format!("**{actor}** {label}：{link}"),
        source,
    )
}

fn release_message(payload: &Map<String, Value>) -> UnifiedMessage {
    let action = stripped(payload, "action");
    let release = payload.get("release").and_then(Value::as_object);
    let repo = repo(payload);
    let actor = actor(payload);
    let tag = first_truthy_str(release, &["tag_name", "name"])
        .unwrap_or_default()
        .trim()
        .to_string();
    let tag = if tag.is_empty() {
        "未知标签".to_string()
    } else {
        tag
    };
    let name = match release
        .and_then(|map| map.get("name"))
        .filter(|value| truthy(value))
        .and_then(Value::as_str)
    {
        Some(name) => name.trim().to_string(),
        None => tag.clone(),
    };
    let url = release
        .and_then(|map| map.get("html_url"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let label = lookup(RELEASE_ACTIONS, &action)
        .map(str::to_string)
        .unwrap_or_else(|| action_or_update(&action));

    let link = link_text(&name, &url);
    let mut body = format!("**{actor}** {label}：{link}");
    let notes = release
        .and_then(|map| map.get("body"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if !notes.is_empty() {
        let chars: Vec<char> = notes.chars().collect();
        let notes = if chars.len() > RELEASE_NOTES_LIMIT {
            let head: String = chars[..RELEASE_NOTES_LIMIT].iter().collect();
            format!("{}…", head.trim_end())
        } else {
            notes.to_string()
        };
        body.push_str(&format!("\n\n{notes}"));
    }
    let source = format!(
        "release.{}",
        if action.is_empty() {
            "unknown"
        } else {
            action.as_str()
        }
    );
    markdown_message(format!("{repo} Release {tag}"), body, source)
}

fn workflow_run_message(payload: &Map<String, Value>) -> Result<UnifiedMessage, AdapterError> {
    let action = stripped(payload, "action");
    if action != "completed" {
        return Err(AdapterError::ignored(format!(
            "workflow_run 仅推送 completed：{action}"
        )));
    }
    let run = payload.get("workflow_run").and_then(Value::as_object);
    let repo = repo(payload);
    let name = first_truthy_str(run, &["name"])
        .unwrap_or_default()
        .trim()
        .to_string();
    let name = if name.is_empty() {
        "工作流".to_string()
    } else {
        name
    };
    let conclusion = stripped_map(run, "conclusion");
    let conclusion = if conclusion.is_empty() {
        "unknown".to_string()
    } else {
        conclusion
    };
    let label = lookup(CONCLUSIONS, &conclusion)
        .map(str::to_string)
        .unwrap_or_else(|| conclusion.clone());
    let branch = stripped_map(run, "head_branch");
    let url = stripped_map(run, "html_url");

    let mut body = if branch.is_empty() {
        format!("运行{label}")
    } else {
        format!("分支 `{branch}` 运行{label}")
    };
    if !url.is_empty() {
        body.push_str(&format!("\n\n[查看运行]({url})"));
    }
    Ok(markdown_message(
        format!("{repo} 工作流 {name} {label}"),
        body,
        "workflow_run.completed".to_string(),
    ))
}

fn workflow_job_message(payload: &Map<String, Value>) -> UnifiedMessage {
    let action = stripped(payload, "action");
    let job = payload.get("workflow_job").and_then(Value::as_object);
    let repo = repo(payload);
    let name = first_truthy_str(job, &["name"])
        .unwrap_or_default()
        .trim()
        .to_string();
    let name = if name.is_empty() {
        "任务".to_string()
    } else {
        name
    };
    let conclusion = stripped_map(job, "conclusion");
    let status = stripped_map(job, "status");
    let label = if !conclusion.is_empty() {
        lookup(CONCLUSIONS, &conclusion)
            .map(str::to_string)
            .unwrap_or_else(|| conclusion.clone())
    } else {
        let key = if status.is_empty() {
            action.as_str()
        } else {
            status.as_str()
        };
        lookup(WORKFLOW_STATUS, key)
            .map(str::to_string)
            .unwrap_or_else(|| action_or_update(&action))
    };
    let branch = stripped_map(job, "head_branch");
    let url = stripped_map(job, "html_url");

    let mut body = if branch.is_empty() {
        format!("任务{label}")
    } else {
        format!("分支 `{branch}` 任务{label}")
    };
    if !url.is_empty() {
        body.push_str(&format!("\n\n[查看运行]({url})"));
    }
    let title = format!("{repo} 工作流任务 {name} {label}")
        .trim()
        .to_string();
    let source = if action.is_empty() {
        "workflow_job".to_string()
    } else {
        format!("workflow_job.{action}")
    };
    markdown_message(title, body, source)
}

fn generic_message(payload: &Map<String, Value>, event: &str) -> UnifiedMessage {
    let repo = repo(payload);
    let actor = actor(payload);
    let action = stripped(payload, "action");
    let label = lookup(EVENT_LABELS, event).unwrap_or(event);
    let action_text = if action.is_empty() {
        String::new()
    } else {
        lookup_action(&action).unwrap_or_else(|| action.clone())
    };
    let (subject, url) = subject(payload, event);

    let mut body = if action_text.is_empty() {
        format!("**{actor}** 触发了{label}事件")
    } else {
        format!("**{actor}** {action_text}")
    };
    if !subject.is_empty() {
        let link = link_text(&subject, &url);
        body.push_str(&format!("：{link}"));
    }
    let repo_url = repo_url(payload);
    if url.is_empty() && !repo_url.is_empty() {
        body.push_str(&format!("\n\n[查看仓库]({repo_url})"));
    }
    let title = if repo.is_empty() {
        format!("GitHub {label}")
    } else {
        format!("{repo} {label}")
    };
    let source = if action.is_empty() {
        event.to_string()
    } else {
        format!("{event}.{action}")
    };
    markdown_message(title, body, source)
}

fn markdown_message(title: String, body: String, source: String) -> UnifiedMessage {
    UnifiedMessage {
        fmt: FMT_MARKDOWN.to_string(),
        title: Some(title),
        body,
        source_msgtype: source,
        ..UnifiedMessage::default()
    }
}

fn repo(payload: &Map<String, Value>) -> String {
    let Some(repository) = payload.get("repository").and_then(Value::as_object) else {
        return String::new();
    };
    first_truthy_str(Some(repository), &["full_name", "name"])
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn actor(payload: &Map<String, Value>) -> String {
    let login = payload
        .get("sender")
        .and_then(Value::as_object)
        .and_then(|map| map.get("login"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if login.is_empty() {
        "未知用户".to_string()
    } else {
        login.to_string()
    }
}

fn short_ref(reference: &str) -> String {
    for prefix in ["refs/heads/", "refs/tags/"] {
        if let Some(rest) = reference.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    if reference.is_empty() {
        "未知引用".to_string()
    } else {
        reference.to_string()
    }
}

fn repo_url(payload: &Map<String, Value>) -> String {
    match payload.get("repository") {
        Some(Value::Object(repository)) => url_of(repository),
        _ => String::new(),
    }
}

fn url_of(node: &Map<String, Value>) -> String {
    for key in ["html_url", "target_url", "url"] {
        let Some(value) = node.get(key).and_then(Value::as_str) else {
            continue;
        };
        let value = value.trim();
        if value.starts_with("http://") || value.starts_with("https://") {
            return value.to_string();
        }
    }
    String::new()
}

fn clip(text: &str) -> String {
    let flat = text.split_whitespace().collect::<Vec<&str>>().join(" ");
    let chars: Vec<char> = flat.chars().collect();
    if chars.len() <= SUBJECT_LIMIT {
        return flat;
    }
    let head: String = chars[..SUBJECT_LIMIT - 1].iter().collect();
    format!("{}…", head.trim_end())
}

fn subject(payload: &Map<String, Value>, event: &str) -> (String, String) {
    if event == "create" || event == "delete" {
        let reference = stripped(payload, "ref");
        if !reference.is_empty() {
            let ref_type = first_truthy_str(Some(payload), &["ref_type"])
                .unwrap_or_default()
                .trim()
                .to_string();
            let ref_type = if ref_type.is_empty() {
                "引用".to_string()
            } else {
                ref_type
            };
            return (clip(&format!("{ref_type} {reference}")), repo_url(payload));
        }
    }

    if event == "gollum"
        && let Some(page) = payload
            .get("pages")
            .and_then(Value::as_array)
            .and_then(|pages| pages.first())
            .and_then(Value::as_object)
    {
        let name = first_truthy_str(Some(page), &["page_name", "title"])
            .unwrap_or_default()
            .trim();
        if !name.is_empty() {
            return (clip(name), url_of(page));
        }
    }

    for (key, fields) in SUBJECT_FIELDS {
        let Some(node) = payload.get(*key).and_then(Value::as_object) else {
            continue;
        };
        for field in *fields {
            let value = node
                .get(*field)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            if !value.is_empty() {
                return (clip(value), url_of(node));
            }
        }
    }
    (String::new(), String::new())
}

fn link_text(label: &str, url: &str) -> String {
    if url.is_empty() {
        label.to_string()
    } else {
        format!("[{label}]({url})")
    }
}

fn action_or_update(action: &str) -> String {
    if action.is_empty() {
        "更新".to_string()
    } else {
        action.to_string()
    }
}

fn lookup<'a>(table: &'a [(&'a str, &'a str)], key: &str) -> Option<&'a str> {
    table
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, value)| *value)
}

fn lookup_action(action: &str) -> Option<String> {
    lookup(PR_ACTIONS, action)
        .or_else(|| lookup(ISSUE_ACTIONS, action))
        .or_else(|| lookup(RELEASE_ACTIONS, action))
        .or_else(|| lookup(EXTRA_ACTION_LABELS, action))
        .map(str::to_string)
}

fn object_field<'a>(payload: &'a Map<String, Value>, key: &str) -> Option<&'a Map<String, Value>> {
    payload.get(key).and_then(Value::as_object)
}

fn raw_str<'a>(payload: &'a Map<String, Value>, key: &str) -> &'a str {
    payload.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn stripped(payload: &Map<String, Value>, key: &str) -> String {
    raw_str(payload, key).trim().to_string()
}

fn stripped_map(map: Option<&Map<String, Value>>, key: &str) -> String {
    map.and_then(|map| map.get(key))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn first_truthy_str<'a>(map: Option<&'a Map<String, Value>>, keys: &[&str]) -> Option<&'a str> {
    let map = map?;
    keys.iter()
        .filter_map(|key| map.get(*key))
        .find(|value| truthy(value))
        .and_then(Value::as_str)
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// 近似 Python `str(value)`，用于标题里的数字编号。
fn value_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Null => "None".to_string(),
        other => other.to_string(),
    }
}

fn take_chars(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse(payload: serde_json::Value, event: &str) -> Result<UnifiedMessage, AdapterError> {
        GitHubAdapter::new().parse(&payload, event)
    }

    #[test]
    fn ping_reports_repository_and_zen() {
        let message = parse(
            json!({
                "repository": {"full_name": "o/r"},
                "zen": "非机器人"
            }),
            "ping",
        )
        .expect("解析成功");
        assert_eq!(message.fmt, FMT_MARKDOWN);
        assert_eq!(message.title.as_deref(), Some("GitHub Webhook 接入成功"));
        assert_eq!(message.body, "Webhook 已接入仓库 o/r\n\n非机器人");
        assert_eq!(message.source_msgtype, "ping");
    }

    #[test]
    fn push_limits_commits_and_appends_compare_link() {
        let message = parse(
            json!({
                "ref": "refs/heads/main",
                "forced": true,
                "compare": "https://github.com/o/r/compare/a...b",
                "repository": {"full_name": "o/r"},
                "sender": {"login": "alice"},
                "commits": [
                    {"id": "abcdef1234567", "message": "fix: 修复\n\n详情", "author": {"name": "Alice"}},
                    {"id": "1234567890abc", "message": "docs: 文档"},
                    {"id": "c3", "message": "c3"},
                    {"id": "c4", "message": "c4"},
                    {"id": "c5", "message": "c5"},
                    {"id": "c6", "message": "c6"}
                ]
            }),
            "push",
        )
        .expect("解析成功");
        assert_eq!(message.title.as_deref(), Some("o/r 推送 main"));
        assert_eq!(
            message.body,
            "**alice** 推送了 6 个提交到 `main`（强制推送）\n\
             - `abcdef1` fix: 修复 — Alice\n\
             - `1234567` docs: 文档\n\
             - `c3` c3\n\
             - `c4` c4\n\
             - `c5` c5\n\
             - …另有 1 条提交\n\n\
             [查看对比](https://github.com/o/r/compare/a...b)"
        );
    }

    #[test]
    fn deleted_branch_push_has_dedicated_message() {
        let message = parse(
            json!({
                "ref": "refs/heads/feature",
                "deleted": true,
                "repository": {"full_name": "o/r"},
                "sender": {"login": "alice"}
            }),
            "push",
        )
        .expect("解析成功");
        assert_eq!(message.title.as_deref(), Some("o/r 删除分支"));
        assert_eq!(message.body, "**alice** 删除了 `feature`");
        assert_eq!(message.source_msgtype, "push");
    }

    #[test]
    fn merged_pull_request_uses_merger_and_label() {
        let message = parse(
            json!({
                "action": "closed",
                "number": 7,
                "pull_request": {
                    "number": 7,
                    "title": " 新功能 ",
                    "html_url": "https://github.com/o/r/pull/7",
                    "merged": true,
                    "merged_by": {"login": "bob"}
                },
                "repository": {"full_name": "o/r"},
                "sender": {"login": "alice"}
            }),
            "pull_request",
        )
        .expect("解析成功");
        assert_eq!(message.title.as_deref(), Some("o/r PR #7"));
        assert_eq!(
            message.body,
            "**bob** 合并：[新功能](https://github.com/o/r/pull/7)"
        );
        assert_eq!(message.source_msgtype, "pull_request.closed");
    }

    #[test]
    fn issues_use_action_labels() {
        let message = parse(
            json!({
                "action": "opened",
                "issue": {
                    "number": 3,
                    "title": "Bug",
                    "html_url": "https://github.com/o/r/issues/3"
                },
                "repository": {"full_name": "o/r"},
                "sender": {"login": "alice"}
            }),
            "issues",
        )
        .expect("解析成功");
        assert_eq!(message.title.as_deref(), Some("o/r Issue #3"));
        assert_eq!(
            message.body,
            "**alice** 打开：[Bug](https://github.com/o/r/issues/3)"
        );
        assert_eq!(message.source_msgtype, "issues.opened");
    }

    #[test]
    fn release_truncates_notes_after_500_chars() {
        let notes = "a".repeat(600);
        let message = parse(
            json!({
                "action": "published",
                "release": {
                    "tag_name": "v1.0.0",
                    "name": "v1.0.0",
                    "html_url": "https://github.com/o/r/releases/tag/v1.0.0",
                    "body": notes
                },
                "repository": {"full_name": "o/r"},
                "sender": {"login": "alice"}
            }),
            "release",
        )
        .expect("解析成功");
        assert_eq!(message.title.as_deref(), Some("o/r Release v1.0.0"));
        assert_eq!(
            message.body,
            format!(
                "**alice** 发布：[v1.0.0](https://github.com/o/r/releases/tag/v1.0.0)\n\n{}…",
                "a".repeat(500)
            )
        );
        assert_eq!(message.source_msgtype, "release.published");
    }

    #[test]
    fn workflow_run_only_accepts_completed() {
        let ignored = parse(
            json!({"action": "requested", "workflow_run": {"name": "CI"}}),
            "workflow_run",
        )
        .expect_err("非 completed 应忽略");
        assert!(ignored.is_ignored());
        assert_eq!(
            ignored.to_string(),
            "workflow_run 仅推送 completed：requested"
        );

        let message = parse(
            json!({
                "action": "completed",
                "workflow_run": {
                    "name": "CI",
                    "conclusion": "failure",
                    "head_branch": "main",
                    "html_url": "https://github.com/o/r/actions/runs/1"
                },
                "repository": {"full_name": "o/r"}
            }),
            "workflow_run",
        )
        .expect("解析成功");
        assert_eq!(message.title.as_deref(), Some("o/r 工作流 CI 失败"));
        assert_eq!(
            message.body,
            "分支 `main` 运行失败\n\n[查看运行](https://github.com/o/r/actions/runs/1)"
        );
        assert_eq!(message.source_msgtype, "workflow_run.completed");
    }

    #[test]
    fn workflow_job_uses_conclusion_label() {
        let message = parse(
            json!({
                "action": "completed",
                "workflow_job": {
                    "name": "build",
                    "conclusion": "success",
                    "head_branch": "main",
                    "html_url": "https://github.com/o/r/actions/runs/2/job/3"
                },
                "repository": {"full_name": "o/r"}
            }),
            "workflow_job",
        )
        .expect("解析成功");
        assert_eq!(message.title.as_deref(), Some("o/r 工作流任务 build 成功"));
        assert_eq!(
            message.body,
            "分支 `main` 任务成功\n\n[查看运行](https://github.com/o/r/actions/runs/2/job/3)"
        );
        assert_eq!(message.source_msgtype, "workflow_job.completed");
    }

    #[test]
    fn generic_create_event_uses_subject_and_repo_url() {
        let message = parse(
            json!({
                "ref": "v1.0.0",
                "ref_type": "tag",
                "repository": {"full_name": "o/r", "html_url": "https://github.com/o/r"},
                "sender": {"login": "alice"}
            }),
            "create",
        )
        .expect("解析成功");
        assert_eq!(message.title.as_deref(), Some("o/r 创建引用"));
        assert_eq!(
            message.body,
            "**alice** 触发了创建引用事件：[tag v1.0.0](https://github.com/o/r)"
        );
        assert_eq!(message.source_msgtype, "create");
    }

    #[test]
    fn generic_event_appends_repo_link_when_subject_has_no_url() {
        let message = parse(
            json!({
                "action": "created",
                "repository": {"full_name": "o/r", "html_url": "https://github.com/o/r"},
                "sender": {"login": "alice"}
            }),
            "star",
        )
        .expect("解析成功");
        assert_eq!(message.title.as_deref(), Some("o/r Star"));
        assert_eq!(
            message.body,
            "**alice** 创建\n\n[查看仓库](https://github.com/o/r)"
        );
        assert_eq!(message.source_msgtype, "star.created");
    }

    #[test]
    fn missing_event_or_invalid_payload_is_rejected() {
        assert_eq!(
            parse(json!({"repository": {}}), "  ")
                .unwrap_err()
                .to_string(),
            "缺少 X-GitHub-Event 请求头"
        );
        assert_eq!(
            parse(json!([]), "ping").unwrap_err().to_string(),
            "负载必须是 JSON 对象"
        );
    }
}
