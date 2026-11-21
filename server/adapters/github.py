"""GitHub Webhook 负载解析。

官方文档：
- 事件与负载：https://docs.github.com/en/webhooks/webhook-events-and-payloads
- 签名校验：https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries

事件类型来自 `X-GitHub-Event` 请求头而不是负载本身，因此 parse 需要 event 参数。
常见事件使用专门格式，其余事件使用通用格式，确保所有事件类型都会生成消息。
"""

from __future__ import annotations

from server.adapters.base import (
    FMT_MARKDOWN,
    IgnoredEvent,
    PayloadError,
    UnifiedMessage,
)

_PUSH_COMMIT_LIMIT = 5
_RELEASE_NOTES_LIMIT = 500

_PR_ACTIONS = {
    "opened": "打开",
    "closed": "关闭",
    "reopened": "重新打开",
    "ready_for_review": "标记为可评审",
    "synchronize": "更新了提交",
    "review_requested": "请求评审",
    "review_request_removed": "撤销评审请求",
    "edited": "编辑",
    "labeled": "添加标签",
    "unlabeled": "移除标签",
}

_ISSUE_ACTIONS = {
    "opened": "打开",
    "closed": "关闭",
    "reopened": "重新打开",
    "edited": "编辑",
    "assigned": "指派",
    "unassigned": "取消指派",
    "labeled": "添加标签",
    "unlabeled": "移除标签",
    "milestoned": "设置里程碑",
    "demilestoned": "移除里程碑",
}

_RELEASE_ACTIONS = {
    "published": "发布",
    "created": "创建",
    "edited": "编辑",
    "prereleased": "预发布",
    "released": "发布",
    "unpublished": "取消发布",
    "deleted": "删除",
}

_CONCLUSIONS = {
    "success": "成功",
    "failure": "失败",
    "cancelled": "已取消",
    "skipped": "已跳过",
    "timed_out": "超时",
    "action_required": "需要处理",
    "neutral": "中性",
    "stale": "过期",
}

_WORKFLOW_STATUS = {
    "queued": "排队中",
    "in_progress": "进行中",
    "pending": "等待中",
    "waiting": "等待中",
    "requested": "已请求",
    "completed": "已完成",
}

_ACTION_LABELS = {
    **_PR_ACTIONS,
    **_ISSUE_ACTIONS,
    **_RELEASE_ACTIONS,
    "created": "创建",
    "deleted": "删除",
    "updated": "更新",
    "added": "添加",
    "removed": "移除",
    "completed": "完成",
    "in_progress": "进行中",
    "queued": "排队中",
    "waiting": "等待中",
    "requested": "请求",
    "rerequested": "重新请求",
    "submitted": "提交",
    "dismissed": "驳回",
    "approved": "通过",
    "changes_requested": "请求修改",
    "commented": "评论",
    "resolved": "已解决",
    "unresolved": "未解决",
    "started": "开始",
    "stopped": "停止",
    "granted": "授权",
    "revoked": "撤销",
    "transferred": "转移",
    "renamed": "重命名",
    "archived": "归档",
    "unarchived": "取消归档",
    "publicized": "设为公开",
    "privatized": "设为私有",
    "pinned": "置顶",
    "unpinned": "取消置顶",
    "locked": "锁定",
    "unlocked": "解锁",
}

# 事件展示名；未列出的新事件直接使用 X-GitHub-Event 原值。
_EVENT_LABELS = {
    "branch_protection_configuration": "分支保护配置",
    "branch_protection_rule": "分支保护规则",
    "check_run": "检查运行",
    "check_suite": "检查套件",
    "code_scanning_alert": "代码扫描告警",
    "commit_comment": "提交评论",
    "create": "创建引用",
    "custom_property": "自定义属性",
    "custom_property_values": "自定义属性值",
    "delete": "删除引用",
    "dependabot_alert": "Dependabot 告警",
    "deploy_key": "部署密钥",
    "deployment": "部署",
    "deployment_protection_rule": "部署保护规则",
    "deployment_review": "部署评审",
    "deployment_status": "部署状态",
    "discussion": "讨论",
    "discussion_comment": "讨论评论",
    "fork": "Fork",
    "github_app_authorization": "GitHub App 授权",
    "gollum": "Wiki 页面",
    "installation": "App 安装",
    "installation_repositories": "App 仓库变更",
    "installation_target": "App 安装目标",
    "issue_comment": "Issue 评论",
    "issue_dependencies": "Issue 依赖",
    "issue_relates_to": "Issue 关联",
    "issues": "Issue",
    "label": "标签",
    "marketplace_purchase": "Marketplace 购买",
    "member": "成员",
    "membership": "成员关系",
    "merge_group": "合并组",
    "meta": "Meta",
    "milestone": "里程碑",
    "org_block": "组织封禁",
    "organization": "组织",
    "package": "包",
    "page_build": "Pages 构建",
    "personal_access_token_request": "个人访问令牌请求",
    "ping": "Ping",
    "project": "项目",
    "project_card": "项目卡片",
    "project_column": "项目列",
    "projects_v2": "项目",
    "projects_v2_item": "项目条目",
    "projects_v2_status_update": "项目状态更新",
    "public": "仓库公开",
    "pull_request": "Pull Request",
    "pull_request_review": "PR 评审",
    "pull_request_review_comment": "PR 评审评论",
    "pull_request_review_thread": "PR 评审线程",
    "push": "推送",
    "registry_package": "注册表包",
    "release": "Release",
    "repository": "仓库",
    "repository_advisory": "仓库安全公告",
    "repository_dispatch": "仓库分发",
    "repository_import": "仓库导入",
    "repository_ruleset": "仓库规则集",
    "repository_vulnerability_alert": "仓库漏洞告警",
    "secret_scanning_alert": "密钥扫描告警",
    "secret_scanning_alert_location": "密钥扫描位置",
    "secret_scanning_scan": "密钥扫描",
    "security_advisory": "安全公告",
    "security_and_analysis": "安全与分析",
    "sponsorship": "赞助",
    "star": "Star",
    "status": "提交状态",
    "sub_issues": "子 Issue",
    "team": "团队",
    "team_add": "团队添加",
    "watch": "Watch",
    "workflow_dispatch": "工作流手动触发",
    "workflow_job": "工作流任务",
    "workflow_run": "工作流运行",
}

# 通用格式从负载中提取可读主体与链接的候选字段。
_SUBJECT_FIELDS = {
    "pull_request": ("title",),
    "issue": ("title",),
    "release": ("name", "tag_name"),
    "discussion": ("title",),
    "comment": ("body",),
    "check_run": ("name",),
    "check_suite": ("head_branch",),
    "workflow_run": ("name",),
    "workflow_job": ("name",),
    "deployment": ("environment", "description"),
    "deployment_status": ("description", "state"),
    "forkee": ("full_name",),
    "member": ("login",),
    "organization": ("login",),
    "team": ("name",),
    "project": ("name",),
    "projects_v2": ("title",),
    "projects_v2_item": ("title", "name"),
    "package": ("name",),
    "registry_package": ("name",),
    "security_advisory": ("summary",),
    "repository_advisory": ("summary",),
    "secret_scanning_alert": ("secret_type_display_name",),
}

_SUBJECT_LIMIT = 80


class GitHubAdapter:
    platform = "github"

    def parse(self, payload: dict, *, event: str = "") -> UnifiedMessage:
        if not isinstance(payload, dict):
            raise PayloadError("负载必须是 JSON 对象")
        event = (event or "").strip().lower()
        if not event:
            raise PayloadError("缺少 X-GitHub-Event 请求头")
        handler = {
            "ping": self._ping,
            "push": self._push,
            "pull_request": self._pull_request,
            "issues": self._issues,
            "release": self._release,
            "workflow_job": self._workflow_job,
            "workflow_run": self._workflow_run,
        }.get(event)
        if handler is not None:
            return handler(payload, event)
        return self._generic(payload, event)

    # -- 事件 ---------------------------------------------------------------

    def _ping(self, payload: dict, event: str) -> UnifiedMessage:
        repo = _repo(payload)
        zen = (payload.get("zen") or "").strip()
        body = f"Webhook 已接入仓库 {repo}" if repo else "Webhook 已接入"
        if zen:
            body += f"\n\n{zen}"
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            title="GitHub Webhook 接入成功",
            body=body,
            source_msgtype=event,
        )

    def _push(self, payload: dict, event: str) -> UnifiedMessage:
        repo = _repo(payload)
        branch = _short_ref(payload.get("ref") or "")
        actor = _actor(payload) or (payload.get("pusher") or {}).get("name") or "未知用户"
        commits = payload.get("commits") or []

        if payload.get("deleted"):
            return UnifiedMessage(
                fmt=FMT_MARKDOWN,
                title=f"{repo} 删除分支",
                body=f"**{actor}** 删除了 `{branch}`",
                source_msgtype=event,
            )

        lines: list[str] = []
        for commit in commits[:_PUSH_COMMIT_LIMIT]:
            sha = (commit.get("id") or "")[:7]
            message = (commit.get("message") or "").split("\n", 1)[0].strip()
            author = ((commit.get("author") or {}).get("name") or "").strip()
            item = f"- `{sha}` {message}" if sha else f"- {message}"
            if author:
                item += f" — {author}"
            lines.append(item)
        if len(commits) > _PUSH_COMMIT_LIMIT:
            lines.append(f"- …另有 {len(commits) - _PUSH_COMMIT_LIMIT} 条提交")

        head = f"**{actor}** 推送了 {len(commits)} 个提交到 `{branch}`"
        if payload.get("created"):
            head += "（新建分支）"
        if payload.get("forced"):
            head += "（强制推送）"
        body = "\n".join([head, *lines])
        compare = (payload.get("compare") or "").strip()
        if compare:
            body += f"\n\n[查看对比]({compare})"
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            title=f"{repo} 推送 {branch}",
            body=body,
            source_msgtype=event,
        )

    def _pull_request(self, payload: dict, event: str) -> UnifiedMessage:
        action = (payload.get("action") or "").strip()
        pr = payload.get("pull_request") or {}
        repo = _repo(payload)
        actor = _actor(payload)
        number = pr.get("number") or payload.get("number") or ""
        title_text = (pr.get("title") or "").strip() or "（无标题）"
        url = (pr.get("html_url") or "").strip()

        if action == "closed" and pr.get("merged"):
            label = "合并"
            actor = ((pr.get("merged_by") or {}).get("login") or "").strip() or actor
        else:
            label = _PR_ACTIONS.get(action, action or "更新")

        link = f"[{title_text}]({url})" if url else title_text
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            title=f"{repo} PR #{number}",
            body=f"**{actor}** {label}：{link}",
            source_msgtype=f"pull_request.{action or 'unknown'}",
        )

    def _issues(self, payload: dict, event: str) -> UnifiedMessage:
        action = (payload.get("action") or "").strip()
        issue = payload.get("issue") or {}
        repo = _repo(payload)
        actor = _actor(payload)
        number = issue.get("number") or payload.get("number") or ""
        title_text = (issue.get("title") or "").strip() or "（无标题）"
        url = (issue.get("html_url") or "").strip()
        label = _ISSUE_ACTIONS.get(action, action or "更新")

        link = f"[{title_text}]({url})" if url else title_text
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            title=f"{repo} Issue #{number}",
            body=f"**{actor}** {label}：{link}",
            source_msgtype=f"issues.{action or 'unknown'}",
        )

    def _release(self, payload: dict, event: str) -> UnifiedMessage:
        action = (payload.get("action") or "").strip()
        release = payload.get("release") or {}
        repo = _repo(payload)
        actor = _actor(payload)
        tag = (release.get("tag_name") or release.get("name") or "").strip() or "未知标签"
        name = (release.get("name") or tag).strip()
        url = (release.get("html_url") or "").strip()
        label = _RELEASE_ACTIONS.get(action, action or "更新")

        link = f"[{name}]({url})" if url else name
        body = f"**{actor}** {label}：{link}"
        notes = (release.get("body") or "").strip()
        if notes:
            if len(notes) > _RELEASE_NOTES_LIMIT:
                notes = notes[:_RELEASE_NOTES_LIMIT].rstrip() + "…"
            body += f"\n\n{notes}"
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            title=f"{repo} Release {tag}",
            body=body,
            source_msgtype=f"release.{action or 'unknown'}",
        )

    def _workflow_run(self, payload: dict, event: str) -> UnifiedMessage:
        action = (payload.get("action") or "").strip()
        if action != "completed":
            raise IgnoredEvent(f"workflow_run 仅推送 completed：{action}")
        run = payload.get("workflow_run") or {}
        repo = _repo(payload)
        name = (run.get("name") or "工作流").strip()
        conclusion = (run.get("conclusion") or "unknown").strip()
        label = _CONCLUSIONS.get(conclusion, conclusion)
        branch = (run.get("head_branch") or "").strip()
        url = (run.get("html_url") or "").strip()

        body = f"分支 `{branch}` 运行{label}" if branch else f"运行{label}"
        if url:
            body += f"\n\n[查看运行]({url})"
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            title=f"{repo} 工作流 {name} {label}",
            body=body,
            source_msgtype="workflow_run.completed",
        )

    def _workflow_job(self, payload: dict, event: str) -> UnifiedMessage:
        action = (payload.get("action") or "").strip()
        job = payload.get("workflow_job") or {}
        repo = _repo(payload)
        name = (job.get("name") or "任务").strip()
        conclusion = (job.get("conclusion") or "").strip()
        status = (job.get("status") or "").strip()
        if conclusion:
            label = _CONCLUSIONS.get(conclusion, conclusion)
        else:
            label = _WORKFLOW_STATUS.get(status or action, action or "更新")
        branch = (job.get("head_branch") or "").strip()
        url = (job.get("html_url") or "").strip()

        body = f"分支 `{branch}` 任务{label}" if branch else f"任务{label}"
        if url:
            body += f"\n\n[查看运行]({url})"
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            title=f"{repo} 工作流任务 {name} {label}".strip(),
            body=body,
            source_msgtype=f"workflow_job.{action}" if action else "workflow_job",
        )

    def _generic(self, payload: dict, event: str) -> UnifiedMessage:
        """未专门格式化的 GitHub 事件；保证任何 X-GitHub-Event 都有输出。"""
        repo = _repo(payload)
        actor = _actor(payload)
        action = (payload.get("action") or "").strip()
        label = _EVENT_LABELS.get(event, event)
        action_text = _ACTION_LABELS.get(action, action)
        subject, url = _subject(payload, event)

        body = (
            f"**{actor}** {action_text}"
            if action_text
            else f"**{actor}** 触发了{label}事件"
        )
        if subject:
            link = f"[{subject}]({url})" if url else subject
            body += f"：{link}"
        repo_url = _repo_url(payload)
        if not url and repo_url:
            body += f"\n\n[查看仓库]({repo_url})"

        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            title=(f"{repo} {label}" if repo else f"GitHub {label}"),
            body=body,
            source_msgtype=f"{event}.{action}" if action else event,
        )


# -- 工具 -------------------------------------------------------------------


def _repo(payload: dict) -> str:
    repo = payload.get("repository") or {}
    return (repo.get("full_name") or repo.get("name") or "").strip()


def _actor(payload: dict) -> str:
    sender = payload.get("sender") or {}
    return (sender.get("login") or "").strip() or "未知用户"


def _short_ref(ref: str) -> str:
    for prefix in ("refs/heads/", "refs/tags/"):
        if ref.startswith(prefix):
            return ref[len(prefix) :]
    return ref or "未知引用"


def _repo_url(payload: dict) -> str:
    repo = payload.get("repository")
    return _url_of(repo) if isinstance(repo, dict) else ""


def _url_of(node: dict) -> str:
    for key in ("html_url", "target_url", "url"):
        value = node.get(key)
        if isinstance(value, str) and value.strip().startswith(("http://", "https://")):
            return value.strip()
    return ""


def _clip(text: str) -> str:
    flat = " ".join(text.split())
    if len(flat) <= _SUBJECT_LIMIT:
        return flat
    return flat[: _SUBJECT_LIMIT - 1].rstrip() + "…"


def _subject(payload: dict, event: str) -> tuple[str, str]:
    """从负载中取一个可读主体与链接；取不到时返回空串。"""
    if event in ("create", "delete"):
        ref = (payload.get("ref") or "").strip()
        if ref:
            ref_type = (payload.get("ref_type") or "引用").strip()
            return _clip(f"{ref_type} {ref}"), _repo_url(payload)

    if event == "gollum":
        pages = payload.get("pages")
        if isinstance(pages, list) and pages and isinstance(pages[0], dict):
            page = pages[0]
            name = (page.get("page_name") or page.get("title") or "").strip()
            if name:
                return _clip(name), _url_of(page)

    for key, fields in _SUBJECT_FIELDS.items():
        node = payload.get(key)
        if not isinstance(node, dict):
            continue
        for field in fields:
            value = node.get(field)
            if isinstance(value, str) and value.strip():
                return _clip(value), _url_of(node)
    return "", ""
