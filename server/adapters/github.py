"""GitHub Webhook 负载解析。

官方文档：
- 事件与负载：https://docs.github.com/en/webhooks/webhook-events-and-payloads
- 签名校验：https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries

事件类型来自 `X-GitHub-Event` 请求头而不是负载本身，因此 parse 需要 event 参数。
未订阅的事件抛 IgnoredEvent，调用方按成功确认但不推送。
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
            "workflow_run": self._workflow_run,
        }.get(event)
        if handler is None:
            raise IgnoredEvent(f"未订阅的 GitHub 事件：{event}")
        return handler(payload, event)

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
