//! 集成测试共用辅助。
//!
//! 各套件读写的是同一批全局表（系统设置、推送队列、引导写入的账号与机器人），
//! `cargo test` 会依次启动多个套件进程：共用一个库时，前一个套件留下的行会被
//! 后一个套件的清库步骤或外键约束撞上（如 `admin_audit_logs` 引用 `users`）。
//!
//! 这里统一按套件固定库名：`MYSQL_URL` 只提供服务器与凭据，库名由各套件自己
//! 指定，与 CI 里「每个套件一个独立数据库」的约定一致。

/// 把连接串里的库名换成 `suite_db`，其余部分原样保留。
///
/// 连接串形如 `mysql://user:pass@host:port/db?opts`：库名是主机之后的第一段
/// 路径，查询参数原样保留；没有路径时按新增库名处理。
pub fn with_database(url: &str, suite_db: &str) -> String {
    let (server, query) = match url.split_once('?') {
        Some((head, query)) => (head, Some(query)),
        None => (url, None),
    };
    // 主机之后的第一段 '/' 才是路径起点，避开 `mysql://` 里的斜杠。
    let authority_end = server.find("://").map_or(0, |index| index + 3);
    let server = match server[authority_end..].find('/') {
        Some(offset) => &server[..authority_end + offset],
        None => server,
    };
    match query {
        Some(query) => format!("{server}/{suite_db}?{query}"),
        None => format!("{server}/{suite_db}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_database_name() {
        assert_eq!(
            with_database("mysql://u:p@127.0.0.1:3306/shared", "qbot_test_admin"),
            "mysql://u:p@127.0.0.1:3306/qbot_test_admin"
        );
    }

    #[test]
    fn keeps_query_string() {
        assert_eq!(
            with_database(
                "mysql://u:p@127.0.0.1:3306/shared?ssl-mode=disabled",
                "qbot_test_webhook"
            ),
            "mysql://u:p@127.0.0.1:3306/qbot_test_webhook?ssl-mode=disabled"
        );
    }

    #[test]
    fn appends_database_when_missing() {
        assert_eq!(
            with_database("mysql://u:p@127.0.0.1:3306", "qbot_test_bootstrap"),
            "mysql://u:p@127.0.0.1:3306/qbot_test_bootstrap"
        );
    }
}
