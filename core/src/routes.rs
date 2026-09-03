//! 端点路径的**单一来源**（约束 C10 的延伸）
//!
//! # 为什么需要这个模块
//!
//! 路径字符串原本散落在三处：`bin/gen_schema.rs` 的端点清单、`server` 的路由匹配、
//! 各客户端的请求构造。三处各写一遍字面量，于是漂移已经真实发生：
//!
//! | 位置 | 写法 |
//! |---|---|
//! | `V4-ARCHITECTURE.md` §六（**事实源**） | `/api/v4/sync-status`、`/api/v4/unpair` |
//! | `bin/gen_schema.rs` 端点清单 | `/api/v4/sync/status`、`/api/v4/pair/unpair` |
//!
//! 这类漂移的杀伤力和 E6（注释写 xxHash64、常量却是自造的）完全一样：
//! 双端各按各自那份文档实现，联调时 404，而两边的代码"看起来都对"。
//!
//! # 事实源是文档，不是这里
//!
//! 本模块的内容**逐行抄自 `V4-ARCHITECTURE.md` §六 V4 路由表**，包括 HTTP 方法。
//! 顺序也与文档三张表一致（发现与配对 / 传输会话 / 清单与同步）。
//!
//! > 曾经有一版本模块自创了「一律 `/api/v4/<资源>/<动作>`」的规约，
//! > 把文档里的 `/api/v4/sync-status` 改写成 `/api/v4/sync/status`。
//! > 那不是"统一命名"，那是**在两份已有写法之外又造了第三份**——
//! > 恰好是本模块存在的理由所要消灭的东西。
//! > 命名要改可以，但必须**先改文档**，再让这里跟随。
//!
//! [`ALL`] 供 CI 校验"文档清单 = schema 清单 = 服务端实现"。

/// HTTP 方法。只用到这两个，刻意不引 `http::Method`，
/// 让本模块保持零依赖的纯常量表（可被任意端复用，包括未来的非 hyper 实现）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    /// 与 `http::Method::as_str()` 对齐的大写形式
    pub const fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

/// 一条路由（方法 + 路径）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub method: Method,
    pub path: &'static str,
}

// ── 发现与配对（文档 §六 表一）─────────────────────────────────────────
/// GET —— 设备信息 + 静态公钥 + serverNonce + 能力位图 + 在线性 TTL
pub const PROBE: &str = "/api/v4/probe";
/// POST —— 路径 B（重连）：签发 challenge token。**幂等**，带 `requestId`
pub const HANDSHAKE_CHALLENGE: &str = "/api/v4/handshake/challenge";
/// POST —— 路径 A（首配）/ 路径 B：验 HMAC。**幂等**，带 `requestId`
pub const HANDSHAKE_VERIFY: &str = "/api/v4/handshake/verify";
/// GET —— 按 `requestId` 查询握手结果。
///
/// 解决"握手发出去就失联，不知道成没成"：没有这个端点，客户端只能重发，
/// 而重发在非幂等实现上会把已建立的配对又推回中间态。
pub const HANDSHAKE_STATUS: &str = "/api/v4/handshake/status";
/// POST —— 请求解配对（发起方向对端提出）
pub const UNPAIR_REQUEST: &str = "/api/v4/unpair-request";
/// POST —— 解配对通知（ECDSA 签名）
pub const UNPAIR: &str = "/api/v4/unpair";
/// POST —— 吊销通知
pub const REVOKE_NOTIFY: &str = "/api/v4/revoke-notify";
/// POST —— 吊销确认。收到它才能把 `Revoking` 推进到终态
pub const REVOKE_ACK: &str = "/api/v4/revoke-ack";
/// GET —— **双向信任对账**：问的不是"你在吗"，而是"你还认我吗"
pub const SYNC_STATUS: &str = "/api/v4/sync-status";

// ── 传输会话（文档 §六 表二）───────────────────────────────────────────
/// POST —— 会话注册
pub const SESSION_REGISTER: &str = "/api/v4/session/register";
/// POST —— 上传准备，响应带 `X-Capabilities`
pub const SESSION_PREPARE: &str = "/api/v4/session/prepare";
/// POST —— 分块上传
pub const SESSION_CHUNK: &str = "/api/v4/session/chunk";
/// GET —— 块差异探测。**权威块位图来源**，弱+强双校验
pub const SESSION_DIFF: &str = "/api/v4/session/diff";
/// GET —— 整体校验
pub const SESSION_VERIFY: &str = "/api/v4/session/verify";
/// GET —— 查询会话当前 phase（phase 变更需对端 ack，此端点用于对账）
pub const SESSION_PHASE: &str = "/api/v4/session/phase";
/// POST —— 心跳，携带本端 phase 与权威块位图版本号
pub const SESSION_HEARTBEAT: &str = "/api/v4/session/heartbeat";
/// POST —— 中止会话
pub const SESSION_ABORT: &str = "/api/v4/session/abort";
/// POST —— 文件回执。**任务终态由接收端经此端点权威回传**
pub const SESSION_RECEIPT: &str = "/api/v4/session/receipt";
/// GET —— 查询会话内每个文件的终态。解决"双端对任务认知不一致"
pub const SESSION_TASKS: &str = "/api/v4/session/tasks";

// ── 清单与同步（文档 §六 表三）─────────────────────────────────────────
/// GET —— 备份清单
pub const MANIFEST: &str = "/api/v4/manifest";
/// GET —— 块状态查询
pub const CHUNK_STATUS: &str = "/api/v4/chunk-status";
/// POST —— 目录映射同步
pub const SYNC_DIR: &str = "/api/v4/sync-dir";
/// POST —— 移到待删（假删除：移入 `delete/`，不真删）
pub const MOVE_TO_DELETE: &str = "/api/v4/move-to-delete";
/// POST —— 断开连接
pub const DISCONNECT: &str = "/api/v4/disconnect";

/// 全部端点，顺序与文档 §六 三张表一致。
///
/// CI 用它校验"文档清单 = schema 清单 = 服务端实现"。
pub const ALL: &[Route] = &[
    // 发现与配对
    Route {
        method: Method::Get,
        path: PROBE,
    },
    Route {
        method: Method::Post,
        path: HANDSHAKE_CHALLENGE,
    },
    Route {
        method: Method::Post,
        path: HANDSHAKE_VERIFY,
    },
    Route {
        method: Method::Get,
        path: HANDSHAKE_STATUS,
    },
    Route {
        method: Method::Post,
        path: UNPAIR_REQUEST,
    },
    Route {
        method: Method::Post,
        path: UNPAIR,
    },
    Route {
        method: Method::Post,
        path: REVOKE_NOTIFY,
    },
    Route {
        method: Method::Post,
        path: REVOKE_ACK,
    },
    Route {
        method: Method::Get,
        path: SYNC_STATUS,
    },
    // 传输会话
    Route {
        method: Method::Post,
        path: SESSION_REGISTER,
    },
    Route {
        method: Method::Post,
        path: SESSION_PREPARE,
    },
    Route {
        method: Method::Post,
        path: SESSION_CHUNK,
    },
    Route {
        method: Method::Get,
        path: SESSION_DIFF,
    },
    Route {
        method: Method::Get,
        path: SESSION_VERIFY,
    },
    Route {
        method: Method::Get,
        path: SESSION_PHASE,
    },
    Route {
        method: Method::Post,
        path: SESSION_HEARTBEAT,
    },
    Route {
        method: Method::Post,
        path: SESSION_ABORT,
    },
    Route {
        method: Method::Post,
        path: SESSION_RECEIPT,
    },
    Route {
        method: Method::Get,
        path: SESSION_TASKS,
    },
    // 清单与同步
    Route {
        method: Method::Get,
        path: MANIFEST,
    },
    Route {
        method: Method::Get,
        path: CHUNK_STATUS,
    },
    Route {
        method: Method::Post,
        path: SYNC_DIR,
    },
    Route {
        method: Method::Post,
        path: MOVE_TO_DELETE,
    },
    Route {
        method: Method::Post,
        path: DISCONNECT,
    },
];

/// 文档 §六 三张表的端点总数。
///
/// 钉死这个数字，是为了让"偷偷加一个端点而不更新文档"变成一次测试失败。
pub const ROUTE_COUNT: usize = 24;

/// 拼出完整 URL。
///
/// `base` 形如 `http://192.168.1.7:53317`（尾斜杠会被吃掉）；`path` 取本模块常量。
pub fn url(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// 去掉 `/api/v4/` 前缀，返回服务端 match 用的短路径。
///
/// 服务端已经按前缀分流过一次，内部 match 只比短路径，避免每条 arm 重复写前缀。
pub fn strip_prefix(path: &str) -> Option<&str> {
    path.strip_prefix(crate::version::API_PREFIX)?
        .strip_prefix('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::API_PREFIX;
    use std::collections::HashSet;

    #[test]
    fn route_count_is_pinned_to_the_document() {
        assert_eq!(
            ALL.len(),
            ROUTE_COUNT,
            "端点数量与文档 §六 不符：新增/删除端点必须同步 V4-ARCHITECTURE.md §六 路由表"
        );
    }

    #[test]
    fn every_route_lives_under_api_prefix() {
        for r in ALL {
            assert!(
                r.path.starts_with(API_PREFIX),
                "{} 不在 {API_PREFIX} 之下：版本前缀是灰度共存的唯一手段，不得绕过",
                r.path
            );
        }
    }

    #[test]
    fn routes_are_unique() {
        // 同一路径即便方法不同也不允许重复出现两条记录，
        // 否则服务端 match 里必然有一条永远打不到。
        let set: HashSet<_> = ALL.iter().map(|r| r.path).collect();
        assert_eq!(
            set.len(),
            ALL.len(),
            "端点路径重复：同一路径挂两个处理器必然一个永远打不到"
        );
    }

    #[test]
    fn paths_are_lowercase_kebab_without_trailing_slash() {
        for r in ALL {
            let p = r.path;
            assert!(!p.ends_with('/'), "{p} 带尾斜杠：与不带的会被当成两个路由");
            assert_eq!(
                p.to_lowercase().as_str(),
                p,
                "{p} 含大写：路径大小写敏感，必然联调失败"
            );
            assert!(!p.contains('_'), "{p} 用了下划线，规约是连字符");
            assert!(!p.contains(' '), "{p} 含空格");
        }
    }

    /// 读端点必须是 GET、写端点必须是 POST。
    ///
    /// 这不是洁癖：GET 会被代理与客户端库自动重试，把一个写操作放在 GET 上，
    /// 等于默许"网络抖一下就重复执行一次"。
    #[test]
    fn query_endpoints_are_get_and_mutations_are_post() {
        for r in ALL {
            let looks_like_query = matches!(
                r.path,
                PROBE
                    | HANDSHAKE_STATUS
                    | SYNC_STATUS
                    | SESSION_DIFF
                    | SESSION_VERIFY
                    | SESSION_PHASE
                    | SESSION_TASKS
                    | MANIFEST
                    | CHUNK_STATUS
            );
            let expected = if looks_like_query {
                Method::Get
            } else {
                Method::Post
            };
            assert_eq!(
                r.method, expected,
                "{} 的方法不对：查询用 GET、变更用 POST（GET 会被自动重试）",
                r.path
            );
        }
    }

    #[test]
    fn method_strings_match_http_crate_spelling() {
        assert_eq!(Method::Get.as_str(), "GET");
        assert_eq!(Method::Post.as_str(), "POST");
    }

    #[test]
    fn url_joins_without_double_slash() {
        assert_eq!(
            url("http://10.0.0.2:53317/", PROBE),
            "http://10.0.0.2:53317/api/v4/probe"
        );
        assert_eq!(
            url("http://10.0.0.2:53317", PROBE),
            "http://10.0.0.2:53317/api/v4/probe"
        );
    }

    #[test]
    fn strip_prefix_yields_short_paths_for_every_route() {
        for r in ALL {
            let short = strip_prefix(r.path)
                .unwrap_or_else(|| panic!("{} 无法去前缀，说明它不在 {API_PREFIX} 下", r.path));
            assert!(!short.starts_with('/'), "{short} 去前缀后不应再带斜杠");
            assert_eq!(url("", &format!("{API_PREFIX}/{short}")), r.path);
        }
    }

    #[test]
    fn strip_prefix_rejects_foreign_paths() {
        assert_eq!(strip_prefix("/api/v3/probe"), None);
        assert_eq!(strip_prefix("/probe"), None);
        // 前缀相同但不是路径分段边界（`/api/v40/...`）也必须拒绝
        assert_eq!(strip_prefix("/api/v40/probe"), None);
    }
}
