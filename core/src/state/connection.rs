//! 连接状态机（每设备一个实例）
//!
//! **核心不变量：`Connected` 蕴含 `Online`。**
//! 在线性一旦跌到 `Offline`，连接必然被推到 `Lost`（见 `on_presence_drop`），
//! 不存在「已连接但对方离线」这个状态 —— 从定义上堵死，而非靠 UI 判断。
//!
//! 状态：Disconnected / Connecting / Connected / Disconnecting / Lost / Failed
//! （共 10 条迁移，见 V4-TRANSFER-MODULE.md §三）

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    /// 对端在线性跌落导致连接丢失（非主动断开）
    Lost,
    /// 握手/连接建立失败
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IllegalTransition {
    pub from: ConnectionState,
    pub event: &'static str,
    pub reason: &'static str,
}

/// 驱动连接态迁移的事件
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnEvent {
    /// 用户发起连接（仅在 peer online 时由 policy 放行）
    ConnectRequest,
    /// 握手成功
    HandshakeOk,
    /// 握手失败
    HandshakeFailed,
    /// 用户主动断开
    DisconnectRequest,
    /// 清理完成（Disconnecting → Disconnected）
    CleanedUp,
    /// 对端在线性跌落（Presence 进入 Offline）
    PeerPresenceDropped,
    /// 检测到 Lost 后自动复位
    AutoReset,
    /// 重试（从 Failed/Lost 重新发起）
    Retry,
    /// 应用退出 / 强制中止
    ForceAbort,
}

impl ConnectionState {
    /// 尝试迁移。非法迁移返回 `Err(IllegalTransition)`，**绝不静默**。
    pub fn transition(self, ev: ConnEvent) -> Result<Self, IllegalTransition> {
        use ConnectionState::*;
        let next = match (self, ev) {
            (Disconnected, ConnEvent::ConnectRequest) => Connecting,
            (Disconnected, ConnEvent::ForceAbort) => Disconnected,
            (Connecting, ConnEvent::HandshakeOk) => Connected,
            (Connecting, ConnEvent::HandshakeFailed) => Failed,
            (Connecting, ConnEvent::ConnectRequest) => return Err(self.illegal(ev, "已在连接中")),
            (Connecting, ConnEvent::DisconnectRequest) => Disconnected, // 取消连接中
            (Connecting, ConnEvent::ForceAbort) => Disconnected,
            (Connected, ConnEvent::DisconnectRequest) => Disconnecting,
            (Connected, ConnEvent::PeerPresenceDropped) => Lost, // 不变量：connected → online
            (Connected, ConnEvent::ForceAbort) => Disconnected,
            (Connected, ConnEvent::ConnectRequest) => return Err(self.illegal(ev, "已连接")),
            (Disconnecting, ConnEvent::CleanedUp) => Disconnected,
            (Disconnecting, ConnEvent::ForceAbort) => Disconnected,
            (Lost, ConnEvent::AutoReset) => Disconnected,
            (Lost, ConnEvent::Retry) => Connecting,
            (Lost, ConnEvent::ForceAbort) => Disconnected,
            (Failed, ConnEvent::Retry) => Connecting,
            (Failed, ConnEvent::AutoReset) => Disconnected,
            (Failed, ConnEvent::ForceAbort) => Disconnected,
            // 其余所有 (state, event) 组合均非法（含 Disconnected+DisconnectRequest、
            // Connected+AutoReset、Lost+PeerPresenceDropped 等未显式列出的组合）
            _ => return Err(self.illegal(ev, "当前状态不允许该事件")),
        };
        Ok(next)
    }

    fn illegal(self, event: ConnEvent, reason: &'static str) -> IllegalTransition {
        IllegalTransition {
            from: self,
            event: event.name(),
            reason,
        }
    }

    /// 是否可与对端传输（仅 Connected）
    pub fn can_transfer(self) -> bool {
        matches!(self, ConnectionState::Connected)
    }
}

impl ConnEvent {
    pub fn name(self) -> &'static str {
        match self {
            ConnEvent::ConnectRequest => "ConnectRequest",
            ConnEvent::HandshakeOk => "HandshakeOk",
            ConnEvent::HandshakeFailed => "HandshakeFailed",
            ConnEvent::DisconnectRequest => "DisconnectRequest",
            ConnEvent::CleanedUp => "CleanedUp",
            ConnEvent::PeerPresenceDropped => "PeerPresenceDropped",
            ConnEvent::AutoReset => "AutoReset",
            ConnEvent::Retry => "Retry",
            ConnEvent::ForceAbort => "ForceAbort",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path() {
        let s = ConnectionState::Disconnected;
        let s = s.transition(ConnEvent::ConnectRequest).unwrap();
        assert_eq!(s, ConnectionState::Connecting);
        let s = s.transition(ConnEvent::HandshakeOk).unwrap();
        assert_eq!(s, ConnectionState::Connected);
        let s = s.transition(ConnEvent::DisconnectRequest).unwrap();
        assert_eq!(s, ConnectionState::Disconnecting);
        let s = s.transition(ConnEvent::CleanedUp).unwrap();
        assert_eq!(s, ConnectionState::Disconnected);
    }

    #[test]
    fn connected_implies_online_drop_to_lost() {
        let s = ConnectionState::Connected;
        let s = s.transition(ConnEvent::PeerPresenceDropped).unwrap();
        assert_eq!(s, ConnectionState::Lost);
    }

    #[test]
    fn lost_can_retry() {
        let s = ConnectionState::Lost;
        let s = s.transition(ConnEvent::Retry).unwrap();
        assert_eq!(s, ConnectionState::Connecting);
    }

    #[test]
    fn failed_then_retry() {
        let s = ConnectionState::Connecting;
        let s = s.transition(ConnEvent::HandshakeFailed).unwrap();
        assert_eq!(s, ConnectionState::Failed);
        let s = s.transition(ConnEvent::Retry).unwrap();
        assert_eq!(s, ConnectionState::Connecting);
    }

    #[test]
    fn illegal_double_connect_rejected() {
        let s = ConnectionState::Connecting;
        let r = s.transition(ConnEvent::ConnectRequest);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().reason, "已在连接中");
    }

    #[test]
    fn connected_handshake_ok_is_illegal() {
        // 已连接时再收到 HandshakeOk 是异常，必须报错而非静默
        let s = ConnectionState::Connected;
        assert!(s.transition(ConnEvent::HandshakeOk).is_err());
    }

    #[test]
    fn force_abort_from_any_terminalizing() {
        for s in [
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Disconnecting,
            ConnectionState::Lost,
            ConnectionState::Failed,
        ] {
            assert_eq!(
                s.transition(ConnEvent::ForceAbort).unwrap(),
                ConnectionState::Disconnected
            );
        }
    }
}
