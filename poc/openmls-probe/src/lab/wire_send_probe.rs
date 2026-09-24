//! 默认关闭的本机验收计数；不持久化、不参与业务状态，也不统计快照加密。
//! CLI 的一次 execute 同步运行于当前线程；异常终止未输出记录时不能视作零次。

use std::cell::Cell;

thread_local! {
    static CREATE_MESSAGE_CALLS: Cell<u64> = const { Cell::new(0) };
}

/// 清空当前线程的验收计数；仅由实验 CLI 在 execute 前调用。
pub fn reset() {
    CREATE_MESSAGE_CALLS.set(0);
}

/// 返回当前线程自 reset 起的 wire_send create_message 调用次数。
pub fn calls() -> u64 {
    CREATE_MESSAGE_CALLS.get()
}

pub(super) fn record_create_message() {
    CREATE_MESSAGE_CALLS.set(CREATE_MESSAGE_CALLS.get() + 1);
}

#[cfg(test)]
mod tests {
    use super::{calls, record_create_message, reset};
    use crate::lab::wire_tests::Fixture;
    use serde_json::json;

    #[test]
    fn actual_wire_send_counts_once_but_reload_retry_and_conflicts_do_not() {
        reset();
        let fixture = Fixture::new();
        assert_eq!(calls(), 0);
        let original = fixture.send("A", "M1");
        assert_eq!(calls(), 1);
        reset();
        // 每个 call 都经 execute 重新加载快照，复用原尝试不得再调用 MLS 创建。
        let retry = fixture.send("A", "M1");
        assert_eq!(retry["reused"], true);
        assert_eq!(retry["envelope"], original["envelope"]);
        assert_eq!(calls(), 0);
        fixture.fails(
            "A",
            json!({"operation":"wire_send","logical_message_id":"M1",
            "attempt_id":"P1","payload":"changed"}),
            "idempotency_conflict",
        );
        assert_eq!(calls(), 0);
        fixture.fails(
            "A",
            json!({"operation":"wire_send","logical_message_id":"M1",
            "attempt_id":"P2","payload":"synthetic test content"}),
            "attempt_closed",
        );
        assert_eq!(calls(), 0);
    }

    #[test]
    fn legacy_send_and_snapshot_saves_are_not_counted() {
        reset();
        let fixture = Fixture::new();
        fixture.call(
            "A",
            json!({"operation":"send","id":"legacy-message",
            "payload":"synthetic test content"}),
        );
        assert_eq!(calls(), 0);
    }

    #[test]
    fn counts_and_reset_are_thread_local() {
        reset();
        record_create_message();
        std::thread::spawn(|| {
            assert_eq!(calls(), 0);
            record_create_message();
            record_create_message();
            assert_eq!(calls(), 2);
            reset();
            assert_eq!(calls(), 0);
        })
        .join()
        .unwrap();
        assert_eq!(calls(), 1);
        reset();
        assert_eq!(calls(), 0);
    }
}
