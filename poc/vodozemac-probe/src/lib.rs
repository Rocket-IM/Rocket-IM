//! 隔离的密码库机制探针，不包含业务身份验证、网络或持久化事务。
//! 公钥/群密钥直接传递只是可信测试装置，不代表完整设备授权已经实现。

use vodozemac::{
    megolm::{GroupSession, InboundGroupSession, MegolmMessage},
    olm::{Account, OlmMessage, Session, SessionConfig, SessionPickle},
};

type ProbeResult<T> = Result<T, String>;

fn require(condition: bool, message: &str) -> ProbeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn olm_sessions() -> ProbeResult<(Session, Session)> {
    let alice = Account::new();
    let mut bob = Account::new();
    bob.generate_one_time_keys(1);
    let key = bob
        .one_time_keys()
        .values()
        .next()
        .copied()
        .ok_or("未生成一次性公钥")?;
    let mut sender = alice
        .create_outbound_session(SessionConfig::version_1(), bob.curve25519_key(), key)
        .map_err(|e| format!("建立发送会话失败: {e}"))?;
    bob.mark_keys_as_published();
    let first = sender
        .encrypt(b"synthetic offline first message")
        .map_err(|e| format!("首条加密失败: {e}"))?;
    let OlmMessage::PreKey(first) = first else {
        return Err("首条消息不是 PreKey 消息".to_owned());
    };
    let result = bob
        .create_inbound_session(SessionConfig::version_1(), alice.curve25519_key(), &first)
        .map_err(|e| format!("建立接收会话失败: {e}"))?;
    require(
        result.plaintext == b"synthetic offline first message",
        "离线首条内容不一致",
    )?;
    Ok((sender, result.session))
}

fn olm_roundtrip_and_reorder() -> ProbeResult<()> {
    let (mut alice, mut bob) = olm_sessions()?;
    let reply = bob
        .encrypt(b"synthetic reply")
        .map_err(|e| format!("回复加密失败: {e}"))?;
    require(
        alice.decrypt(&reply).map_err(|e| e.to_string())? == b"synthetic reply",
        "回复不一致",
    )?;
    let first = alice.encrypt(b"message one").map_err(|e| e.to_string())?;
    let second = alice.encrypt(b"message two").map_err(|e| e.to_string())?;
    require(
        bob.decrypt(&second).map_err(|e| e.to_string())? == b"message two",
        "乱序第二条失败",
    )?;
    require(
        bob.decrypt(&first).map_err(|e| e.to_string())? == b"message one",
        "乱序第一条失败",
    )?;
    require(
        bob.decrypt(&first).is_err(),
        "Olm 已消费消息密钥仍被重复使用",
    )
}

fn olm_encrypted_snapshot() -> ProbeResult<()> {
    let (mut alice, mut bob) = olm_sessions()?;
    let mut key = [0_u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| format!("随机数失败: {e}"))?;
    let encrypted = alice.pickle().encrypt(&key);
    let wrong_key = [0_u8; 32];
    require(
        SessionPickle::from_encrypted(&encrypted, &wrong_key).is_err(),
        "错误密钥解开快照",
    )?;
    let pickle = SessionPickle::from_encrypted(&encrypted, &key)
        .map_err(|e| format!("加密快照解码失败: {e}"))?;
    // 原会话不再发送，避免把恢复成两个发送实例误当成正常使用方式。
    drop(alice);
    alice = Session::from_pickle(pickle);
    let message = alice
        .encrypt(b"after snapshot")
        .map_err(|e| e.to_string())?;
    require(
        bob.decrypt(&message).map_err(|e| e.to_string())? == b"after snapshot",
        "恢复后收发失败",
    )
}

fn megolm_rotation_boundary() -> ProbeResult<()> {
    let mut old_sender = GroupSession::new(Default::default());
    let old_key = old_sender.session_key();
    let mut bob_old = InboundGroupSession::new(&old_key, Default::default());
    let mut removed = InboundGroupSession::new(&old_key, Default::default());
    let before = old_sender.encrypt(b"before membership change");
    require(
        bob_old
            .decrypt(&before)
            .map_err(|e| e.to_string())?
            .plaintext
            == b"before membership change",
        "群消息初始失败",
    )?;
    require(
        removed.decrypt(&before).is_ok(),
        "旧成员测试前未持有有效密钥",
    )?;
    // 反例：仅推进原会话并不能排除持有旧状态的成员。
    let still_old = old_sender.encrypt(b"same session after removal flag");
    require(
        removed.decrypt(&still_old).is_ok(),
        "未复现同会话仍可解密的边界",
    )?;

    // 仅向保留者交付新会话密钥；真实系统还必须实现可验证授权及安全分发。
    let mut new_sender = GroupSession::new(Default::default());
    let mut retained = InboundGroupSession::new(&new_sender.session_key(), Default::default());
    let after = new_sender.encrypt(b"new independent sender session");
    require(removed.decrypt(&after).is_err(), "旧会话可解开新会话密文")?;
    require(
        retained
            .decrypt(&after)
            .map_err(|e| e.to_string())?
            .plaintext
            == b"new independent sender session",
        "保留者不能解密新会话",
    )?;
    // Megolm 解密 API 不承担 IM 展示去重，明确验证该行为而非宣称自动防重放。
    require(
        retained.decrypt(&after).is_ok(),
        "需重新核查 Megolm 重复密文行为",
    )
}

fn megolm_tamper() -> ProbeResult<()> {
    let mut sender = GroupSession::new(Default::default());
    let mut receiver = InboundGroupSession::new(&sender.session_key(), Default::default());
    let message = sender.encrypt(b"tamper fixture");
    let mut bytes = message.to_bytes();
    let last = bytes.last_mut().ok_or("密文为空")?;
    *last ^= 1;
    if let Ok(corrupted) = MegolmMessage::from_bytes(&bytes) {
        require(receiver.decrypt(&corrupted).is_err(), "篡改密文被接受")?;
    }
    require(
        receiver
            .decrypt(&message)
            .map_err(|e| e.to_string())?
            .plaintext
            == b"tamper fixture",
        "失败后有效消息不能解密",
    )
}

/// 运行全部本地机制探针；只返回固定结果，不输出明文、密钥或快照。
pub fn run_smoke() -> ProbeResult<String> {
    olm_roundtrip_and_reorder()?;
    olm_encrypted_snapshot()?;
    megolm_rotation_boundary()?;
    megolm_tamper()?;
    Ok("PASS vodozemac 0.10.0: olm-offline-reorder-replay; encrypted-snapshot; megolm-rotation-and-replay-boundary; tamper".to_owned())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn run_browser_smoke() -> Result<String, wasm_bindgen::JsValue> {
    run_smoke().map_err(|e| wasm_bindgen::JsValue::from_str(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_roundtrip_reorder_and_replay() -> ProbeResult<()> {
        olm_roundtrip_and_reorder()
    }

    #[test]
    fn encrypted_snapshot_roundtrip_and_wrong_key() -> ProbeResult<()> {
        olm_encrypted_snapshot()
    }

    #[test]
    fn group_rotation_and_replay_boundaries() -> ProbeResult<()> {
        megolm_rotation_boundary()
    }

    #[test]
    fn tamper_rejection_keeps_valid_receive_working() -> ProbeResult<()> {
        megolm_tamper()
    }
}
