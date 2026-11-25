//! 预算设计的实测与反例；观察真实编码/事务，不提供公开诊断或修改准入。
use super::{
    data::{Data, Record, Saved, MAX_DATA},
    journal::{Candidate, Journal, Phase},
    tests::Pair,
    *,
};

// 非E2EE填充：失败记录只用于构造准确字节边界，不冒充密码执行历史。
pub(super) fn pad_data(data: &mut Data, target: usize) {
    let mut size = encode(data).unwrap().len();
    let mut first = None;
    while data.requests.len() < 1024 {
        let key = format!("budget-padding-{}", data.requests.len());
        let mut record = Record {
            hash: "00".repeat(32),
            input: Some(Action::Send {
                message_id: key.clone(),
                text: "x".into(),
            }),
            action: "send".into(),
            result: RequestState::Failed {
                error: Error::new("budget_fixture"),
            },
            rejection: None,
        };
        let overhead = encode(&key).unwrap().len()
            + 1
            + usize::from(!data.requests.is_empty())
            + encode(&record).unwrap().len();
        if size + overhead > target {
            break;
        }
        let extra = (target - size - overhead).min(16383);
        if let Some(Action::Send { text, .. }) = &mut record.input {
            *text = "x".repeat(extra + 1);
        }
        record.hash = hash(&encode(record.input.as_ref().unwrap()).unwrap());
        first.get_or_insert_with(|| key.clone());
        data.requests.insert(key, record);
        size += overhead + extra;
    }
    if let Some(first) = first {
        let slack = target - size;
        assert!(slack < 1024);
        let record = data.requests.get_mut(&first).unwrap();
        if let Some(Action::Send { text, .. }) = &mut record.input {
            text.push_str(&"x".repeat(slack));
        }
        record.hash = hash(&encode(record.input.as_ref().unwrap()).unwrap());
        size += slack;
    }
    assert_eq!(encode(data).unwrap().len(), size);
    assert!(size <= target);
}

pub(super) fn pad_meta(saved: &mut Saved, target: usize) {
    loop {
        let before = encode(&saved.meta).unwrap().len();
        let mut archive = Candidate {
            data: Data::empty(saved.data.state.scope.clone()),
            crypto: vec![],
        };
        let overhead = encode(&archive).unwrap().len() - encode(&archive.data).unwrap().len()
            + usize::from(!saved.meta.archives.is_empty());
        let Some(remaining) = target.checked_sub(before + overhead) else {
            break;
        };
        if remaining < 1024 {
            break;
        }
        pad_data(&mut archive.data, remaining.min(MAX_DATA));
        saved.meta.archives.push(archive);
        assert!(saved.meta.archives.len() <= 16);
    }
    saved.meta.validate(&saved.data, &saved.crypto).unwrap();
    let size = encode(&saved.meta).unwrap().len();
    assert!(size <= target && target - size < 1024);
}

#[test]
fn maximum_legal_text_exhausts_data_before_message_slots() {
    let mut pair = Pair::new();
    pair.group();
    let text = "\0".repeat(32768);
    let mut first = None;
    let mut received = 0;
    for n in 0..29 {
        let input = Action::Send {
            message_id: format!("max-{n}"),
            text: text.clone(),
        };
        let sent = pair.a.execute(format!("send-{n}"), input).unwrap();
        let Value::Sent { envelope } = sent.value else {
            panic!()
        };
        let action = Action::Receive { envelope };
        let before = pair.b.database.call(|db| db.read(Ok)).unwrap();
        match pair.b.execute(format!("receive-{n}"), action.clone()) {
            Ok(_) => {
                received += 1;
                if first.is_none() {
                    first = Some(action);
                }
            }
            Err(error) => {
                assert_eq!(error.code, "storage_limit");
                assert!(!error.paused);
                let after = pair.b.database.call(|db| db.read(Ok)).unwrap();
                assert_eq!(
                    operations::fingerprint(&before).unwrap(),
                    operations::fingerprint(&after).unwrap()
                );
                assert!(after.data.state.pending_request.is_none());
                assert_eq!(
                    pair.b.request(format!("receive-{n}")).unwrap(),
                    RequestState::Missing
                );
                println!("BUDGET maximum_text received={received} data={} meta={} crypto={} requests={} messages={}", encode(&after.data).unwrap().len(), encode(&after.meta).unwrap().len(), after.crypto.len(), after.data.requests.len(), after.data.messages.len());
                pair.reopen();
                assert_eq!(
                    pair.b
                        .execute(format!("receive-{n}"), action)
                        .unwrap_err()
                        .code,
                    "storage_limit"
                );
                assert!(
                    pair.b
                        .recover_request("receive-0".into(), first.unwrap())
                        .unwrap()
                        .cached
                );
                break;
            }
        }
    }
    assert!(received > 0 && received < 29);
    let saved = pair.b.database.call(|db| db.read(Ok)).unwrap();
    let message = &saved.data.messages[0];
    let receipt = message.receipt.as_ref().unwrap();
    assert!(matches!(&receipt.value, Value::Received { message: m, .. } if m.text == text));
    assert!(
        matches!(&saved.data.requests["receive-0"].result, RequestState::Complete { outcome } if outcome == receipt)
    );
    // 仅三份正文就构成严格下界，尚未包含密文、字段和网络原事件。
    let escaped_text = encode(&text).unwrap().len() - 2;
    assert_eq!(escaped_text, 6 * 32768);
    assert!(29 * 3 * escaped_text > MAX_DATA);
    println!(
        "BUDGET plaintext_lower_bound messages=29 bytes={} messages_256_bytes={}",
        29 * 3 * escaped_text,
        256 * 3 * escaped_text
    );
}

#[test]
fn candidate_encoding_counts_byte_arrays_and_backup_guard() {
    let mut pair = Pair::new();
    pair.group();
    let mut saved = pair.a.database.call(|db| db.read(Ok)).unwrap();
    let actual = encode(&saved.crypto).unwrap().len();
    assert!(actual > saved.crypto.len());
    let before = encode(&saved.meta).unwrap().len();
    saved.meta.backup_guard = Some("01".repeat(32));
    let guard = encode(&saved.meta).unwrap().len() - before;
    // 这里只测生产serde的表示上界；全255字节不是有效密码快照。
    let raw = vec![255_u8; 4 * 1024 * 1024];
    assert_eq!(encode(&raw).unwrap().len(), 16 * 1024 * 1024 + 1);
    println!("BUDGET encoding crypto_raw={} crypto_json={actual} max_crypto_json={} backup_guard_delta={guard}", saved.crypto.len(), encode(&raw).unwrap().len());
}

#[test]
fn complete_candidate_at_meta_boundary_installs_without_repeating_crypto() {
    let mut pair = Pair::new();
    pair.group();
    let action = Action::Send {
        message_id: "candidate".into(),
        text: "bounded".into(),
    };
    let mut saved = pair.a.database.call(|db| db.read(Ok)).unwrap();
    operations::prepare(&mut saved, "candidate", &action).unwrap();
    saved.meta.journal = Some(Journal {
        request: "candidate".into(),
        input: action.clone(),
        phase: Phase::Executing,
        seed: None,
        candidate: None,
    });
    let (candidate, expected) =
        candidate::apply(Box::new(saved.clone()), "candidate", &action).unwrap();
    saved.meta.journal.as_mut().unwrap().candidate = Some(Candidate {
        data: candidate.data.clone(),
        crypto: candidate.crypto.clone(),
    });
    pad_meta(&mut saved, store::MAX_META - 32);
    let before = encode(&saved.meta).unwrap().len();
    let start = saved.clone();
    pair.a
        .database
        .call(move |db| {
            db.update(false, |s| {
                *s = start;
                Ok(())
            })
        })
        .unwrap();
    // 新增首次备份guard无法容纳，必须原子拒绝；不模拟钥匙串外部预约成功。
    let fingerprint = operations::fingerprint(&saved).unwrap();
    let error = pair
        .a
        .database
        .call(|db| {
            db.update(false, |s| {
                s.meta.backup_guard = Some("01".repeat(32));
                Ok(())
            })
        })
        .unwrap_err();
    assert_eq!(error.code, "storage_limit");
    assert_eq!(
        pair.a
            .database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap(),
        fingerprint
    );
    pair.reopen();
    assert_eq!(
        pair.a
            .recover_request("candidate".into(), action.clone())
            .unwrap(),
        expected
    );
    let after = pair.a.database.call(|db| db.read(Ok)).unwrap();
    assert_eq!(after.crypto, candidate.crypto);
    assert_eq!(
        encode(&after.data).unwrap(),
        encode(&candidate.data).unwrap()
    );
    assert!(after.meta.journal.is_none());
    assert!(
        pair.a
            .recover_request("candidate".into(), action)
            .unwrap()
            .cached
    );
    println!(
        "BUDGET complete_candidate meta_before={before} meta_after={} archives={}",
        encode(&after.meta).unwrap().len(),
        after.meta.archives.len()
    );
}
