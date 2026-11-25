//! 非E2EE容量填充夹具：保留真实密码快照，精确验证原计额和事务回滚。
use super::rejection_tests::{attach, reject};
use crate::persistent::{
    data::{Record, Saved, MAX_DATA},
    journal::Candidate,
    operations, store,
    tests::{send, Pair},
    types::*,
};

fn fill_data(saved: &mut Saved, target: usize) {
    loop {
        let size = encode(&saved.data).unwrap().len();
        if size + 1024 >= target {
            break;
        }
        let request = format!("budget-{}", saved.data.requests.len());
        let action = Action::Send {
            message_id: request.clone(),
            text: "x".repeat((target - size - 512).min(32768)),
        };
        saved.data.requests.insert(
            request,
            Record {
                hash: hash(&encode(&action).unwrap()),
                input: Some(action),
                action: "send".into(),
                result: RequestState::Failed {
                    error: Error::new("fixture_failure"),
                },
                rejection: None,
            },
        );
    }
    saved.data.validate(&saved.crypto).unwrap();
    assert!(saved.data.requests.len() < 1024);
    assert!(encode(&saved.data).unwrap().len() <= target);
}

#[test]
fn rejection_at_byte_budgets_shrinks_data_and_does_not_grow_recovery_metadata() {
    let mut p = Pair::new();
    p.group();
    attach(&mut p);
    let e = send(&mut p.b, "rejected");
    let mut saved = p.b.database.call(|db| db.read(Ok)).unwrap();
    fill_data(&mut saved, MAX_DATA);
    let before = encode(&saved.data).unwrap().len();
    assert!(before > MAX_DATA - 2048);
    let action = Action::Send {
        message_id: "new".into(),
        text: "new".into(),
    };
    assert_eq!(
        operations::prepare(&mut saved, "new", &action)
            .err()
            .unwrap()
            .code,
        "storage_limit"
    );
    // 元数据接近32MiB；每个归档仍有独立的16MiB数据/4MiB密码边界。
    let mut archived = saved.clone();
    fill_data(&mut archived, MAX_DATA);
    saved.meta.archives.push(Candidate {
        data: archived.data.clone(),
        crypto: archived.crypto.clone(),
    });
    saved.meta.archives.push(Candidate {
        data: archived.data,
        crypto: archived.crypto,
    });
    // 两份近16MiB快照加密码会超过32MiB；减少第二份的失败夹具直到合法。
    while encode(&saved.meta).unwrap().len() > store::MAX_META {
        let second = &mut saved.meta.archives[1];
        let key = second
            .data
            .requests
            .keys()
            .rfind(|k| k.starts_with("budget-"))
            .unwrap()
            .clone();
        second.data.requests.remove(&key);
    }
    let metadata = encode(&saved.meta).unwrap();
    assert!(metadata.len() > store::MAX_META - 65536);
    saved.meta.validate(&saved.data, &saved.crypto).unwrap();
    let start = saved.clone();
    p.b.database
        .call(move |db| {
            db.update(false, |s| {
                *s = start;
                Ok(())
            })
        })
        .unwrap();
    p.b.database
        .call(move |db| db.update(true, |s| reject(s, "rejected", &e)))
        .unwrap();
    let after = p.b.database.call(|db| db.read(Ok)).unwrap();
    assert!(encode(&after.data).unwrap().len() < before);
    assert_eq!(encode(&after.meta).unwrap(), metadata);
    assert_eq!(after.crypto, saved.crypto);
    assert_eq!(after.data.requests.len(), saved.data.requests.len());
    // 真正写事务中的超限不能留下新内容或新的成功结果。
    let before = operations::fingerprint(&after).unwrap();
    let error =
        p.b.database
            .call(|db| {
                db.update(false, |s| {
                    let archive = s.meta.archives[0].clone();
                    s.meta.archives.push(archive);
                    Ok(())
                })
            })
            .unwrap_err();
    assert_eq!(error.code, "storage_limit");
    assert_eq!(
        p.b.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap(),
        before
    );
    p.reopen();
}
