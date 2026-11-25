use super::{
    tests::{send, Pair},
    *,
};

fn query(direction: HistoryDirection, size: u32, cursor: Option<String>) -> HistoryQuery {
    HistoryQuery {
        direction,
        page_size: size,
        cursor,
    }
}
fn ids(page: &HistoryPage) -> Vec<&str> {
    page.items
        .iter()
        .map(|i| i.message.message_id.as_str())
        .collect()
}

#[test]
fn stable_both_directions_across_append_restart_and_duplicate_receive() {
    let mut p = Pair::new();
    assert!(
        p.a.history(query(HistoryDirection::Forward, 2, None))
            .unwrap()
            .done
    );
    p.group();
    let e = send(&mut p.a, "first");
    p.b.execute(
        "rx".into(),
        Action::Receive {
            envelope: e.clone(),
        },
    )
    .unwrap();
    p.b.execute("duplicate".into(), Action::Receive { envelope: e })
        .unwrap();
    let e = send(&mut p.b, "reply");
    p.a.execute("rx".into(), Action::Receive { envelope: e })
        .unwrap();
    send(&mut p.a, "third");
    let f =
        p.a.history(query(HistoryDirection::Forward, 1, None))
            .unwrap();
    let b =
        p.a.history(query(HistoryDirection::Backward, 1, None))
            .unwrap();
    assert_eq!(ids(&f), ["first"]);
    assert_eq!(ids(&b), ["third"]);
    send(&mut p.a, "after-bound");
    p.reopen();
    for (first, direction, expected) in [
        (f, HistoryDirection::Forward, ["reply", "third"]),
        (b, HistoryDirection::Backward, ["reply", "first"]),
    ] {
        let mut cursor = first.next_cursor;
        for id in expected {
            let page = p.a.history(query(direction, 1, cursor.clone())).unwrap();
            assert_eq!(page, p.a.history(query(direction, 1, cursor)).unwrap());
            assert_eq!(page.upper_bound, "3");
            assert_eq!(ids(&page), [id]);
            cursor = page.next_cursor;
        }
        assert!(cursor.is_none());
    }
    assert_eq!(
        p.a.history(query(HistoryDirection::Forward, 64, None))
            .unwrap()
            .items
            .len(),
        4
    );
    assert_eq!(
        p.b.history(query(HistoryDirection::Forward, 64, None))
            .unwrap()
            .items
            .len(),
        2
    );
}

#[test]
fn cursors_reject_other_space_scope_options_and_malformed_input() {
    let mut p = Pair::new();
    p.group();
    send(&mut p.a, "one");
    send(&mut p.a, "two");
    let cursor =
        p.a.history(query(HistoryDirection::Forward, 1, None))
            .unwrap()
            .next_cursor;
    let mut other = Pair::new();
    other.group();
    send(&mut other.a, "one");
    send(&mut other.a, "two");
    for device in [&p.b, &other.a] {
        assert_eq!(
            device
                .history(query(HistoryDirection::Forward, 1, cursor.clone()))
                .unwrap_err()
                .code,
            "history_cursor_mismatch"
        );
    }
    for (direction, size) in [
        (HistoryDirection::Backward, 1),
        (HistoryDirection::Forward, 2),
    ] {
        assert_eq!(
            p.a.history(query(direction, size, cursor.clone()))
                .unwrap_err()
                .code,
            "history_cursor_mismatch"
        );
    }
    for bad in [
        "",
        "h2:2:1:abc",
        "h1:02:1:0000000000000000000000000000000000000000000000000000000000000000",
    ] {
        assert_eq!(
            p.a.history(query(HistoryDirection::Forward, 1, Some(bad.into())))
                .unwrap_err()
                .code,
            "history_cursor_invalid"
        );
    }
    for size in [0, 65, u32::MAX] {
        assert_eq!(
            p.a.history(query(HistoryDirection::Forward, size, None))
                .unwrap_err()
                .code,
            "history_page_size_invalid"
        );
    }
}

#[test]
fn maximum_escaped_messages_form_short_nonterminal_pages_without_ipc_overflow() {
    let mut p = Pair::new();
    p.group();
    for n in 0..5 {
        p.a.execute(
            format!("control{n}"),
            Action::Send {
                message_id: format!("control{n}"),
                text: "\0".repeat(32768),
            },
        )
        .unwrap();
    }
    let mut cursor = None;
    let mut count = 0;
    loop {
        let page =
            p.a.history(query(HistoryDirection::Forward, 64, cursor))
                .unwrap();
        assert!(encode(&page).unwrap().len() < 600_000);
        count += page.items.len();
        if page.done {
            break;
        }
        assert!(!page.items.is_empty());
        cursor = page.next_cursor;
    }
    assert_eq!(count, 5);
}

#[test]
fn history_read_preserves_reserved_request_and_database_bytes() {
    let mut p = Pair::new();
    p.group();
    send(&mut p.a, "old");
    p.a.database
        .call(|db| {
            db.update(false, |s| {
                operations::prepare(
                    s,
                    "pending",
                    &Action::Send {
                        message_id: "pending".into(),
                        text: "pending".into(),
                    },
                )?;
                Ok(())
            })
        })
        .unwrap();
    let before =
        p.a.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap();
    let page =
        p.a.history(query(HistoryDirection::Forward, 64, None))
            .unwrap();
    assert_eq!(ids(&page), ["old"]);
    let after =
        p.a.database
            .call(|db| db.read(|s| operations::fingerprint(&s)))
            .unwrap();
    assert_eq!(before, after);
    assert_eq!(
        p.a.request("pending".into()).unwrap(),
        RequestState::Pending
    );
}
