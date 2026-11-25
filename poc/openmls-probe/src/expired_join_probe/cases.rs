//! 真正到期后才运行的分支；失败探测在临时 provider，健康快照不被覆盖。
use super::*;
use openmls_traits::storage::StorageProvider;

fn rejected<T>(result: Result<T, String>, expected: &str) -> Result<Value, String> {
    match result {
        Ok(_) => Err(format!("expected rejection: {expected}")),
        Err(error) => {
            ensure(
                error.contains(expected),
                &format!("unexpected rejection: {error}; expected {expected}"),
            )?;
            Ok(json!({"status":"EXPECTED_REJECTION","error":error}))
        }
    }
}

fn prepare(f: &mut Fixture) -> Result<(), String> {
    ensure(now()? > f.old_expires, "old lifetime has not expired")?;
    f.new_expires = now()? + 20;
    let package = f.get("c")?.package(f.new_expires)?;
    ensure(
        package.hpke_init_key() != f.original_package.hpke_init_key(),
        "init key reused",
    )?;
    let removed = f.get("old")?.group()?.own_leaf_index();
    let (commit, welcome) = commit::replacement(f.get("a")?, removed, vec![package.clone()])?;
    f.replacement = commit;
    f.welcome = welcome;
    f.package = Some(package);
    Ok(())
}

pub(super) fn recover(f: &mut Fixture) -> Result<Value, String> {
    let mut report = serde_json::Map::new();
    // 最初目标不消费；只在独立攻击副本中曾成功加入。
    report.insert(
        "old_welcome_expired".into(),
        rejected(f.fork("c")?.join(&f.original_welcome), "Lifetime")?,
    );
    report.insert(
        "old_add_expired".into(),
        rejected(f.fork("before_add")?.apply(&f.original_add), "Lifetime")?,
    );
    let before = f.get("b")?.fact()?;
    let mut candidate = f.fork("a")?;
    let pending_package = Actor::new("synthetic/pending")?.package(now()? + 3600)?;
    let mut pending_group = candidate.group()?;
    checked(
        "pending proposal",
        pending_group.propose_add_member(&candidate.provider, &candidate.signer, &pending_package),
    )?;
    let fresh = f.get("c")?.package(now()? + 120)?;
    let removed = f.get("old")?.group()?.own_leaf_index();
    report.insert(
        "pending_proposals".into(),
        rejected(
            commit::replacement(&candidate, removed, vec![fresh]),
            "pending proposals forbidden",
        )?,
    );
    // 一个真实可验证但多一个 Add 的候选必须被装置精确检查拒绝。
    candidate = f.fork("a")?;
    let fresh = f.get("c")?.package(now()? + 120)?;
    let outsider = Actor::new("synthetic/outsider")?.package(now()? + 3600)?;
    let (extra, _) = commit::replacement(&candidate, removed, vec![fresh.clone(), outsider])?;
    let sender = f.get("a")?.group()?.own_leaf_index();
    report.insert(
        "extra_inline_add".into(),
        rejected(
            commit::accept(&f.fork("b")?, &extra, removed, &fresh, sender),
            "exactly two inline",
        )?,
    );
    let wrong_removed = f.get("b")?.group()?.own_leaf_index();
    report.insert(
        "wrong_remove_construct".into(),
        rejected(
            commit::replacement(&f.fork("a")?, wrong_removed, vec![fresh]),
            "DuplicateSignatureKey",
        )?,
    );
    prepare(f)?;
    let package = f.package.as_ref().ok_or("missing package")?.clone();
    report.insert(
        "missing_predecessor".into(),
        rejected(f.fork("before_add")?.apply(&f.replacement), "WrongEpoch")?,
    );
    let delayed = f.fork("b")?;
    f.actors.insert("delayed".into(), delayed);
    let unjoined = f.fork("c")?;
    f.actors.insert("unjoined".into(), unjoined);
    report.insert(
        "wrong_remove_binding".into(),
        rejected(
            commit::accept(
                &f.fork("b")?,
                &f.replacement,
                wrong_removed,
                &package,
                sender,
            ),
            "replacement identity mismatch",
        )?,
    );
    let wrong_package = f.get("c")?.package(now()? + 120)?;
    report.insert(
        "wrong_package_binding".into(),
        rejected(
            commit::accept(
                &f.fork("b")?,
                &f.replacement,
                removed,
                &wrong_package,
                sender,
            ),
            "exact Remove/Add mismatch",
        )?,
    );
    report.insert(
        "wrong_sender_binding".into(),
        rejected(
            commit::accept(
                &f.fork("b")?,
                &f.replacement,
                removed,
                &package,
                wrong_removed,
            ),
            "sender/group/epoch mismatch",
        )?,
    );
    let mut missing = f.fork("c")?;
    let reference = checked("package ref", package.hash_ref(missing.provider.crypto()))?;
    checked(
        "delete test bundle",
        missing.provider.storage().delete_key_package(&reference),
    )?;
    report.insert(
        "missing_bundle".into(),
        rejected(missing.join(&f.welcome), "NoMatchingKeyPackage")?,
    );
    let mut corrupt = f.welcome.clone();
    let last = corrupt.last_mut().ok_or("empty welcome")?;
    *last ^= 1;
    report.insert(
        "corrupt_welcome".into(),
        rejected(
            f.fork("c")?.join(&corrupt),
            "GroupSecrets(DecryptionFailed)",
        )?,
    );
    // 构造同群健康状态+匹配新bundle，仅测试库默认同群保护；不删除健康群。
    let mut duplicate = f.fork("c")?;
    let old = f.fork("old")?;
    checked(
        "collision provider",
        duplicate.provider.storage().values.write(),
    )?
    .extend(checked("old provider", old.provider.storage().values.read())?.clone());
    duplicate.group_id = old.group_id.clone();
    let healthy = duplicate.fact()?;
    report.insert(
        "existing_group".into(),
        rejected(duplicate.join(&f.welcome), "GroupAlreadyExists")?,
    );
    ensure(
        duplicate.fact()? == healthy,
        "existing healthy group changed",
    )?;
    commit::accept(f.get("b")?, &f.replacement, removed, &package, sender)?;
    checked(
        "committer merge",
        f.get("a")?
            .group()?
            .merge_pending_commit(&f.get("a")?.provider),
    )?;
    let welcome = f.welcome.clone();
    f.get_mut("c")?.join(&welcome)?;
    commit::same_state(f.get("a")?, f.get("b")?)?;
    commit::same_state(f.get("a")?, f.get("c")?)?;
    let after = f.get("b")?.fact()?;
    let ids = |value: &Value| -> Vec<Value> {
        value["members"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .map(|m| json!([m["identity"], m["signature"]]))
            .collect()
    };
    ensure(
        ids(&before) == ids(&after) && before["tree"] != after["tree"],
        "identity set or crypto state invalid",
    )?;
    let ciphertext = f.get("a")?.send(b"synthetic after-recovery")?;
    f.get("b")?
        .receive(&ciphertext, b"synthetic after-recovery")?;
    f.get("c")?
        .receive(&ciphertext, b"synthetic after-recovery")?;
    let reply = f.get("c")?.send(b"synthetic recovered reply")?;
    f.get("a")?.receive(&reply, b"synthetic recovered reply")?;
    f.get("b")?.receive(&reply, b"synthetic recovered reply")?;
    report.insert(
        "direct_old_secret".into(),
        attack::verify(f.get("old")?, f.get("c")?, &f.old_message, &ciphertext)?,
    );
    // 旧副本还获得真实公开握手（默认 wire policy），应用后应只成为被移除状态。
    let old_copy = f.fork("old")?;
    old_copy.apply(&f.replacement)?;
    ensure(!old_copy.group()?.is_active(), "old copy became new member")?;
    report.insert(
        "old_copy_received_commit".into(),
        json!({"active":false,"fact":old_copy.fact()?}),
    );
    report.insert(
        "new_target_old_history".into(),
        rejected(
            f.get("c")?
                .receive(&f.old_message, b"synthetic pre-recovery"),
            "TooDistantInThePast",
        )?,
    );
    let current = f.get("c")?.fact()?;
    report.insert(
        "repeat_welcome".into(),
        rejected(f.get_mut("c")?.join(&welcome), "NoMatchingKeyPackage")?,
    );
    ensure(
        f.get("c")?.fact()? == current,
        "duplicate join changed healthy state",
    )?;
    report.insert(
        "timely".into(),
        json!({"status":"PASS_SCOPED","identity_set_unchanged":true,"crypto_tree_changed":true,
        "exact_remove":removed.u32(),"inline_add":1,"inline_remove":1,"update_path":true,
        "commit_sha256":digest(&f.replacement),"welcome_sha256":digest(&f.welcome),
        "key_package_sha256":digest(&checked("package bytes",package.tls_serialize_detached())?),
        "bidirectional_communication":true,"before":before,"after":after}),
    );
    // 合法后继不用目标旧包重新加入；按实际 Commit 顺序前进。
    let a = f.get("a")?;
    let mut group = a.group()?;
    let update = checked(
        "successor update",
        group.self_update(&a.provider, &a.signer, LeafNodeParameters::default()),
    )?;
    let bytes = checked("successor bytes", update.into_commit().to_bytes())?;
    f.get("b")?.apply(&bytes)?;
    f.get("c")?.apply(&bytes)?;
    checked("successor merge", group.merge_pending_commit(&a.provider))?;
    commit::same_state(a, f.get("b")?)?;
    commit::same_state(a, f.get("c")?)?;
    let bytes = f.get("c")?.send(b"synthetic successor epoch")?;
    a.receive(&bytes, b"synthetic successor epoch")?;
    f.get("b")?.receive(&bytes, b"synthetic successor epoch")?;
    report.insert(
        "legal_successor".into(),
        json!({"communication":true,"target":f.get("c")?.fact()?}),
    );
    Ok(Value::Object(report))
}

pub(super) fn expired_tree(f: &mut Fixture) -> Result<Value, String> {
    prepare(f)?;
    let fact = f.get("b")?.fact()?;
    let result = rejected(f.fork("c")?.join(&f.welcome), "Lifetime")?;
    ensure(
        f.get("b")?.fact()? == fact,
        "expired survivor state changed",
    )?;
    Ok(
        json!({"welcome":result,"expired_leaf":"survivor b","survivor_unchanged":true,
        "old_expires":f.old_expires,"new_expires":f.new_expires,"attempted_at":now()?}),
    )
}

pub(super) fn late(f: &mut Fixture) -> Result<Value, String> {
    ensure(now()? > f.new_expires, "new lifetime has not expired")?;
    let before = f.get("delayed")?.fact()?;
    let package = f.package.as_ref().ok_or("missing package")?.clone();
    let removed = f.get("old")?.group()?.own_leaf_index();
    let delayed = rejected(
        commit::accept(
            &f.fork("delayed")?,
            &f.replacement,
            removed,
            &package,
            f.get("a")?.group()?.own_leaf_index(),
        ),
        "Lifetime",
    )?;
    let welcome = rejected(f.fork("unjoined")?.join(&f.welcome), "Lifetime")?;
    ensure(
        f.get("delayed")?.fact()? == before,
        "late rejection changed survivor",
    )?;
    // 已成功加入的端不因当年的材料过期丧失现有通信状态。
    let bytes = f.get("a")?.send(b"synthetic after restart and expiry")?;
    f.get("b")?
        .receive(&bytes, b"synthetic after restart and expiry")?;
    f.get("c")?
        .receive(&bytes, b"synthetic after restart and expiry")?;
    let bytes = f
        .get("b")?
        .send(b"synthetic survivor reply after restart")?;
    f.get("a")?
        .receive(&bytes, b"synthetic survivor reply after restart")?;
    f.get("c")?
        .receive(&bytes, b"synthetic survivor reply after restart")?;
    Ok(
        json!({"late_replacement_commit":delayed,"late_recovery_welcome":welcome,
        "delayed_state_preserved":true,"restarted_current_members_communicate":true,
        "before":before,"after":f.get("delayed")?.fact()?}),
    )
}
