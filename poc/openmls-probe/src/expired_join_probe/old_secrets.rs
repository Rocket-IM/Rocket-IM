//! 旧消息秘密攻击矩阵；完整旧provider与合法当前材料隔离保存，仅输出公开结果。
use super::*;

const AAD: &[u8] = b"Rocket-IM/POC/old-message-secret-matrix/v1";
#[derive(Serialize, Deserialize)]
pub(super) struct Control {
    pub(super) sender: String,
    pub(super) generation: u32,
    pub(super) packet: Vec<u8>,
    pub(super) payload: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Target {
    pub(super) stage: String,
    pub(super) sender: String,
    pub(super) generation: u32,
    pub(super) packet: Vec<u8>,
    pub(super) payload: Vec<u8>,
    pub(super) current: Actor,
    pub(super) legal_receivers: Vec<String>,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Scenario {
    pub(super) name: String,
    pub(super) old_bundle: Actor,
    pub(super) old: BTreeMap<String, Actor>,
    pub(super) controls: Vec<Control>,
    pub(super) targets: Vec<Target>,
    pub(super) commits: Vec<Vec<u8>>,
    pub(super) facts: Value,
}
#[derive(Serialize, Deserialize)]
struct Matrix {
    version: String,
    scenarios: Vec<Scenario>,
}
fn actor<'a>(actors: &'a BTreeMap<String, Actor>, name: &str) -> Result<&'a Actor, String> {
    actors.get(name).ok_or_else(|| "missing actor".into())
}
fn actor_mut<'a>(
    actors: &'a mut BTreeMap<String, Actor>,
    name: &str,
) -> Result<&'a mut Actor, String> {
    actors.get_mut(name).ok_or_else(|| "missing actor".into())
}
pub(super) fn scenario(name: &str) -> Result<Scenario, String> {
    let mut a = Actor::new("synthetic/service/alice/device-a")?;
    a.create()?;
    let mut b = Actor::new("synthetic/service/bob/device-b")?;
    let (_, welcome) = actor::add(&a, b.package(now()? + 3600)?)?;
    b.join(&welcome)?;
    let label = if name == "revoke_device" {
        "synthetic/service/alice/device-c"
    } else {
        "synthetic/service/charlie/device-c"
    };
    let mut seed = Actor::new(label)?;
    let package = seed.package(now()? + 3600)?;
    let old_bundle = seed.fork()?;
    let mut c = seed.fork()?;
    let (commit, welcome) = actor::add(&a, package)?;
    b.apply(&commit)?;
    c.join(&welcome)?;
    let old_fact = c.fact()?;
    let mut old = BTreeMap::from([("root".into(), c.fork()?)]);
    let mut actors = BTreeMap::from([("a".into(), a), ("b".into(), b), ("c".into(), c)]);
    let mut controls = vec![];
    for sender in ["a", "b"] {
        let payload = format!("synthetic/{name}/R0/{sender}/0").into_bytes();
        let packet = actor(&actors, sender)?.send(&payload)?;
        actor(&actors, "c")?.receive(&packet, &payload)?;
        controls.push(Control {
            sender: sender.into(),
            generation: 0,
            packet,
            payload,
        });
    }
    old.insert("head".into(), actor_mut(&mut actors, "c")?.fork()?);
    for sender in ["a", "b"] {
        for generation in 1..=4 {
            let payload = format!("synthetic/{name}/R0/{sender}/{generation}").into_bytes();
            let packet = actor(&actors, sender)?.send(&payload)?;
            if generation == 3 {
                actor(&actors, "c")?.receive(&packet, &payload)?;
            }
            controls.push(Control {
                sender: sender.into(),
                generation,
                packet,
                payload,
            });
        }
    }
    old.insert("cached".into(), actor_mut(&mut actors, "c")?.fork()?);
    let removed = actor(&actors, "c")?.group()?.own_leaf_index();
    let mut commits = vec![];
    if name == "replace_same_identity" {
        let fresh = seed.package(now()? + 3600)?;
        let (commit, welcome) = commit::replacement(actor(&actors, "a")?, removed, vec![fresh])?;
        actor(&actors, "b")?.apply(&commit)?;
        checked(
            "merge replacement",
            actor(&actors, "a")?
                .group()?
                .merge_pending_commit(&actor(&actors, "a")?.provider),
        )?;
        seed.join(&welcome)?;
        commit::same_state(actor(&actors, "a")?, &seed)?;
        ensure(
            seed.fact()?["members"] == old_fact["members"]
                || seed.credential == actor(&old, "root")?.credential,
            "same identity not retained",
        )?;
        actors.insert("c".into(), seed);
        commits.push(commit);
    } else {
        let a = actor(&actors, "a")?;
        let mut group = a.group()?;
        let (commit, _, _) = checked(
            "remove",
            group.remove_members(&a.provider, &a.signer, &[removed]),
        )?;
        let commit = checked("remove bytes", commit.to_bytes())?;
        actor(&actors, "b")?.apply(&commit)?;
        checked("merge remove", group.merge_pending_commit(&a.provider))?;
        actors.remove("c");
        commits.push(commit);
    }
    let mut targets = vec![];
    let mut stages = vec![];
    for stage in ["R1", "R2"] {
        if stage == "R2" {
            let a = actor(&actors, "a")?;
            let mut group = a.group()?;
            let update = checked(
                "healthy update",
                group.self_update(&a.provider, &a.signer, LeafNodeParameters::default()),
            )?;
            let packet = checked("update bytes", update.into_commit().to_bytes())?;
            for peer in ["b", "c"] {
                if let Some(p) = actors.get(peer) {
                    p.apply(&packet)?;
                }
            }
            checked(
                "merge healthy update",
                group.merge_pending_commit(&a.provider),
            )?;
            commits.push(packet);
        }
        for peer in ["b", "c"] {
            if let Some(p) = actors.get(peer) {
                commit::same_state(actor(&actors, "a")?, p)?;
            }
        }
        stages.push(json!({"stage":stage,"current":actor(&actors,"a")?.fact()?}));
        for sender in ["a", "b"] {
            for generation in 0..=4 {
                let current = actor_mut(&mut actors, sender)?.fork()?;
                let payload =
                    format!("synthetic/{name}/{stage}/{sender}/{generation}").into_bytes();
                let packet = actor(&actors, sender)?.send(&payload)?;
                let mut legal_receivers = vec![];
                for (peer, p) in &actors {
                    if peer != sender {
                        p.receive(&packet, &payload)?;
                        legal_receivers.push(peer.clone());
                    }
                }
                if [0, 1, 4].contains(&generation) {
                    targets.push(Target {
                        stage: stage.into(),
                        sender: sender.into(),
                        generation,
                        packet,
                        payload,
                        current,
                        legal_receivers,
                    });
                }
            }
        }
    }
    // 公共链真实交给独立旧副本；不把inactive/WrongEpoch作为密码拒绝结果。
    let observer = actor_mut(&mut old, "root")?.fork()?;
    observer.apply(&commits[0])?;
    let public_result = observer.fact()?;
    ensure(!observer.group()?.is_active(), "removed copy still active")?;
    let facts = json!({"old":old_fact,"stages":stages,"public_commit_old_copy":public_result,"commit_sha256":commits.iter().map(|x|digest(x)).collect::<Vec<_>>(),"synthetic_only":true});
    Ok(Scenario {
        name: name.into(),
        old_bundle,
        old,
        controls,
        targets,
        commits,
        facts,
    })
}
pub(super) fn run(phase: &str, path: &Path) -> Result<Value, String> {
    let mut matrix = if phase == "old-secrets-init" {
        ensure(
            !path.join("state.enc").exists(),
            "existing old-secret fixture",
        )?;
        let mut key = [0u8; 32];
        checked("random key", getrandom::getrandom(&mut key))?;
        let mut file = checked(
            "new key",
            fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path.join("state.key")),
        )?;
        checked("write key", file.write_all(&key))?;
        checked("sync key", file.sync_all())?;
        Matrix {
            version: "rim-old-secrets-matrix-1".into(),
            scenarios: ["remove_member", "revoke_device", "replace_same_identity"]
                .into_iter()
                .map(scenario)
                .collect::<Result<_, _>>()?,
        }
    } else {
        let bytes = checked(
            "load fixture",
            openmls_probe::snapshot::load(&path.join("state.enc"), &key(path)?, AAD),
        )?;
        let mut m: Matrix = checked("decode fixture", serde_json::from_slice(&bytes))?;
        for s in &mut m.scenarios {
            s.old_bundle.restore()?;
            for a in s.old.values_mut() {
                a.restore()?;
            }
            for t in &mut s.targets {
                t.current.restore()?;
            }
        }
        m
    };
    ensure(
        matrix.version == "rim-old-secrets-matrix-1" && matrix.scenarios.len() == 3,
        "matrix format",
    )?;
    if phase == "old-secrets-init" {
        for s in &mut matrix.scenarios {
            s.old_bundle.capture()?;
            for a in s.old.values_mut() {
                a.capture()?;
            }
            for t in &mut s.targets {
                t.current.capture()?;
            }
        }
        checked(
            "save fixture",
            openmls_probe::snapshot::save(
                &path.join("state.enc"),
                &key(path)?,
                AAD,
                &checked("encode fixture", serde_json::to_vec(&matrix))?,
                openmls_probe::snapshot::Failpoint::None,
            ),
        )?;
    }
    let scenarios = matrix
        .scenarios
        .iter()
        .map(super::old_secret_cases::evaluate)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(
        json!({"status":"PASS_SCOPED","phase":phase,"pid":std::process::id(),"scenarios":scenarios,"direct_aead":true,"snapshot_sha256":digest(&checked("snapshot hash",fs::read(path.join("state.enc")))?),"full_old_secret_attack":"NOT_COMPLETE","full_stage0":"NOT_COMPLETE"}),
    )
}
