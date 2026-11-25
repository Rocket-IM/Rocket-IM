//! 有界、默认关闭的恢复机制实验。所有名字与材料均为本轮合成，输出无秘密。
mod actor;
mod attack;
mod cases;
mod commit;
mod old_secret_cases;
#[cfg(test)]
mod old_secret_tests;
mod old_secrets;
mod raw_message;
mod raw_secrets;
use actor::Actor;
use openmls::prelude::{
    tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize},
    *,
};
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const CONTEXT: &[u8] = b"Rocket-IM/expired-join-mechanism/v1";
fn checked<T, E: std::fmt::Debug>(step: &str, result: Result<T, E>) -> Result<T, String> {
    result.map_err(|e| format!("{step}: {e:?}"))
}
fn ensure(ok: bool, reason: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(reason.into())
    }
}
fn now() -> Result<u64, String> {
    Ok(checked("clock", SystemTime::now().duration_since(UNIX_EPOCH))?.as_secs())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn protocol(bytes: &[u8]) -> Result<ProtocolMessage, String> {
    checked(
        "protocol",
        checked("message", MlsMessageIn::tls_deserialize_exact(bytes))?.try_into_protocol_message(),
    )
}

#[derive(Serialize, Deserialize)]
struct Fixture {
    actors: BTreeMap<String, Actor>,
    original_add: Vec<u8>,
    original_welcome: Vec<u8>,
    original_package: KeyPackage,
    old_message: Vec<u8>,
    replacement: Vec<u8>,
    welcome: Vec<u8>,
    package: Option<KeyPackage>,
    old_expires: u64,
    new_expires: u64,
}
impl Fixture {
    fn init(expired_survivor: bool, expires: u64) -> Result<Self, String> {
        let mut a = Actor::new("synthetic/service/owner/a")?;
        a.create()?;
        let mut b = Actor::new("synthetic/service/survivor/b")?;
        let bp = b.package(if expired_survivor {
            expires
        } else {
            now()? + 3600
        })?;
        let (_, welcome) = actor::add(&a, bp)?;
        b.join(&welcome)?;
        let before = b.fork()?;
        let mut c = Actor::new("synthetic/service/target/c")?;
        let package = c.package(expires)?;
        let mut old = c.fork()?;
        let (original_add, original_welcome) = actor::add(&a, package.clone())?;
        b.apply(&original_add)?;
        old.join(&original_welcome)?;
        let old_message = a.send(b"synthetic pre-recovery")?;
        old.receive(&old_message, b"synthetic pre-recovery")?;
        let actors = BTreeMap::from([
            ("a".into(), a),
            ("b".into(), b),
            ("c".into(), c),
            ("old".into(), old),
            ("before_add".into(), before),
        ]);
        Ok(Self {
            actors,
            original_add,
            original_welcome,
            original_package: package,
            old_message,
            replacement: vec![],
            welcome: vec![],
            package: None,
            old_expires: expires,
            new_expires: 0,
        })
    }
    fn get(&self, name: &str) -> Result<&Actor, String> {
        self.actors
            .get(name)
            .ok_or_else(|| format!("missing actor {name}"))
    }
    fn get_mut(&mut self, name: &str) -> Result<&mut Actor, String> {
        self.actors
            .get_mut(name)
            .ok_or_else(|| format!("missing actor {name}"))
    }
    fn fork(&mut self, name: &str) -> Result<Actor, String> {
        self.get_mut(name)?.fork()
    }
    fn facts(&self) -> Result<Value, String> {
        let mut facts = serde_json::Map::new();
        for (name, actor) in &self.actors {
            if actor.group_id.is_some() {
                facts.insert(name.clone(), actor.fact()?);
            }
        }
        Ok(Value::Object(facts))
    }
}
#[derive(Serialize, Deserialize)]
struct State {
    phase: String,
    normal: Fixture,
    expired_tree: Fixture,
}

fn key(path: &Path) -> Result<[u8; 32], String> {
    checked("read snapshot key", fs::read(path.join("state.key")))?
        .try_into()
        .map_err(|_| "invalid snapshot key".into())
}
fn save(path: &Path, state: &mut State) -> Result<(), String> {
    for fixture in [&mut state.normal, &mut state.expired_tree] {
        for actor in fixture.actors.values_mut() {
            actor.capture()?;
        }
    }
    checked(
        "save snapshot",
        openmls_probe::snapshot::save(
            &path.join("state.enc"),
            &key(path)?,
            CONTEXT,
            &checked("serialize snapshot", serde_json::to_vec(state))?,
            openmls_probe::snapshot::Failpoint::None,
        ),
    )
}
fn load(path: &Path) -> Result<State, String> {
    let bytes = checked(
        "load snapshot",
        openmls_probe::snapshot::load(&path.join("state.enc"), &key(path)?, CONTEXT),
    )?;
    let mut state: State = checked("decode snapshot", serde_json::from_slice(&bytes))?;
    for fixture in [&mut state.normal, &mut state.expired_tree] {
        for actor in fixture.actors.values_mut() {
            actor.restore()?;
        }
    }
    Ok(state)
}

pub(super) fn run(phase: &str, path: &Path) -> Result<Value, String> {
    if matches!(phase, "old-secrets-init" | "old-secrets-attack") {
        return old_secrets::run(phase, path);
    }
    let started = now()?;
    let mut report = json!({"phase":phase,"started_utc_seconds":started,"pid":std::process::id(),
        "scope":"isolated MLS mechanism only; no business recovery authorization/ledger","status":"RUNNING"});
    let mut state = if phase == "init" {
        ensure(!path.join("state.enc").exists(), "existing run state")?;
        let mut bytes = [0; 32];
        checked("random snapshot key", getrandom::getrandom(&mut bytes))?;
        let mut file = checked(
            "create snapshot key",
            fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path.join("state.key")),
        )?;
        checked("write snapshot key", file.write_all(&bytes))?;
        let expires = now()? + 8;
        State {
            phase: "init".into(),
            normal: Fixture::init(false, expires)?,
            expired_tree: Fixture::init(true, expires)?,
        }
    } else {
        load(path)?
    };
    report["before"] = state.normal.facts()?;
    match phase {
        "init" => {
            report["wait_until_utc_seconds"] = json!(state.normal.old_expires + 1);
        }
        "recover" => {
            ensure(state.phase == "init", "phase order")?;
            report["cases"] = cases::recover(&mut state.normal)?;
            report["expired_survivor"] = cases::expired_tree(&mut state.expired_tree)?;
            state.phase = "recover".into();
            report["wait_until_utc_seconds"] = json!(state.normal.new_expires + 1);
        }
        "late" => {
            ensure(state.phase == "recover", "phase order")?;
            report["cases"] = cases::late(&mut state.normal)?;
            state.phase = "late".into();
        }
        _ => return Err("unknown phase".into()),
    }
    report["after"] = state.normal.facts()?;
    report["old_expires_utc_seconds"] = json!(state.normal.old_expires);
    report["new_expires_utc_seconds"] = json!(state.normal.new_expires);
    save(path, &mut state)?;
    report["snapshot_sha256"] = json!(digest(&checked(
        "snapshot digest",
        fs::read(path.join("state.enc"))
    )?));
    report["finished_utc_seconds"] = json!(now()?);
    report["status"] = json!("PASS_SCOPED");
    Ok(report)
}
