//! 独立合成参与者；仅复用内存 provider 与原加密快照，不建立业务引擎。
use super::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(super) struct Actor {
    pub credential: CredentialWithKey,
    pub signer: SignatureKeyPair,
    pub group_id: Option<Vec<u8>>,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    #[serde(skip)]
    pub provider: OpenMlsRustCrypto,
}

impl Actor {
    pub fn new(name: &str) -> Result<Self, String> {
        let provider = OpenMlsRustCrypto::default();
        let signer = checked(
            "new signer",
            SignatureKeyPair::new(SUITE.signature_algorithm()),
        )?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Self {
            credential,
            signer,
            group_id: None,
            entries: vec![],
            provider,
        })
    }

    pub fn capture(&mut self) -> Result<(), String> {
        self.entries = checked("provider read", self.provider.storage().values.read())?
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        self.entries.sort();
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), String> {
        let mut values = checked("provider write", self.provider.storage().values.write())?;
        ensure(values.is_empty(), "restore requires empty provider")?;
        values.extend(self.entries.clone());
        Ok(())
    }

    // 仅用于攻击/离线测试分支；不把副本安装到业务端或用于正常恢复。
    pub fn fork(&mut self) -> Result<Self, String> {
        self.capture()?;
        let mut copy: Self = checked(
            "decode fork",
            serde_json::from_slice(&checked("encode fork", serde_json::to_vec(self))?),
        )?;
        copy.restore()?;
        Ok(copy)
    }

    pub fn package(&self, expires: u64) -> Result<KeyPackage, String> {
        let bundle = checked(
            "key package",
            KeyPackage::builder()
                .key_package_lifetime(Lifetime::init(now()? - 1, expires))
                .build(SUITE, &self.provider, &self.signer, self.credential.clone()),
        )?;
        Ok(bundle.key_package().clone())
    }

    pub fn create(&mut self) -> Result<(), String> {
        let group = checked(
            "create",
            MlsGroup::new(
                &self.provider,
                &self.signer,
                &MlsGroupCreateConfig::builder()
                    .ciphersuite(SUITE)
                    .use_ratchet_tree_extension(true)
                    .max_past_epochs(2)
                    .build(),
                self.credential.clone(),
            ),
        )?;
        self.group_id = Some(group.group_id().as_slice().to_vec());
        Ok(())
    }

    pub fn group(&self) -> Result<MlsGroup, String> {
        checked(
            "load group",
            MlsGroup::load(
                self.provider.storage(),
                &GroupId::from_slice(self.group_id.as_ref().ok_or("missing group id")?),
            ),
        )?
        .ok_or_else(|| "missing group".into())
    }

    pub fn join(&mut self, bytes: &[u8]) -> Result<(), String> {
        let message = checked("decode welcome", MlsMessageIn::tls_deserialize_exact(bytes))?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err("not welcome".into());
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(2)
            .build();
        let staged = checked(
            "stage welcome",
            StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None),
        )?;
        let group = checked("merge welcome", staged.into_group(&self.provider))?;
        self.group_id = Some(group.group_id().as_slice().to_vec());
        Ok(())
    }

    pub fn apply(&self, bytes: &[u8]) -> Result<(), String> {
        let mut group = self.group()?;
        let processed = checked(
            "process commit",
            group.process_message(&self.provider, protocol(bytes)?),
        )?;
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err("not commit".into());
        };
        checked(
            "merge commit",
            group.merge_staged_commit(&self.provider, *staged),
        )
    }

    pub fn send(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        checked(
            "message bytes",
            checked(
                "send",
                self.group()?
                    .create_message(&self.provider, &self.signer, plaintext),
            )?
            .to_bytes(),
        )
    }

    pub fn receive(&self, bytes: &[u8], expected: &[u8]) -> Result<(), String> {
        let message = checked(
            "receive",
            self.group()?
                .process_message(&self.provider, protocol(bytes)?),
        )?;
        let ProcessedMessageContent::ApplicationMessage(message) = message.into_content() else {
            return Err("not application".into());
        };
        ensure(message.into_bytes() == expected, "plaintext mismatch")
    }

    pub fn fact(&self) -> Result<Value, String> {
        let group = self.group()?;
        let members: Vec<_> = group.members().map(|m| json!({"leaf":m.index.u32(),
            "identity":digest(m.credential.serialized_content()),"signature":digest(&m.signature_key),
            "encryption":digest(&m.encryption_key)})).collect();
        Ok(
            json!({"group":digest(group.group_id().as_slice()),"epoch":group.epoch().as_u64(),
            "own_leaf":group.own_leaf_index().u32(),"active":group.is_active(),"members":members,
            "tree":digest(&checked("tree bytes",group.export_ratchet_tree().tls_serialize_detached())?)}),
        )
    }
}

pub(super) fn add(actor: &Actor, package: KeyPackage) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut group = actor.group()?;
    let (commit, welcome, _) = checked(
        "add",
        group.add_members(&actor.provider, &actor.signer, &[package]),
    )?;
    checked("merge add", group.merge_pending_commit(&actor.provider))?;
    Ok((
        checked("commit bytes", commit.to_bytes())?,
        checked("welcome bytes", welcome.to_bytes())?,
    ))
}
