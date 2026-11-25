//! 已知原件的可重复计量；不保存另一份秘密候选，也不执行密码输入。
use super::{
    capacity_types::*,
    data::Saved,
    metering::{self, RESOURCES},
    types::*,
};

pub(super) const VERSION: &str = "known-v1";
pub(super) struct Proof {
    pub used: [usize; 9],
    pub peak: [usize; 9],
    pub candidate: bool,
    pub recovery: bool,
    pub sends: usize,
    pub controls: usize,
    pub reports: usize,
}
impl Proof {
    fn include(&mut self, s: &Saved) -> Result<()> {
        let mut stage = s.clone();
        // 字段在原Meta中实际编码为82字节；已启用时不能重复加额。
        if stage.meta.backup_guard.is_none() {
            stage.meta.backup_guard = Some("0".repeat(64));
        }
        for (peak, used) in self.peak.iter_mut().zip(metering::usage(&stage)?) {
            *peak = (*peak).max(used);
        }
        Ok(())
    }
    pub fn fits(&self) -> bool {
        self.peak
            .iter()
            .zip(RESOURCES)
            .all(|(n, (_, _, limit))| *n <= limit)
    }
    pub fn public(&self) -> CapacityReserve {
        CapacityReserve {
            state: "bounded_ready".into(),
            protected_remaining: None,
            ordinary_available: None,
            resources: RESOURCES
                .iter()
                .enumerate()
                .map(|(i, (category, _, limit))| CapacityReservedResource {
                    category: (*category).into(),
                    protected_remaining: self.peak[i].saturating_sub(self.used[i]).to_string(),
                    ordinary_available: limit.saturating_sub(self.peak[i]).to_string(),
                })
                .collect(),
            work: vec![
                CapacityReservedWork {
                    kind: "candidate_install".into(),
                    count: usize::from(self.candidate).to_string(),
                },
                CapacityReservedWork {
                    kind: "send_settlement".into(),
                    count: self.sends.to_string(),
                },
                CapacityReservedWork {
                    kind: "known_control".into(),
                    count: self.controls.to_string(),
                },
                CapacityReservedWork {
                    kind: "known_report".into(),
                    count: self.reports.to_string(),
                },
                CapacityReservedWork {
                    kind: "target_install".into(),
                    count: usize::from(self.recovery).to_string(),
                },
                CapacityReservedWork {
                    kind: "backup_guard".into(),
                    count: "1".into(),
                },
            ],
        }
    }
}
pub(super) fn prove(s: &Saved) -> Result<Proof> {
    let used = metering::usage(s)?;
    let mut proof = Proof {
        used,
        peak: used,
        candidate: false,
        recovery: false,
        sends: 0,
        controls: 0,
        reports: 0,
    };
    proof.include(s)?;
    let mut next = s.clone();
    if !s.meta.blocks_operations()
        && s.meta
            .journal
            .as_ref()
            .is_some_and(|j| j.candidate.is_some())
    {
        next = super::journal::installed(s)?;
        proof.candidate = true;
        proof.include(&next)?;
    } else if let Some(receipt) = super::network::install_receipt(s)? {
        next = super::recovery_finish::finished(s.clone(), receipt)?;
        proof.recovery = true;
        proof.include(&next)?;
    }
    // 保留原授权/未知门禁。只保证这里列出的本地字节，不能推导连接或远端完成。
    let work = super::network::project_known(&mut next)?;
    proof.sends = work.0;
    proof.controls = work.1;
    proof.reports = work.2;
    proof.peak[3] = proof.peak[3].max(work.3);
    proof.include(&next)?;
    Ok(proof)
}
pub(super) fn check(s: &Saved) -> Result<()> {
    if s.meta.reserve_version.is_some() && !prove(s)?.fits() {
        return Err(Error::new("capacity_reserved"));
    }
    Ok(())
}
