//! 默认关闭的保存屏障只暂停真实时钟，不替换时间、不改 MLS 或验证结果。
use super::{checked, ensure, LabError};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

pub(super) fn before_final_sample() -> Result<(), LabError> {
    let Some(path) = std::env::var_os("RIM_WITNESS_FINAL_SAVE_BARRIER") else {
        return Ok(());
    };
    let path = PathBuf::from(path);
    ensure(
        path.is_absolute() && path.is_dir(),
        "probe",
        "保存屏障须为已存在绝对目录",
    )?;
    checked(
        "probe",
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path.join("arrived")),
    )?;
    let start = Instant::now();
    while !path
        .join("release")
        .try_exists()
        .map_err(|e| LabError::new("probe", e.to_string()))?
    {
        ensure(
            start.elapsed() < Duration::from_secs(60),
            "probe",
            "保存屏障超时",
        )?;
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
