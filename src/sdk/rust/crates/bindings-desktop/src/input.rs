//! IPC读取线程只收有界帧；业务、密码与网络由SDK协调者持有。
use std::{
    io::{self, BufRead, Read},
    sync::mpsc::{self, Receiver},
    thread,
};
pub(super) fn start() -> Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::sync_channel(8);
    thread::spawn(move || {
        let mut input = io::stdin().lock();
        loop {
            let mut line = Vec::new();
            match (&mut input)
                .take(1024 * 1024 + 1)
                .read_until(b'\n', &mut line)
            {
                Ok(count) if count > 0 && count <= 1024 * 1024 && line.ends_with(b"\n") => {
                    if sender.send(line).is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    });
    // 读取者在stdin关闭时退出；主动close时进程退出回收，不持有数据库/密钥对象。
    receiver
}
