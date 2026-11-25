//! 每次请求共享绝对截止时刻，防止分片/慢速字节持续刷新socket相对超时。
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};
pub(super) struct DeadlineStream {
    pub stream: TcpStream,
    until: Instant,
}
impl DeadlineStream {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            until: Instant::now() + Duration::from_secs(3),
        }
    }
    pub fn reset(&mut self) {
        self.until = Instant::now() + Duration::from_secs(1);
    }
    fn remaining(&self) -> io::Result<Duration> {
        self.until
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "network deadline"))
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_bytes_do_not_extend_request_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (receiver, _) = listener.accept().unwrap();
        let thread = std::thread::spawn(move || {
            for _ in 0..20 {
                if sender.write_all(&[1]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let mut stream = DeadlineStream::new(receiver);
        stream.reset();
        let start = Instant::now();
        let error = stream.read_exact(&mut [0; 20]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        assert!(start.elapsed() < Duration::from_millis(1600));
        drop(stream);
        thread.join().unwrap();
    }
}
