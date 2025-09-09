// tools/src/bin/client.rs
// TQUIC Client: 发送真实文件（Datagram/Stream），固定码率整形，丰富日志，CSV 可选。
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use clap::Parser;
use log::{debug, error, info};
use mio::event::Event;
use tquic::{Config, Connection, Endpoint, Error, PacketInfo, TlsConfig, TransportHandler, CongestionControlAlgorithm};
use tquic_tools::qskt::{QuicSocket, Result};

#[cfg(unix)]
use std::os::unix::fs::FileExt;

#[cfg(unix)]
fn read_exact_at_cross(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    f.read_exact_at(buf, off)
}

#[cfg(windows)]
fn read_exact_at_cross(f: &File, mut buf: &mut [u8], off: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut done = 0;
    while done < buf.len() {
        let n = f.seek_read(&mut buf[done..], off + done as u64)?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        done += n;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Datagram,
    Stream,
}
impl std::str::FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "datagram" | "dg" => Ok(Mode::Datagram),
            "stream" | "str" => Ok(Mode::Stream),
            _ => Err(format!("invalid mode: {s}")),
        }
    }
}

// 与服务端相同的 Datagram 头
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct DgHdr {
    file_id: u64,
    total_size: u64,
    offset: u64,
    len: u32,
    flags: u8,
    _pad: [u8; 3],
    send_ts_ns: u64,
}
impl DgHdr {
    const SIZE: usize = 40;
    fn write_to(&self, b: &mut BytesMut) {
        b.put_u64_le(self.file_id);
        b.put_u64_le(self.total_size);
        b.put_u64_le(self.offset);
        b.put_u32_le(self.len);
        b.put_u8(self.flags);
        b.put_u8(0);
        b.put_u8(0);
        b.put_u8(0);
        b.put_u64_le(self.send_ts_ns);
    }
}

#[derive(Parser, Debug, Clone)]
#[clap(name = "client")]
pub struct ClientOpt {
    /// Log level
    #[clap(long, default_value = "INFO")]
    pub log_level: log::LevelFilter,

    /// Server addr
    #[clap(short, long)]
    pub connect_to: SocketAddr,

    /// Idle timeout (us)
    #[clap(long, default_value = "5_000_000")]
    pub idle_timeout: u64,

    /// session/qlog/keylog
    #[clap(long)]
    pub session_file: Option<String>,
    #[clap(long)]
    pub keylog_file: Option<String>,
    #[clap(long)]
    pub qlog_file: Option<String>,

    /// DATAGRAM local config
    #[clap(long, default_value = "1200")]
    pub max_datagram_frame_size: usize,
    #[clap(long, default_value = "500000")]
    pub send_timeout: u64,
    #[clap(long, default_value = "31")]
    pub priority: u8,
    #[clap(long, default_value = "31")]
    pub datagram_event_mask: u8,

    /// Mode: datagram|stream
    #[clap(long, default_value = "datagram")]
    pub mode: Mode,

    /// File to send
    #[clap(long, value_parser)]
    pub in_file: PathBuf,

    /// Chunk bytes (建议≈1200)
    #[clap(long, default_value = "1200")]
    pub chunk_bytes: usize,

    /// Rate shaping (Mbps)
    #[clap(long, default_value = "10.0")]
    pub rate_mbps: f64,

    /// CSV for send logs (optional)
    #[clap(long)]
    pub csv_send: Option<String>,

    /// CCA name (optional)
    #[clap(long)]
    pub cca: Option<String>,
}

const MAX_BUF_SIZE: usize = 64 * 1024;

struct Client {
    endpoint: Endpoint,
    poll: mio::Poll,
    sock: Rc<QuicSocket>,
    context: Rc<std::cell::RefCell<ClientContext>>,
    recv_buf: Vec<u8>,
}

impl Client {
    fn new(opt: &ClientOpt) -> Result<Self> {
        let mut cfg = Config::new()?;
        cfg.set_max_idle_timeout(opt.idle_timeout);
        if let Some(cca) = &opt.cca {
            info!("set CCA={cca} (hook here if API available)");
            let cca = match cca.as_str() {
                "Cubic" => CongestionControlAlgorithm::Cubic,
                "Bbr" => CongestionControlAlgorithm::Bbr,
                "Copa" => CongestionControlAlgorithm::Copa,
                _ => {
                    error!("unknown CCA: {cca}");
                    return Err(format!("unknown CCA: {cca}").into());
                }
            };
            cfg.set_congestion_control_algorithm(cca);
        }

        let tls = TlsConfig::new_client_config(vec![b"http/0.9".to_vec()], false)?;
        cfg.set_tls_config(tls);

        // DATAGRAM 本地配置
        cfg.set_local_datagram_config(
            opt.max_datagram_frame_size as u64,
            opt.send_timeout,
            opt.priority,
            opt.datagram_event_mask,
        );

        let ctx = Rc::new(std::cell::RefCell::new(ClientContext { finish: false }));
        let handler = ClientHandler::new(opt, ctx.clone());

        let poll = mio::Poll::new()?;
        let registry = poll.registry();
        let sock = Rc::new(QuicSocket::new_client_socket(
            opt.connect_to.is_ipv4(),
            registry,
        )?);

        Ok(Self {
            endpoint: Endpoint::new(Box::new(cfg), false, Box::new(handler), sock.clone()),
            poll,
            sock,
            context: ctx,
            recv_buf: vec![0u8; MAX_BUF_SIZE],
        })
    }

    fn finish(&self) -> bool {
        self.context.borrow().finish
    }

    fn process_read_event(&mut self, ev: &Event) -> Result<()> {
        loop {
            let (len, local, remote) = match self.sock.recv_from(&mut self.recv_buf, ev.token()) {
                Ok(v) => v,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break;
                    }
                    return Err(format!("socket recv error: {:?}", e).into());
                }
            };
            let pkt_info = PacketInfo {
                src: remote,
                dst: local,
                time: Instant::now(),
            };
            if let Err(e) = self.endpoint.recv(&mut self.recv_buf[..len], &pkt_info) {
                error!("endpoint.recv error: {e:?}");
            }
        }
        Ok(())
    }
}

struct ClientContext {
    finish: bool,
}

struct ClientHandler {
    // options
    mode: Mode,
    in_file: PathBuf,
    chunk: usize,
    bytes_per_sec: usize,

    // state
    file: File,
    total_size: u64,
    sent_bytes: u64,
    file_id: u64,

    // pacing
    interval_per_chunk: Duration,
    next_deadline: Instant,

    // stream
    stream_id: Option<u64>,

    // logs
    csv: Option<File>,
}

impl ClientHandler {
    fn new(opt: &ClientOpt, _ctx: Rc<std::cell::RefCell<ClientContext>>) -> Self {
        let file = File::open(&opt.in_file).expect("open input file");
        let total_size = file.metadata().unwrap().len();
        let bytes_per_sec = (opt.rate_mbps * 1e6 / 8.0) as usize;
        let interval = Duration::from_secs_f64(opt.chunk_bytes as f64 / bytes_per_sec as f64);

        // 简单 file_id：hash(路径 + 大小)
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        opt.in_file.hash(&mut hasher);
        (total_size as usize).hash(&mut hasher);
        let file_id = hasher.finish();

        let csv = match &opt.csv_send {
            Some(p) => {
                if let Some(parent) = std::path::Path::new(p).parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                Some(
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(p)
                        .unwrap(),
                )
            }
            None => None,
        };

        Self {
            mode: opt.mode,
            in_file: opt.in_file.clone(),
            chunk: opt.chunk_bytes,
            bytes_per_sec,
            file,
            total_size,
            sent_bytes: 0,
            file_id,
            interval_per_chunk: interval,
            next_deadline: Instant::now(),
            stream_id: None,
            csv,
        }
    }

    fn log_send(&mut self, now_ns: u64, off: u64, sz: usize, mode: &str) {
        if let Some(f) = &mut self.csv {
            let _ = writeln!(
                f,
                "send,{},{:016x},{},{},{}",
                now_ns, self.file_id, off, sz, mode
            );
        }
    }

    fn try_send_more(&mut self, conn: &mut Connection) {
        if self.sent_bytes >= self.total_size {
            let _ = conn.close(true, 0x00, b"ok");
            return;
        }

        while self.sent_bytes < self.total_size && Instant::now() >= self.next_deadline {
            let remaining = (self.total_size - self.sent_bytes) as usize;
            let payload_size = remaining.min(self.chunk);

            match self.mode {
                Mode::Datagram => {
                    // 从文件读取 payload
                    let mut buf = vec![0u8; payload_size];
                    let off = self.sent_bytes;
                    if let Err(e) = read_exact_at_cross(&self.file, &mut buf, off) {
                        error!("file read_exact_at error: {e:?}");
                        break;
                    }
                    // 构造 datagram: header + payload
                    let mut packet = BytesMut::with_capacity(DgHdr::SIZE + payload_size);
                    let hdr = DgHdr {
                        file_id: self.file_id,
                        total_size: self.total_size,
                        offset: off,
                        len: payload_size as u32,
                        flags: if (off + payload_size as u64) >= self.total_size {
                            1
                        } else {
                            0
                        },
                        _pad: [0, 0, 0],
                        send_ts_ns: monotonic_ns(),
                    };
                    hdr.write_to(&mut packet);
                    packet.extend_from_slice(&buf);
                    match conn.datagram_send(packet.freeze(), None, true) {
                        Ok(()) | Err(Error::Done) => {
                            self.log_send(hdr.send_ts_ns, off, payload_size, "datagram");
                            self.sent_bytes += payload_size as u64;
                        }
                        Err(e) => {
                            error!("datagram_send error: {e:?}");
                            break;
                        }
                    }
                }
                Mode::Stream => {
                    // 在 on_conn_established 里调用并保存 sid
                    let sid = match self.stream_id {
                        Some(s) => s,
                        None => {
                            error!("no stream id");
                            break;
                        }
                    };
                    // 从文件读取
                    let mut buf = vec![0u8; payload_size];
                    let off = self.sent_bytes;
                    if let Err(e) = read_exact_at_cross(&self.file, &mut buf, off) {
                        error!("file read_exact_at error: {e:?}");
                        break;
                    }
                    match conn.stream_write(
                        sid,
                        Bytes::from(buf),
                        (off + payload_size as u64) >= self.total_size,
                    ) {
                        Ok(_) | Err(Error::Done) => {
                            self.log_send(monotonic_ns(), off, payload_size, "stream");
                            self.sent_bytes += payload_size as u64;
                        }
                        Err(e) => {
                            error!("stream_write error: {e:?}");
                            break;
                        }
                    }
                }
            }

            self.next_deadline += self.interval_per_chunk;
            if self.sent_bytes % (1024 * 1024) as u64 == 0 {
                info!(
                    "[PROGRESS] {}/{} bytes ({:.1}%)",
                    self.sent_bytes,
                    self.total_size,
                    (self.sent_bytes as f64 * 100.0 / self.total_size as f64)
                );
            }
        }
    }
}

impl TransportHandler for ClientHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        info!(
            "{} conn created, mode={:?}, file={}, total={}B, file_id={:016x}",
            conn.trace_id(),
            self.mode,
            self.in_file.display(),
            self.total_size,
            self.file_id
        );
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        info!("{} conn established", conn.trace_id());
        // 如果你们 fork 有 open_uni()，可在这里：
        let sid = conn.stream_bidi_new(3, true).unwrap_or(0);
        self.stream_id = Some(sid);
        self.next_deadline = Instant::now();
        self.try_send_more(conn);
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        info!(
            "{} conn closed (sent {} bytes)",
            conn.trace_id(),
            self.sent_bytes
        );
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, _stream_id: u64) {
        self.try_send_more(conn);
        if self.sent_bytes >= self.total_size {
            let _ = conn.close(true, 0x00, b"ok");
        }
    }

    fn on_stream_readable(&mut self, _conn: &mut Connection, _stream_id: u64) {
        // 客户端无需读
    }

    fn on_stream_created(&mut self, conn: &mut Connection, sid: u64) {
        debug!("{} stream {} created", conn.trace_id(), sid);
        // 可在这里保存 sid 用于 stream 发送（如果你们依赖创建回调）
        if self.stream_id.is_none() {
            self.stream_id = Some(sid);
        }
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, sid: u64) {
        info!("{} stream {} closed", conn.trace_id(), sid);
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}

    // datagram 事件用于继续推进发送
    fn on_datagram_acked(&mut self, conn: &mut Connection) {
        self.try_send_more(conn);
    }
    fn on_datagram_drop(&mut self, conn: &mut Connection) {
        self.try_send_more(conn);
    }
    fn on_datagram_longtime(&mut self, conn: &mut Connection) {
        self.try_send_more(conn);
    }
    fn on_datagram_losted(&mut self, conn: &mut Connection) {
        self.try_send_more(conn);
    }
    fn on_datagram_recvived(&mut self, _conn: &mut Connection) {}
}

// 小工具
fn monotonic_ns() -> u64 {
    use std::time::Instant;
    thread_local! { static START: Instant = Instant::now(); }
    START.with(|s| s.elapsed().as_nanos() as u64)
}

fn main() -> Result<()> {
    let opt = ClientOpt::parse();
    env_logger::builder().filter_level(opt.log_level).init();

    let mut cli = Client::new(&opt)?;
    cli.endpoint.connect(
        cli.sock.local_addr(),
        opt.connect_to,
        None,
        None,
        None,
        None,
    )?;

    let mut events = mio::Events::with_capacity(1024);
    loop {
        cli.endpoint.process_connections()?;
        if cli.finish() {
            break;
        }

        cli.poll.poll(&mut events, cli.endpoint.timeout())?;
        for ev in events.iter() {
            if ev.is_readable() {
                cli.process_read_event(ev)?;
            }
        }
        cli.endpoint.on_timeout(Instant::now());
    }
    Ok(())
}
