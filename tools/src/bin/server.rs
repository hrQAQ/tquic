// tools/src/bin/server.rs
// TQUIC Server: 接收真实文件（Datagram/Stream），丰富日志，CSV 可选。
// 依赖：tquic, tquic_tools, bytes, clap, log, env_logger, mio

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Instant;

use bytes::Buf; // 用于小端读取
use clap::Parser;
use log::{debug, error, info, warn};
use mio::event::Event;

use tquic::{Config, Connection, Endpoint, Error, PacketInfo, TlsConfig, TransportHandler, CongestionControlAlgorithm};
use tquic_tools::qskt::{QuicSocket, Result};

#[derive(Parser, Debug, Clone)]
#[clap(name = "server")]
pub struct ServerOpt {
    /// TLS certificate (PEM)
    #[clap(short, long = "cert", default_value = "./cert.crt")]
    pub cert_file: String,

    /// TLS private key (PEM)
    #[clap(short, long = "key", default_value = "./cert.key")]
    pub key_file: String,

    /// Log level
    #[clap(long, default_value = "INFO")]
    pub log_level: log::LevelFilter,

    /// Listen addr
    #[clap(short, long, default_value = "0.0.0.0:4433")]
    pub listen: SocketAddr,

    /// Idle timeout (us)
    #[clap(long, default_value = "5_000_000")]
    pub idle_timeout: u64,

    /// qlog/keylog
    #[clap(long)]
    pub keylog_file: Option<String>,
    #[clap(long)]
    pub qlog_file: Option<String>,

    /// DATAGRAM local config
    #[clap(long, default_value = "1200")]
    pub max_datagram_frame_size: usize,
    #[clap(long, default_value = "5000000")]
    pub send_timeout: u64,
    #[clap(long, default_value = "31")]
    pub priority: u8,
    #[clap(long, default_value = "31")]
    pub datagram_event_mask: u8,

    /// Directory to write received files
    #[clap(long, default_value = "results/recv")]
    pub out_dir: String,

    /// Flush frequency for CSV (every N records)
    #[clap(long, default_value = "200")]
    pub flush_every: usize,

    /// CSV path to write receive logs (optional)
    #[clap(long)]
    pub csv_recv: Option<String>,

    /// CCA name (optional)
    #[clap(long)]
    pub cca: Option<String>,
}

const MAX_BUF_SIZE: usize = 64 * 1024;

// Datagram header (40 bytes aligned)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct DgHdr {
    file_id: u64,
    total_size: u64,
    offset: u64,
    len: u32,
    flags: u8,       // bit0: last
    _pad: [u8; 3],   // align
    send_ts_ns: u64, // for E2E latency
}
impl DgHdr {
    const SIZE: usize = 40;
    fn parse(buf: &[u8]) -> Option<(DgHdr, &[u8])> {
        if buf.len() < Self::SIZE {
            return None;
        }
        let mut p = &buf[..];
        let file_id = p.get_u64_le();
        let total_size = p.get_u64_le();
        let offset = p.get_u64_le();
        let len = p.get_u32_le();
        let flags = p.get_u8();
        let _pad0 = p.get_u8();
        let _pad1 = p.get_u8();
        let _pad2 = p.get_u8();
        let send_ts_ns = p.get_u64_le();
        let payload = &buf[Self::SIZE..];
        Some((
            DgHdr {
                file_id,
                total_size,
                offset,
                len,
                flags,
                _pad: [0, 0, 0],
                send_ts_ns,
            },
            payload,
        ))
    }
    fn is_last(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

struct Server {
    endpoint: Endpoint,
    poll: mio::Poll,
    sock: Rc<QuicSocket>,
    recv_buf: Vec<u8>,
}

impl Server {
    fn new(opt: &ServerOpt) -> Result<Self> {
        let mut cfg = Config::new()?;
        cfg.set_max_idle_timeout(opt.idle_timeout);

        // 可选拥塞控制算法
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

        // TLS
        let alpn = vec![b"http/0.9".to_vec()];
        let tls = TlsConfig::new_server_config(&opt.cert_file, &opt.key_file, alpn, true)?;
        cfg.set_tls_config(tls);

        // DATAGRAM 本地配置
        cfg.set_local_datagram_config(
            opt.max_datagram_frame_size as u64,
            opt.send_timeout,
            opt.priority,
            opt.datagram_event_mask,
        );

        // 输出目录/CSV 目录
        std::fs::create_dir_all(&opt.out_dir).ok();
        if let Some(csvp) = &opt.csv_recv {
            if let Some(parent) = Path::new(csvp).parent() {
                std::fs::create_dir_all(parent).ok();
            }
        }

        let poll = mio::Poll::new()?;
        let registry = poll.registry();

        let handler = ServerHandler::new(opt)?;
        let sock = Rc::new(QuicSocket::new(&opt.listen, registry)?);

        Ok(Self {
            endpoint: Endpoint::new(Box::new(cfg), true, Box::new(handler), sock.clone()),
            poll,
            sock,
            recv_buf: vec![0u8; MAX_BUF_SIZE],
        })
    }

    fn process_read_event(&mut self, event: &Event) -> Result<()> {
        loop {
            let (len, local, remote) = match self.sock.recv_from(&mut self.recv_buf, event.token()) {
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

// Per-file receiving state (Datagram)
struct FileRx {
    path: PathBuf,
    f: File,
    total: u64,
    received_bytes: u64,
}

struct ServerHandler {
    // 收包缓冲
    buf: Vec<u8>,

    // 可选日志
    keylog: Option<File>,
    qlog: Option<File>,
    csv: Option<File>,
    csv_flush_every: usize,
    csv_count: usize,

    // 输出目录
    out_dir: PathBuf,

    // Datagram 文件表：file_id -> FileRx
    dgram_files: HashMap<u64, FileRx>,

    // Stream 文件表：stream_id -> FileRx
    stream_files: HashMap<u64, FileRx>,
}

impl ServerHandler {
    fn new(opt: &ServerOpt) -> Result<Self> {
        let keylog = match &opt.keylog_file {
            Some(p) => Some(OpenOptions::new().create(true).append(true).open(p)?),
            None => None,
        };
        let qlog = match &opt.qlog_file {
            Some(p) => Some(OpenOptions::new().create(true).append(true).open(p)?),
            None => None,
        };
        let csv = match &opt.csv_recv {
            Some(p) => Some(OpenOptions::new().create(true).append(true).open(p)?),
            None => None,
        };

        Ok(Self {
            buf: vec![0; MAX_BUF_SIZE],
            keylog,
            qlog,
            csv,
            csv_flush_every: opt.flush_every,
            csv_count: 0,
            out_dir: PathBuf::from(&opt.out_dir),
            dgram_files: HashMap::new(),
            stream_files: HashMap::new(),
        })
    }

    #[inline]
    fn csv_line(&mut self, line: &str) {
        if let Some(f) = &mut self.csv {
            let _ = writeln!(f, "{line}");
            self.csv_count += 1;
            if self.csv_count % self.csv_flush_every == 0 {
                let _ = f.flush();
            }
        }
    }

    fn get_or_create_dg_file(&mut self, file_id: u64, total: u64) -> std::io::Result<&mut FileRx> {
        if !self.dgram_files.contains_key(&file_id) {
            let filename = format!("dgram_{file_id:016x}_size{total}.bin");
            let path = self.out_dir.join(filename);
            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .read(true)
                .open(&path)?;
            self.dgram_files.insert(
                file_id,
                FileRx {
                    path,
                    f,
                    total,
                    received_bytes: 0,
                },
            );
        }
        Ok(self.dgram_files.get_mut(&file_id).unwrap())
    }

    fn finish_if_complete_dg(&mut self, file_id: u64) {
        if let Some(rx) = self.dgram_files.get(&file_id) {
            if let Ok(meta) = rx.f.metadata() {
                if meta.len() >= rx.total {
                    info!(
                        "[DGRAM] file_id={:016x} completed: {} bytes -> {}",
                        file_id,
                        rx.total,
                        rx.path.display()
                    );
                }
            }
        }
    }

    fn handle_datagram(&mut self, conn: &mut Connection) {
        // 逐个读完
        while let Some(bytes) = conn.datagram_recv() {
            let now_ns = monotonic_ns();
            if let Some((hdr, payload)) = DgHdr::parse(&bytes) {
                debug!(
                    "[DGRAM] recv: file_id={:016x} off={} len={} last={} total={} ts={} size={}B",
                    hdr.file_id,
                    hdr.offset,
                    hdr.len,
                    hdr.is_last(),
                    hdr.total_size,
                    hdr.send_ts_ns,
                    payload.len()
                );
                if (payload.len() as u32) < hdr.len {
                    warn!("[DGRAM] payload shorter than header.len");
                }
                // 建立/获取文件并写入（短作用域，避免和 &mut self 冲突）
                let write_ok = (|| -> std::io::Result<usize> {
                    let rx = self.get_or_create_dg_file(hdr.file_id, hdr.total_size)?;
                    rx.f.seek(SeekFrom::Start(hdr.offset))?;
                    let to_write = std::cmp::min(payload.len(), hdr.len as usize);
                    rx.f.write_all(&payload[..to_write])?;
                    Ok(to_write)
                })();

                match write_ok {
                    Ok(written) => {
                        self.csv_line(&format!(
                            "recv,{},{:016x},{},{},datagram",
                            now_ns, hdr.file_id, hdr.offset, written
                        ));
                        if hdr.is_last() {
                            self.finish_if_complete_dg(hdr.file_id);
                        }
                    }
                    Err(e) => error!("[DGRAM] write error: {e:?}"),
                }
            } else {
                warn!("[DGRAM] bad header, drop {}B", bytes.len());
            }
        }
    }

    fn handle_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        // 如未创建文件，先创建
        if !self.stream_files.contains_key(&stream_id) {
            let filename = format!("stream_{stream_id:016x}.bin");
            let path = self.out_dir.join(filename);
            match OpenOptions::new().create(true).write(true).open(&path) {
                Ok(f) => {
                    self.stream_files.insert(
                        stream_id,
                        FileRx {
                            path: path.clone(),
                            f,
                            total: 0,
                            received_bytes: 0,
                        },
                    );
                    info!("[STREAM] create file for stream {} -> {}", stream_id, path.display());
                }
                Err(e) => {
                    error!("[STREAM] open file error: {e:?}");
                    return;
                }
            }
        }

        loop {
            match conn.stream_read(stream_id, &mut self.buf) {
                Ok((n, fin)) => {
                    if n > 0 {
                        // 缩小 rx 可变借用作用域，避免与 self.csv_line 冲突
                        {
                            let rx = self.stream_files.get_mut(&stream_id).unwrap();
                            if let Err(e) = rx.f.write_all(&self.buf[..n]) {
                                error!("[STREAM] write error: {e:?}");
                                break;
                            }
                            rx.received_bytes += n as u64;
                        } // 这里结束 rx 的可变借用

                        let now = monotonic_ns();
                        self.csv_line(&format!("recv,{now},0,{n},stream"));
                    }

                    if fin {
                        // 再次短借用 flush，然后打印日志
                        let (total, path) = {
                            let rx = self.stream_files.get_mut(&stream_id).unwrap();
                            let _ = rx.f.flush();
                            (rx.received_bytes, rx.path.clone())
                        };
                        info!(
                            "[STREAM] {stream_id} finished: {total} bytes -> {}",
                            path.display()
                        );
                        break;
                    }
                }
                Err(Error::Done) => break,
                Err(e) => {
                    error!("[STREAM] read error: {e:?}");
                    break;
                }
            }
        }
    }
}

impl TransportHandler for ServerHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        info!("{} conn created", conn.trace_id());
        if let Some(k) = &mut self.keylog {
            if let Ok(k2) = k.try_clone() {
                conn.set_keylog(Box::new(k2));
            }
        }
        if let Some(q) = &mut self.qlog {
            if let Ok(q2) = q.try_clone() {
                conn.set_qlog(Box::new(q2), "server qlog".into(), format!("id={}", conn.trace_id()));
            }
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        info!("{} conn established", conn.trace_id());
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        info!("{} conn closed", conn.trace_id());
        if let Some(f) = &mut self.csv {
            let _ = f.flush();
        }
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} created", conn.trace_id(), stream_id);
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        self.handle_stream_readable(conn, stream_id);
    }

    fn on_stream_writable(&mut self, _conn: &mut Connection, _stream_id: u64) {}

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        info!("{} stream {} closed", conn.trace_id(), stream_id);
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}

    // ===== Datagram 回调 =====
    fn on_datagram_recvived(&mut self, conn: &mut Connection) {
        self.handle_datagram(conn);
    }
    fn on_datagram_acked(&mut self, conn: &mut Connection) {
        debug!("{} dgram acked", conn.trace_id());
    }
    fn on_datagram_drop(&mut self, conn: &mut Connection) {
        debug!("{} dgram drop", conn.trace_id());
    }
    fn on_datagram_longtime(&mut self, conn: &mut Connection) {
        debug!("{} dgram longtime", conn.trace_id());
    }
    fn on_datagram_losted(&mut self, conn: &mut Connection) {
        debug!("{} dgram losted", conn.trace_id());
    }
}

// 单调时钟（无 once_cell）
fn monotonic_ns() -> u64 {
    use std::time::Instant;
    thread_local! { static START: Instant = Instant::now(); }
    START.with(|s| s.elapsed().as_nanos() as u64)
}

fn main() -> Result<()> {
    let opt = ServerOpt::parse();
    env_logger::builder().filter_level(opt.log_level).init();

    let mut server = Server::new(&opt)?;
    let mut events = mio::Events::with_capacity(1024);

    loop {
        if let Err(e) = server.endpoint.process_connections() {
            error!("process connections error: {e:?}");
        }

        server.poll.poll(&mut events, server.endpoint.timeout())?;
        for ev in events.iter() {
            if ev.is_readable() {
                server.process_read_event(ev)?;
            }
        }
        server.endpoint.on_timeout(Instant::now());
    }
}
