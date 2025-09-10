// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fs::File;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Instant;

use bytes::Bytes;
use clap::Parser;
use log::debug;
use log::error;
use log::info;
use mio::event::Event;
use tquic::Config;
use tquic::Connection;
use tquic::Endpoint;
use tquic::Error;
use tquic::PacketInfo;
use tquic::TlsConfig;
use tquic::TransportHandler;
use tquic_tools::qskt::QuicSocket;
use tquic_tools::qskt::Result;

#[derive(Parser, Debug)]
#[clap(name = "server")]
pub struct ServerOpt {
    /// TLS certificate in PEM format.
    #[clap(
        short,
        long = "cert",
        default_value = "./cert.crt",
        value_name = "FILE"
    )]
    pub cert_file: String,

    /// TLS private key in PEM format.
    #[clap(short, long = "key", default_value = "./cert.key", value_name = "FILE")]
    pub key_file: String,

    /// Log level, support OFF/ERROR/WARN/INFO/DEBUG/TRACE.
    #[clap(long, default_value = "INFO")]
    pub log_level: log::LevelFilter,

    /// Address to listen.
    #[clap(short, long, default_value = "0.0.0.0:4433", value_name = "ADDR")]
    pub listen: SocketAddr,

    /// Connection idle timeout in microseconds.
    #[clap(long, default_value = "5000", value_name = "TIME")]
    pub idle_timeout: u64,

    /// Save TLS key log into the given file.
    #[clap(long, value_name = "FILE")]
    pub keylog_file: Option<String>,

    /// Save QUIC qlog into the given file.
    #[clap(long, value_name = "FILE")]
    pub qlog_file: Option<String>,

    /// Maximum datagram frame size in bytes (for DATAGRAM extension).
    #[clap(long, default_value = "1200", value_name = "SIZE")]
    pub max_datagram_frame_size: usize,

    /// Send timeout (in microseconds) for datagrams.
    #[clap(long, default_value = "5000000", value_name = "US")]
    pub send_timeout: u64,

    /// Datagram priority (relative to streams).
    #[clap(long, default_value = "31", value_name = "PRIO")]
    pub priority: u8,

    /// Datagram event mask (bitwise OR of DatagramEventMask flags).
    #[clap(long, value_name = "MASK", default_value = "31")]
    pub datagram_event_mask: u8,

    /// Outgoing datagram buffer size in bytes.
    #[clap(long, default_value = "1048576", value_name = "SIZE")]
    pub datagram_out_size: u64,

    /// Incoming datagram buffer size in bytes.
    #[clap(long, default_value = "1048576", value_name = "SIZE")]
    pub datagram_in_size: u64,
}

const MAX_BUF_SIZE: usize = 65536;

/// A simple HTTP/0.9 server over QUIC.
struct Server {
    /// QUIC endpoint
    endpoint: Endpoint,

    /// Event poll
    poll: mio::Poll,

    /// Listen socket
    sock: Rc<QuicSocket>,

    /// Packet read buffer
    recv_buf: Vec<u8>,
}

impl Server {
    fn new(option: &ServerOpt) -> Result<Self> {
        let mut config = Config::new()?;
        config.set_max_idle_timeout(option.idle_timeout);
        let application_protos = vec![b"http/0.9".to_vec()];
        let tls_config = TlsConfig::new_server_config(
            &option.cert_file,
            &option.key_file,
            application_protos,
            true,
        )?;
        config.set_tls_config(tls_config);

        let poll = mio::Poll::new()?;
        let registry = poll.registry();

        let handlers = ServerHandler::new(option)?;
        let sock = Rc::new(QuicSocket::new(&option.listen, registry)?);

        // Set max_datagram_frame_size
        config.set_local_datagram_config(
            option.max_datagram_frame_size as u64,
            option.send_timeout,
            option.priority,
            option.datagram_event_mask,
            option.datagram_out_size,
            option.datagram_in_size,
        );

        Ok(Server {
            endpoint: Endpoint::new(Box::new(config), true, Box::new(handlers), sock.clone()),
            poll,
            sock,
            recv_buf: vec![0u8; MAX_BUF_SIZE],
        })
    }

    pub fn process_read_event(&mut self, event: &Event) -> Result<()> {
        loop {
            let (len, local, remote) = match self.sock.recv_from(&mut self.recv_buf, event.token())
            {
                Ok(v) => v,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        log::debug!("socket recv would block");
                        break;
                    }
                    return Err(format!("socket recv error: {:?}", e).into());
                }
            };
            log::debug!("socket recv recv {} bytes from {:?}", len, remote);

            let pkt_buf = &mut self.recv_buf[..len];
            let pkt_info = PacketInfo {
                src: remote,
                dst: local,
                time: Instant::now(),
            };

            // Process the incoming packet.
            match self.endpoint.recv(pkt_buf, &pkt_info) {
                Ok(_) => {}
                Err(e) => {
                    log::error!("recv failed: {:?}", e);
                    continue;
                }
            };
        }

        Ok(())
    }
}
struct ServerHandler {
    /// Read buffer
    buf: Vec<u8>,

    /// SSL key logger
    keylog: Option<File>,

    /// Qlog file
    qlog: Option<File>,
}

impl ServerHandler {
    fn new(option: &ServerOpt) -> Result<Self> {
        let keylog = match &option.keylog_file {
            Some(keylog_file) => Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(keylog_file)?,
            ),
            None => None,
        };

        let qlog = match &option.qlog_file {
            Some(qlog_file) => Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(qlog_file)?,
            ),
            None => None,
        };

        Ok(Self {
            buf: vec![0; MAX_BUF_SIZE],
            keylog,
            qlog,
        })
    }
}

impl TransportHandler for ServerHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        print!("{} connection is created", conn.trace_id());

        if let Some(keylog) = &mut self.keylog {
            if let Ok(keylog) = keylog.try_clone() {
                conn.set_keylog(Box::new(keylog));
            }
        }

        if let Some(qlog) = &mut self.qlog {
            if let Ok(qlog) = qlog.try_clone() {
                conn.set_qlog(
                    Box::new(qlog),
                    "server qlog".into(),
                    format!("id={}", conn.trace_id()),
                );
            }
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        debug!("{} connection is established", conn.trace_id());
        let data = Bytes::from("Hallo, World");
        match conn.datagram_send(data.clone(), Some(data.len()), true) {
            Ok(()) => {
                info!(
                    "{} connection succeed to send a datagram:{:?}",
                    conn.trace_id(),
                    data
                );
            }
            Err(_e) => {
                error!("{} failed to send datagram: {}", conn.trace_id(), _e);
            }
        }
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        debug!("connection[{:?}] is closed", conn.trace_id());
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is created", conn.trace_id(), stream_id,);
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is readable", conn.trace_id(), stream_id,);
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is writable", conn.trace_id(), stream_id,);
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is closed", conn.trace_id(), stream_id,);
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
    fn on_datagram_acked(&mut self, _conn: &mut Connection) {
        debug!("{} connection has a datagram acked", _conn.trace_id());
    }
    fn on_datagram_drop(&mut self, _conn: &mut Connection) {
        debug!("{} connection dropped a datagram", _conn.trace_id());
    }
    fn on_datagram_longtime(&mut self, _conn: &mut Connection) {
        debug!(
            "{} connection has a datagram beyond the limited of time",
            _conn.trace_id()
        );
    }
    fn on_datagram_lost(&mut self, _conn: &mut Connection) {
        debug!("{} connection has a datagram lost", _conn.trace_id());
    }
    fn on_datagram_recvived(&mut self, _conn: &mut Connection) {
        let data = if _conn.datagram_readable() {
            _conn.datagram_recv().unwrap()
        } else {
            debug!("why cannot read");
            return;
        };
        info!("server has recvived :{:?}", data);
        info!("{} connection recevived a datagram ", _conn.trace_id());

        match _conn.close(true, 0x00, b"ok") {
            Ok(_) | Err(Error::Done) => (),
            Err(e) => panic!(
                "error closing conn (trace_id: {}) : {:?}",
                _conn.trace_id(),
                e
            ),
        }
    }
}

fn main() -> Result<()> {
    let option = ServerOpt::parse();

    // Initialize logging.
    env_logger::builder().filter_level(option.log_level).init();

    // Create server.
    let mut server = Server::new(&option)?;

    // Run event loop.
    let mut events = mio::Events::with_capacity(1024);
    loop {
        // Process connections.
        if let Err(e) = server.endpoint.process_connections() {
            error!("process connections error: {:?}", e);
        }

        server.poll.poll(&mut events, server.endpoint.timeout())?;

        // Process IO events
        for event in events.iter() {
            if event.is_readable() {
                print!("error heppened here");
                server.process_read_event(event)?;
            }
        }

        // Process timeout events.
        // Note: Since `poll()` doesn't clearly tell if there was a timeout when it returns,
        // it is up to the endpoint to check for a timeout and deal with it.
        server.endpoint.on_timeout(Instant::now());
    }
}
