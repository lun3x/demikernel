// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::{
    inetstack::{
        protocols::{
            ethernet2::{
                EtherType2,
                Ethernet2Header,
            },
            ipv4::Ipv4Header,
            tcp::{
                segment::{
                    TcpHeader,
                    TcpSegment,
                },
                SeqNumber,
            },
        },
        test_helpers::{
            self,
            SharedEngine,
        },
    },
    runtime::{
        fail::Fail,
        memory::DemiBuffer,
        network::{
            consts::RECEIVE_BATCH_SIZE,
            types::MacAddress,
            PacketBuf,
        },
        OperationResult,
        QDesc,
        QToken,
    },
};
use ::anyhow::Result;
use ::libc::EBADMSG;
use ::std::{
    net::{
        Ipv4Addr,
        SocketAddrV4,
    },
    time::{
        Duration,
        Instant,
    },
};

//======================================================================================================================
// Tests
//======================================================================================================================

/// Tests connection timeout.
#[test]
fn test_connection_timeout() -> Result<()> {
    let mut now: Instant = Instant::now();

    // Connection parameters
    let listen_port: u16 = 80;
    let listen_addr: SocketAddrV4 = SocketAddrV4::new(test_helpers::BOB_IPV4, listen_port);

    // Setup client.
    let mut client: SharedEngine<RECEIVE_BATCH_SIZE> = test_helpers::new_alice2(now);
    let nretries: usize = client.get_test_rig().get_tcp_config().get_handshake_retries();
    let timeout: Duration = client.get_test_rig().get_tcp_config().get_handshake_timeout();

    // T(0) -> T(1)
    advance_clock(None, Some(&mut client), &mut now);

    // Client: SYN_SENT state at T(1).
    let (_, qt, bytes): (QDesc, QToken, DemiBuffer) = connection_setup_listen_syn_sent(&mut client, listen_addr)?;

    // Sanity check packet.
    check_packet_pure_syn(
        bytes.clone(),
        test_helpers::ALICE_MAC,
        test_helpers::BOB_MAC,
        test_helpers::ALICE_IPV4,
        test_helpers::BOB_IPV4,
        listen_port,
    )?;

    for _ in 0..nretries {
        for _ in 0..timeout.as_secs() {
            advance_clock(None, Some(&mut client), &mut now);
        }
        client.get_test_rig().poll_scheduler();
    }

    match client
        .get_test_rig()
        .get_runtime()
        .remove_coroutine_with_qtoken(qt)
        .get_result()
    {
        None => Ok(()),
        Some((_, OperationResult::Failed(Fail { errno, cause: _ }))) if errno == libc::ETIMEDOUT => Ok(()),
        Some(result) => anyhow::bail!("connect should have timed out, instead returned: {:?}", result),
    }
}

/// Refuse a connection.
#[test]
fn test_refuse_connection_early_rst() -> Result<()> {
    let mut now = Instant::now();

    // Connection parameters
    let listen_port: u16 = 80;
    let listen_addr: SocketAddrV4 = SocketAddrV4::new(test_helpers::BOB_IPV4, listen_port);

    // Setup peers.
    let mut server: SharedEngine<RECEIVE_BATCH_SIZE> = test_helpers::new_bob2(now);
    let mut client: SharedEngine<RECEIVE_BATCH_SIZE> = test_helpers::new_alice2(now);

    // Server: LISTEN state at T(0).
    let _: QToken = connection_setup_closed_listen(&mut server, listen_addr)?;

    // T(0) -> T(1)
    advance_clock(Some(&mut server), Some(&mut client), &mut now);

    // Client: SYN_SENT state at T(1).
    let (_, _, bytes): (QDesc, QToken, DemiBuffer) = connection_setup_listen_syn_sent(&mut client, listen_addr)?;

    // Temper packet.
    let (eth2_header, ipv4_header, tcp_header): (Ethernet2Header, Ipv4Header, TcpHeader) =
        extract_headers(bytes.clone())?;
    let segment: TcpSegment = TcpSegment {
        ethernet2_hdr: eth2_header,
        ipv4_hdr: ipv4_header,
        tcp_hdr: TcpHeader {
            src_port: tcp_header.src_port,
            dst_port: tcp_header.dst_port,
            seq_num: tcp_header.seq_num,
            ack_num: tcp_header.ack_num,
            ns: tcp_header.ns,
            cwr: tcp_header.cwr,
            ece: tcp_header.ece,
            urg: tcp_header.urg,
            ack: tcp_header.ack,
            psh: tcp_header.psh,
            rst: true,
            syn: tcp_header.syn,
            fin: tcp_header.fin,
            window_size: tcp_header.window_size,
            urgent_pointer: tcp_header.urgent_pointer,
            num_options: tcp_header.num_options,
            option_list: tcp_header.option_list,
        },
        data: None,
        tx_checksum_offload: false,
    };

    // Serialize segment.
    let buf: DemiBuffer = serialize_segment(segment)?;

    // T(1) -> T(2)
    advance_clock(Some(&mut server), Some(&mut client), &mut now);

    // Server: SYN_RCVD state at T(2).
    match server.receive(buf) {
        Err(error) if error.errno == EBADMSG => Ok(()),
        _ => anyhow::bail!("server receive should have returned an error"),
    }
}

/// Refuse a connection.
#[test]
fn test_refuse_connection_early_ack() -> Result<()> {
    let mut now = Instant::now();

    // Connection parameters
    let listen_port: u16 = 80;
    let listen_addr: SocketAddrV4 = SocketAddrV4::new(test_helpers::BOB_IPV4, listen_port);

    // Setup peers.
    let mut server: SharedEngine<RECEIVE_BATCH_SIZE> = test_helpers::new_bob2(now);
    let mut client: SharedEngine<RECEIVE_BATCH_SIZE> = test_helpers::new_alice2(now);

    // Server: LISTEN state at T(0).
    let _: QToken = connection_setup_closed_listen(&mut server, listen_addr)?;

    // T(0) -> T(1)
    advance_clock(Some(&mut server), Some(&mut client), &mut now);

    // Client: SYN_SENT state at T(1).
    let (_, _, bytes): (QDesc, QToken, DemiBuffer) = connection_setup_listen_syn_sent(&mut client, listen_addr)?;

    // Temper packet.
    let (eth2_header, ipv4_header, tcp_header): (Ethernet2Header, Ipv4Header, TcpHeader) =
        extract_headers(bytes.clone())?;
    let segment: TcpSegment = TcpSegment {
        ethernet2_hdr: eth2_header,
        ipv4_hdr: ipv4_header,
        tcp_hdr: TcpHeader {
            src_port: tcp_header.src_port,
            dst_port: tcp_header.dst_port,
            seq_num: tcp_header.seq_num,
            ack_num: tcp_header.ack_num,
            ns: tcp_header.ns,
            cwr: tcp_header.cwr,
            ece: tcp_header.ece,
            urg: tcp_header.urg,
            ack: true,
            psh: tcp_header.psh,
            rst: tcp_header.rst,
            syn: tcp_header.syn,
            fin: tcp_header.fin,
            window_size: tcp_header.window_size,
            urgent_pointer: tcp_header.urgent_pointer,
            num_options: tcp_header.num_options,
            option_list: tcp_header.option_list,
        },
        data: None,
        tx_checksum_offload: false,
    };

    // Serialize segment.
    let buf: DemiBuffer = serialize_segment(segment)?;

    // T(1) -> T(2)
    advance_clock(Some(&mut server), Some(&mut client), &mut now);

    // Server: SYN_RCVD state at T(2).
    match server.receive(buf) {
        Err(error) if error.errno == EBADMSG => Ok(()),
        _ => anyhow::bail!("server receive should have returned an error"),
    }
}

/// Tests connection refuse due to missing syn.
#[test]
fn test_refuse_connection_missing_syn() -> Result<()> {
    let mut now = Instant::now();

    // Connection parameters
    let listen_port: u16 = 80;
    let listen_addr: SocketAddrV4 = SocketAddrV4::new(test_helpers::BOB_IPV4, listen_port);

    // Setup peers.
    let mut server: SharedEngine<RECEIVE_BATCH_SIZE> = test_helpers::new_bob2(now);
    let mut client: SharedEngine<RECEIVE_BATCH_SIZE> = test_helpers::new_alice2(now);

    // Server: LISTEN state at T(0).
    let _: QToken = connection_setup_closed_listen(&mut server, listen_addr)?;

    // T(0) -> T(1)
    advance_clock(Some(&mut server), Some(&mut client), &mut now);

    // Client: SYN_SENT state at T(1).
    let (_, _, bytes): (QDesc, QToken, DemiBuffer) = connection_setup_listen_syn_sent(&mut client, listen_addr)?;

    // Sanity check packet.
    check_packet_pure_syn(
        bytes.clone(),
        test_helpers::ALICE_MAC,
        test_helpers::BOB_MAC,
        test_helpers::ALICE_IPV4,
        test_helpers::BOB_IPV4,
        listen_port,
    )?;

    // Temper packet.
    let (eth2_header, ipv4_header, tcp_header): (Ethernet2Header, Ipv4Header, TcpHeader) =
        extract_headers(bytes.clone())?;
    let segment: TcpSegment = TcpSegment {
        ethernet2_hdr: eth2_header,
        ipv4_hdr: ipv4_header,
        tcp_hdr: TcpHeader {
            src_port: tcp_header.src_port,
            dst_port: tcp_header.dst_port,
            seq_num: tcp_header.seq_num,
            ack_num: tcp_header.ack_num,
            ns: tcp_header.ns,
            cwr: tcp_header.cwr,
            ece: tcp_header.ece,
            urg: tcp_header.urg,
            ack: tcp_header.ack,
            psh: tcp_header.psh,
            rst: tcp_header.rst,
            syn: false,
            fin: tcp_header.fin,
            window_size: tcp_header.window_size,
            urgent_pointer: tcp_header.urgent_pointer,
            num_options: tcp_header.num_options,
            option_list: tcp_header.option_list,
        },
        data: None,
        tx_checksum_offload: false,
    };

    // Serialize segment.
    let buf: DemiBuffer = serialize_segment(segment)?;

    // T(1) -> T(2)
    advance_clock(Some(&mut server), Some(&mut client), &mut now);

    // Server: SYN_RCVD state at T(2).
    match server.receive(buf) {
        Err(error) if error.errno == EBADMSG => Ok(()),
        _ => anyhow::bail!("server receive should have returned an error"),
    }
}

/// Tests basic 3-way connection setup.
#[test]
fn test_good_connect() -> Result<()> {
    let mut now = Instant::now();

    // Connection parameters
    let listen_port: u16 = 80;
    let listen_addr: SocketAddrV4 = SocketAddrV4::new(test_helpers::BOB_IPV4, listen_port);

    // Setup peers.
    let mut server: SharedEngine<RECEIVE_BATCH_SIZE> = test_helpers::new_bob2(now);
    let mut client: SharedEngine<RECEIVE_BATCH_SIZE> = test_helpers::new_alice2(now);

    let ((_, _), _): ((QDesc, SocketAddrV4), QDesc) =
        connection_setup(&mut now, &mut server, &mut client, listen_port, listen_addr)?;

    Ok(())
}

//======================================================================================================================
// Standalone Functions
//======================================================================================================================

/// Extracts headers of a TCP packet.
fn extract_headers(bytes: DemiBuffer) -> Result<(Ethernet2Header, Ipv4Header, TcpHeader)> {
    let (eth2_header, eth2_payload) = Ethernet2Header::parse(bytes)?;
    let (ipv4_header, ipv4_payload) = Ipv4Header::parse(eth2_payload)?;
    let (tcp_header, _) = TcpHeader::parse(&ipv4_header, ipv4_payload, false)?;

    return Ok((eth2_header, ipv4_header, tcp_header));
}

/// Serializes a TCP segment.
fn serialize_segment(pkt: TcpSegment) -> Result<DemiBuffer> {
    let header_size: usize = pkt.header_size();
    let body_size: usize = pkt.body_size();
    let mut buf = DemiBuffer::new((header_size + body_size) as u16);
    pkt.write_header(&mut buf[..header_size]);
    if let Some(body) = pkt.take_body() {
        buf[header_size..].copy_from_slice(&body[..]);
    }
    Ok(buf)
}

/// Triggers LISTEN -> SYN_SENT state transition.
fn connection_setup_listen_syn_sent<const N: usize>(
    client: &mut SharedEngine<N>,
    listen_addr: SocketAddrV4,
) -> Result<(QDesc, QToken, DemiBuffer)> {
    // Issue CONNECT operation.
    let client_fd: QDesc = match client.tcp_socket() {
        Ok(fd) => fd,
        Err(e) => anyhow::bail!("client tcp socket returned error: {:?}", e),
    };
    let qt: QToken = client.tcp_connect(client_fd, listen_addr)?;

    // SYN_SENT state.
    client.get_test_rig().poll_scheduler();
    client.get_test_rig().poll_scheduler();

    let bytes: DemiBuffer = client.get_test_rig().pop_frame();

    Ok((client_fd, qt, bytes))
}

/// Triggers CLOSED -> LISTEN state transition.
fn connection_setup_closed_listen<const N: usize>(
    server: &mut SharedEngine<N>,
    listen_addr: SocketAddrV4,
) -> Result<QToken> {
    // Issue ACCEPT operation.
    let socket_fd: QDesc = match server.tcp_socket() {
        Ok(fd) => fd,
        Err(e) => anyhow::bail!("server tcp socket returned error: {:?}", e),
    };
    if let Err(e) = server.tcp_bind(socket_fd, listen_addr) {
        anyhow::bail!("server bind returned an error: {:?}", e);
    }
    if let Err(e) = server.tcp_listen(socket_fd, 1) {
        anyhow::bail!("server listen returned an error: {:?}", e);
    }
    let accept_qt: QToken = server.tcp_accept(socket_fd)?;

    // LISTEN state.
    server.get_test_rig().poll_scheduler();

    Ok(accept_qt)
}

/// Triggers LISTEN -> SYN_RCVD state transition.
fn connection_setup_listen_syn_rcvd<const N: usize>(
    server: &mut SharedEngine<N>,
    bytes: DemiBuffer,
) -> Result<DemiBuffer> {
    // SYN_RCVD state.
    server.receive(bytes).unwrap();
    server.get_test_rig().poll_scheduler();
    Ok(server.get_test_rig().pop_frame())
}

/// Triggers SYN_SENT -> ESTABLISHED state transition.
fn connection_setup_syn_sent_established<const N: usize>(
    client: &mut SharedEngine<N>,
    bytes: DemiBuffer,
) -> Result<DemiBuffer> {
    client.receive(bytes).unwrap();
    client.get_test_rig().poll_scheduler();
    Ok(client.get_test_rig().pop_frame())
}

/// Triggers SYN_RCVD -> ESTABLISHED state transition.
fn connection_setup_sync_rcvd_established<const N: usize>(
    server: &mut SharedEngine<N>,
    bytes: DemiBuffer,
) -> Result<()> {
    server.receive(bytes).unwrap();
    server.get_test_rig().poll_scheduler();
    Ok(())
}

/// Checks for a pure SYN packet. This packet is sent by the sender side (active
/// open peer) when transitioning from the LISTEN to the SYN_SENT state.
fn check_packet_pure_syn(
    bytes: DemiBuffer,
    eth2_src_addr: MacAddress,
    eth2_dst_addr: MacAddress,
    ipv4_src_addr: Ipv4Addr,
    ipv4_dst_addr: Ipv4Addr,
    dst_port: u16,
) -> Result<()> {
    let (eth2_header, eth2_payload) = Ethernet2Header::parse(bytes).unwrap();
    crate::ensure_eq!(eth2_header.src_addr(), eth2_src_addr);
    crate::ensure_eq!(eth2_header.dst_addr(), eth2_dst_addr);
    crate::ensure_eq!(eth2_header.ether_type(), EtherType2::Ipv4);
    let (ipv4_header, ipv4_payload) = Ipv4Header::parse(eth2_payload).unwrap();
    crate::ensure_eq!(ipv4_header.get_src_addr(), ipv4_src_addr);
    crate::ensure_eq!(ipv4_header.get_dest_addr(), ipv4_dst_addr);
    let (tcp_header, _) = TcpHeader::parse(&ipv4_header, ipv4_payload, false).unwrap();
    crate::ensure_eq!(tcp_header.dst_port, dst_port);
    crate::ensure_eq!(tcp_header.seq_num, SeqNumber::from(0));
    crate::ensure_eq!(tcp_header.syn, true);

    Ok(())
}

/// Checks for a SYN+ACK packet. This packet is sent by the receiver side
/// (passive open peer) when transitioning from the LISTEN to the SYN_RCVD state.
fn check_packet_syn_ack(
    bytes: DemiBuffer,
    eth2_src_addr: MacAddress,
    eth2_dst_addr: MacAddress,
    ipv4_src_addr: Ipv4Addr,
    ipv4_dst_addr: Ipv4Addr,
    src_port: u16,
) -> Result<()> {
    let (eth2_header, eth2_payload) = Ethernet2Header::parse(bytes).unwrap();
    crate::ensure_eq!(eth2_header.src_addr(), eth2_src_addr);
    crate::ensure_eq!(eth2_header.dst_addr(), eth2_dst_addr);
    crate::ensure_eq!(eth2_header.ether_type(), EtherType2::Ipv4);
    let (ipv4_header, ipv4_payload) = Ipv4Header::parse(eth2_payload).unwrap();
    crate::ensure_eq!(ipv4_header.get_src_addr(), ipv4_src_addr);
    crate::ensure_eq!(ipv4_header.get_dest_addr(), ipv4_dst_addr);
    let (tcp_header, _) = TcpHeader::parse(&ipv4_header, ipv4_payload, false).unwrap();
    crate::ensure_eq!(tcp_header.src_port, src_port);
    crate::ensure_eq!(tcp_header.ack_num, SeqNumber::from(1));
    crate::ensure_eq!(tcp_header.seq_num, SeqNumber::from(0));
    crate::ensure_eq!(tcp_header.syn, true);
    crate::ensure_eq!(tcp_header.ack, true);

    Ok(())
}

/// Checks for a pure ACK on a SYN+ACK packet. This packet is sent by the sender
/// side (active open peer) when transitioning from the SYN_SENT state to the
/// ESTABLISHED state.
fn check_packet_pure_ack_on_syn_ack(
    bytes: DemiBuffer,
    eth2_src_addr: MacAddress,
    eth2_dst_addr: MacAddress,
    ipv4_src_addr: Ipv4Addr,
    ipv4_dst_addr: Ipv4Addr,
    dst_port: u16,
) -> Result<()> {
    let (eth2_header, eth2_payload) = Ethernet2Header::parse(bytes).unwrap();
    crate::ensure_eq!(eth2_header.src_addr(), eth2_src_addr);
    crate::ensure_eq!(eth2_header.dst_addr(), eth2_dst_addr);
    crate::ensure_eq!(eth2_header.ether_type(), EtherType2::Ipv4);
    let (ipv4_header, ipv4_payload) = Ipv4Header::parse(eth2_payload).unwrap();
    crate::ensure_eq!(ipv4_header.get_src_addr(), ipv4_src_addr);
    crate::ensure_eq!(ipv4_header.get_dest_addr(), ipv4_dst_addr);
    let (tcp_header, _) = TcpHeader::parse(&ipv4_header, ipv4_payload, false).unwrap();
    crate::ensure_eq!(tcp_header.dst_port, dst_port);
    crate::ensure_eq!(tcp_header.seq_num, SeqNumber::from(1));
    crate::ensure_eq!(tcp_header.ack_num, SeqNumber::from(1));
    crate::ensure_eq!(tcp_header.ack, true);

    Ok(())
}

/// Advances clock by one second.
pub fn advance_clock<const N: usize>(
    server: Option<&mut SharedEngine<N>>,
    client: Option<&mut SharedEngine<N>>,
    now: &mut Instant,
) {
    *now += Duration::from_secs(1);
    if let Some(server) = server {
        server.advance_clock(*now);
    }
    if let Some(client) = client {
        client.advance_clock(*now);
    }
}

/// Runs 3-way connection setup.
pub fn connection_setup<const N: usize>(
    now: &mut Instant,
    server: &mut SharedEngine<N>,
    client: &mut SharedEngine<N>,
    listen_port: u16,
    listen_addr: SocketAddrV4,
) -> Result<((QDesc, SocketAddrV4), QDesc)> {
    // Server: LISTEN state at T(0).
    let accept_qt: QToken = connection_setup_closed_listen(server, listen_addr)?;

    // T(0) -> T(1)
    advance_clock(Some(server), Some(client), now);

    // Client: SYN_SENT state at T(1).
    let (client_fd, connect_qt, mut bytes): (QDesc, QToken, DemiBuffer) =
        connection_setup_listen_syn_sent(client, listen_addr)?;

    // Sanity check packet.
    check_packet_pure_syn(
        bytes.clone(),
        test_helpers::ALICE_MAC,
        test_helpers::BOB_MAC,
        test_helpers::ALICE_IPV4,
        test_helpers::BOB_IPV4,
        listen_port,
    )?;

    // T(1) -> T(2)
    advance_clock(Some(server), Some(client), now);

    // Server: SYN_RCVD state at T(2).
    bytes = connection_setup_listen_syn_rcvd(server, bytes)?;

    // Sanity check packet.
    check_packet_syn_ack(
        bytes.clone(),
        test_helpers::BOB_MAC,
        test_helpers::ALICE_MAC,
        test_helpers::BOB_IPV4,
        test_helpers::ALICE_IPV4,
        listen_port,
    )?;

    // T(2) -> T(3)
    advance_clock(Some(server), Some(client), now);

    // Client: ESTABLISHED at T(3).
    bytes = connection_setup_syn_sent_established(client, bytes)?;

    // Sanity check sent packet.
    check_packet_pure_ack_on_syn_ack(
        bytes.clone(),
        test_helpers::ALICE_MAC,
        test_helpers::BOB_MAC,
        test_helpers::ALICE_IPV4,
        test_helpers::BOB_IPV4,
        listen_port,
    )?;
    // T(3) -> T(4)
    advance_clock(Some(server), Some(client), now);

    // Server: ESTABLISHED at T(4).
    connection_setup_sync_rcvd_established(server, bytes)?;

    let (server_fd, addr): (QDesc, SocketAddrV4) = match server
        .get_test_rig()
        .get_runtime()
        .remove_coroutine_with_qtoken(accept_qt)
        .get_result()
    {
        Some((_, crate::OperationResult::Accept((server_fd, addr)))) => (server_fd, addr),
        _ => anyhow::bail!("accept should have completed"),
    };
    match client
        .get_test_rig()
        .get_runtime()
        .remove_coroutine_with_qtoken(connect_qt)
        .get_result()
    {
        Some((_, OperationResult::Connect)) => {},
        _ => anyhow::bail!("connect should have completed"),
    };

    Ok(((server_fd, addr), client_fd))
}
