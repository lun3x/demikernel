// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//==============================================================================
// Imports
//==============================================================================

use super::{
    active_open::ActiveOpenSocket,
    established::EstablishedSocket,
    isn_generator::IsnGenerator,
    passive_open::SharedPassiveSocket,
    queue::SharedTcpQueue,
};
use crate::{
    inetstack::protocols::{
        arp::SharedArpPeer,
        ethernet2::{
            EtherType2,
            Ethernet2Header,
        },
        ip::{
            EphemeralPorts,
            IpProtocol,
        },
        ipv4::Ipv4Header,
        tcp::{
            established::SharedControlBlock,
            operations::{
                AcceptFuture,
                CloseFuture,
                ConnectFuture,
                PopFuture,
                PushFuture,
            },
            segment::{
                TcpHeader,
                TcpSegment,
            },
            SeqNumber,
        },
    },
    runtime::{
        fail::Fail,
        memory::DemiBuffer,
        network::{
            config::TcpConfig,
            types::MacAddress,
            NetworkRuntime,
        },
        timer::TimerRc,
        QDesc,
        SharedBox,
        SharedDemiRuntime,
        SharedObject,
    },
};
use ::futures::channel::mpsc;
use ::rand::{
    prelude::SmallRng,
    Rng,
    SeedableRng,
};

use ::std::{
    collections::HashMap,
    net::{
        Ipv4Addr,
        SocketAddrV4,
    },
    ops::{
        Deref,
        DerefMut,
    },
    task::{
        Context,
        Poll,
    },
    time::Duration,
};

#[cfg(feature = "profiler")]
use crate::timer;

//==============================================================================
// Enumerations
//==============================================================================

pub enum Socket<const N: usize> {
    Inactive(Option<SocketAddrV4>),
    Listening(SharedPassiveSocket<N>),
    Connecting(ActiveOpenSocket<N>),
    Established(EstablishedSocket<N>),
    Closing(EstablishedSocket<N>),
}

#[derive(PartialEq, Eq, Hash)]
enum SocketId {
    Active(SocketAddrV4, SocketAddrV4),
    Passive(SocketAddrV4),
}

//==============================================================================
// Structures
//==============================================================================

pub struct TcpPeer<const N: usize> {
    runtime: SharedDemiRuntime,
    isn_generator: IsnGenerator,
    ephemeral_ports: EphemeralPorts,
    // Connection or socket identifier for mapping incoming packets to the Demikernel queue
    addresses: HashMap<SocketId, QDesc>,
    transport: SharedBox<dyn NetworkRuntime<N>>,
    clock: TimerRc,
    local_link_addr: MacAddress,
    local_ipv4_addr: Ipv4Addr,
    tcp_config: TcpConfig,
    arp: SharedArpPeer<N>,
    rng: SmallRng,
    dead_socket_tx: mpsc::UnboundedSender<QDesc>,
}

#[derive(Clone)]
pub struct SharedTcpPeer<const N: usize>(SharedObject<TcpPeer<N>>);

//==============================================================================
// Associated Functions
//==============================================================================

impl<const N: usize> TcpPeer<N> {
    fn new(
        runtime: SharedDemiRuntime,
        transport: SharedBox<dyn NetworkRuntime<N>>,
        clock: TimerRc,
        local_link_addr: MacAddress,
        local_ipv4_addr: Ipv4Addr,
        tcp_config: TcpConfig,
        arp: SharedArpPeer<N>,
        rng_seed: [u8; 32],
    ) -> Self {
        let mut rng: SmallRng = SmallRng::from_seed(rng_seed);
        let ephemeral_ports: EphemeralPorts = EphemeralPorts::new(&mut rng);
        let nonce: u32 = rng.gen();
        let (tx, _) = mpsc::unbounded();
        Self {
            isn_generator: IsnGenerator::new(nonce),
            ephemeral_ports,
            runtime,
            transport,
            addresses: HashMap::<SocketId, QDesc>::new(),
            clock,
            local_link_addr,
            local_ipv4_addr,
            tcp_config,
            arp,
            rng,
            dead_socket_tx: tx,
        }
    }
}

impl<const N: usize> SharedTcpPeer<N> {
    pub fn new(
        runtime: SharedDemiRuntime,
        transport: SharedBox<dyn NetworkRuntime<N>>,
        clock: TimerRc,
        local_link_addr: MacAddress,
        local_ipv4_addr: Ipv4Addr,
        tcp_config: TcpConfig,
        arp: SharedArpPeer<N>,
        rng_seed: [u8; 32],
    ) -> Result<Self, Fail> {
        Ok(Self(SharedObject::<TcpPeer<N>>::new(TcpPeer::<N>::new(
            runtime,
            transport,
            clock,
            local_link_addr,
            local_ipv4_addr,
            tcp_config,
            arp,
            rng_seed,
        ))))
    }

    /// Opens a TCP socket.
    pub fn socket(&mut self) -> Result<QDesc, Fail> {
        #[cfg(feature = "profiler")]
        timer!("tcp::socket");
        let new_qd: QDesc = self
            .runtime
            .alloc_queue::<SharedTcpQueue<N>>(SharedTcpQueue::<N>::new());
        Ok(new_qd)
    }

    pub fn bind(&mut self, qd: QDesc, local: SocketAddrV4) -> Result<(), Fail> {
        // Check if we are binding to the wildcard address.
        // FIXME: https://github.com/demikernel/demikernel/issues/189
        if local.ip() == &Ipv4Addr::UNSPECIFIED {
            let cause: String = format!("cannot bind to wildcard address (qd={:?})", qd);
            error!("bind(): {}", cause);
            return Err(Fail::new(libc::ENOTSUP, &cause));
        }

        // Check if we are binding to the wildcard port.
        // FIXME: https://github.com/demikernel/demikernel/issues/582
        if local.port() == 0 {
            let cause: String = format!("cannot bind to port 0 (qd={:?})", qd);
            error!("bind(): {}", cause);
            return Err(Fail::new(libc::ENOTSUP, &cause));
        }

        // TODO: Check if we are binding to a non-local address.

        // Check wether the address is in use.
        if self.addr_in_use(local) {
            let cause: String = format!("address is already bound to a socket (qd={:?}", qd);
            error!("bind(): {}", &cause);
            return Err(Fail::new(libc::EADDRINUSE, &cause));
        }

        // Check if this is an ephemeral port.
        if EphemeralPorts::is_private(local.port()) {
            // Allocate ephemeral port from the pool, to leave  ephemeral port allocator in a consistent state.
            self.ephemeral_ports.alloc_port(local.port())?
        }

        // Issue operation.
        let ret: Result<(), Fail> = {
            let mut queue: SharedTcpQueue<N> = self.get_shared_queue(&qd)?;
            match queue.get_socket() {
                Socket::Inactive(None) => {
                    queue.set_socket(Socket::Inactive(Some(local)));
                    Ok(())
                },
                Socket::Inactive(_) => Err(Fail::new(libc::EINVAL, "socket is already bound to an address")),
                Socket::Listening(_) => return Err(Fail::new(libc::EINVAL, "socket is already listening")),
                Socket::Connecting(_) => return Err(Fail::new(libc::EINVAL, "socket is connecting")),
                Socket::Established(_) => return Err(Fail::new(libc::EINVAL, "socket is connected")),
                Socket::Closing(_) => return Err(Fail::new(libc::EINVAL, "socket is closed")),
            }
        };

        // Handle return value.
        match ret {
            Ok(x) => {
                self.addresses.insert(SocketId::Passive(local), qd);
                Ok(x)
            },
            Err(e) => {
                // Rollback ephemeral port allocation.
                if EphemeralPorts::is_private(local.port()) {
                    if self.ephemeral_ports.free(local.port()).is_err() {
                        warn!("bind(): leaking ephemeral port (port={})", local.port());
                    }
                }
                Err(e)
            },
        }
    }

    // Marks the target socket as passive.
    pub fn listen(&mut self, qd: QDesc, backlog: usize) -> Result<(), Fail> {
        // This code borrows a reference to inner, instead of the entire self structure,
        // so we can still borrow self later.
        // Get bound address while checking for several issues.
        let mut queue: SharedTcpQueue<N> = self.get_shared_queue(&qd)?;
        match queue.get_mut_socket() {
            Socket::Inactive(Some(local)) => {
                // Check if there isn't a socket listening on this address/port pair.
                if self.addresses.contains_key(&SocketId::Passive(*local)) {
                    if *self.addresses.get(&SocketId::Passive(*local)).unwrap() != qd {
                        return Err(Fail::new(
                            libc::EADDRINUSE,
                            "another socket is already listening on the same address/port pair",
                        ));
                    }
                }

                let nonce: u32 = self.rng.gen();
                let socket = SharedPassiveSocket::new(
                    *local,
                    backlog,
                    self.runtime.clone(),
                    self.transport.clone(),
                    self.clock.clone(),
                    self.tcp_config.clone(),
                    self.local_link_addr,
                    self.arp.clone(),
                    nonce,
                );
                self.addresses.insert(SocketId::Passive(local.clone()), qd);
                queue.set_socket(Socket::Listening(socket));
                Ok(())
            },
            Socket::Inactive(None) => {
                return Err(Fail::new(libc::EDESTADDRREQ, "socket is not bound to a local address"))
            },
            Socket::Listening(_) => return Err(Fail::new(libc::EINVAL, "socket is already listening")),
            Socket::Connecting(_) => return Err(Fail::new(libc::EINVAL, "socket is connecting")),
            Socket::Established(_) => return Err(Fail::new(libc::EINVAL, "socket is connected")),
            Socket::Closing(_) => return Err(Fail::new(libc::EINVAL, "socket is closed")),
        }
    }

    /// Accepts an incoming connection.
    pub fn accept(&mut self, qd: QDesc) -> (QDesc, AcceptFuture<N>) {
        let new_qd: QDesc = self
            .runtime
            .alloc_queue::<SharedTcpQueue<N>>(SharedTcpQueue::<N>::new());
        (new_qd, AcceptFuture::new(qd, new_qd, self.clone()))
    }

    /// Handles an incoming connection.
    pub fn poll_accept(
        &mut self,
        qd: QDesc,
        new_qd: QDesc,
        ctx: &mut Context,
    ) -> Poll<Result<(QDesc, SocketAddrV4), Fail>> {
        let cb: SharedControlBlock<N> = {
            let mut queue: SharedTcpQueue<N> = self.get_shared_queue(&qd)?;
            match queue.get_mut_socket() {
                Socket::Listening(socket) => match socket.poll_accept(ctx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => match result {
                        Ok(cb) => cb,
                        Err(err) => {
                            // The new queue should have been allocated before this coroutine was scheduled.
                            self.runtime
                                .free_queue::<SharedTcpQueue<N>>(&new_qd)
                                .expect("queue should exist");
                            return Poll::Ready(Err(err));
                        },
                    },
                },
                _ => return Poll::Ready(Err(Fail::new(libc::EOPNOTSUPP, "socket not listening"))),
            }
        };

        let established: EstablishedSocket<N> =
            match EstablishedSocket::new(cb, new_qd, self.dead_socket_tx.clone(), self.runtime.clone()) {
                Ok(socket) => socket,
                Err(e) => return Poll::Ready(Err(e)),
            };
        let local: SocketAddrV4 = established.cb.get_local();
        let remote: SocketAddrV4 = established.cb.get_remote();
        {
            // This queue should have been allocated before the coroutine was scheduled.
            let mut new_queue: SharedTcpQueue<N> =
                self.get_shared_queue(&new_qd).expect("Should have been pre-allocated");
            new_queue.set_socket(Socket::Established(established));
        }
        if self.addresses.insert(SocketId::Active(local, remote), new_qd).is_some() {
            panic!("duplicate queue descriptor in established sockets table");
        }
        // TODO: Reset the connection if the following following check fails, instead of panicking.
        Poll::Ready(Ok((new_qd, remote)))
    }

    pub fn connect(&mut self, qd: QDesc, remote: SocketAddrV4) -> Result<ConnectFuture<N>, Fail> {
        // Get local address bound to socket.
        let mut queue: SharedTcpQueue<N> = self.get_shared_queue(&qd)?;
        match queue.get_socket() {
            Socket::Inactive(local_socket) => {
                let local: SocketAddrV4 = match local_socket {
                    Some(local) => local.clone(),
                    None => {
                        // TODO: we should free this when closing.
                        let local_port: u16 = self.ephemeral_ports.alloc_any()?;
                        SocketAddrV4::new(self.local_ipv4_addr, local_port)
                    },
                };

                // Create active socket.
                let local_isn: SeqNumber = self.isn_generator.generate(&local, &remote);
                let socket: ActiveOpenSocket<N> = ActiveOpenSocket::new(
                    local_isn,
                    local,
                    remote,
                    self.runtime.clone(),
                    self.transport.clone(),
                    self.tcp_config.clone(),
                    self.local_link_addr,
                    self.clock.clone(),
                    self.arp.clone(),
                )?;

                // Update socket state.
                queue.set_socket(Socket::Connecting(socket));
                self.addresses.insert(SocketId::Active(local, remote.clone()), qd)
            },
            Socket::Listening(_) => return Err(Fail::new(libc::EOPNOTSUPP, "socket is listening")),
            Socket::Connecting(_) => return Err(Fail::new(libc::EALREADY, "socket is connecting")),
            Socket::Established(_) => return Err(Fail::new(libc::EISCONN, "socket is connected")),
            Socket::Closing(_) => return Err(Fail::new(libc::EINVAL, "socket is closed")),
        };
        Ok(ConnectFuture { qd, peer: self.clone() })
    }

    pub fn poll_recv(&mut self, qd: QDesc, ctx: &mut Context, size: Option<usize>) -> Poll<Result<DemiBuffer, Fail>> {
        let mut queue: SharedTcpQueue<N> = match self.get_shared_queue(&qd) {
            Ok(queue) => queue,
            Err(e) => return Poll::Ready(Err(e)),
        };

        match queue.get_mut_socket() {
            Socket::Established(ref mut socket) => socket.poll_recv(ctx, size),
            Socket::Closing(ref mut socket) => socket.poll_recv(ctx, size),
            Socket::Connecting(_) => Poll::Ready(Err(Fail::new(libc::EINPROGRESS, "socket connecting"))),
            Socket::Inactive(_) => Poll::Ready(Err(Fail::new(libc::EBADF, "socket inactive"))),
            Socket::Listening(_) => Poll::Ready(Err(Fail::new(libc::ENOTCONN, "socket listening"))),
        }
    }

    /// TODO: Should probably check for valid queue descriptor before we schedule the future
    pub fn push(&self, qd: QDesc, buf: DemiBuffer) -> PushFuture {
        let err: Option<Fail> = match self.send(qd, buf) {
            Ok(()) => None,
            Err(e) => Some(e),
        };
        PushFuture { qd, err }
    }

    /// TODO: Should probably check for valid queue descriptor before we schedule the future
    pub fn pop(&self, qd: QDesc, size: Option<usize>) -> PopFuture<N> {
        PopFuture {
            qd,
            size,
            peer: self.clone(),
        }
    }

    fn send(&self, qd: QDesc, buf: DemiBuffer) -> Result<(), Fail> {
        let queue: SharedTcpQueue<N> = self.get_shared_queue(&qd)?;
        match queue.get_socket() {
            Socket::Established(ref socket) => socket.send(buf),
            _ => Err(Fail::new(libc::ENOTCONN, "connection not established")),
        }
    }

    /// Closes a TCP socket.
    pub fn close(&mut self, qd: QDesc) -> Result<(), Fail> {
        // TODO: Currently we do not handle close correctly because we continue to receive packets at this point to finish the TCP close protocol.
        // 1. We do not remove the endpoint from the addresses table
        // 2. We do not remove the queue from the queue table.
        // As a result, we have stale closed queues that are labelled as closing. We should clean these up.
        // look up socket
        let mut queue: SharedTcpQueue<N> = self.get_shared_queue(&qd)?;

        let (addr, result): (SocketAddrV4, Result<(), Fail>) = match queue.get_mut_socket() {
            // Closing an active socket.
            Socket::Established(socket) => {
                socket.close()?;
                // Only using a clone here because we need to read and write the socket.
                self.get_shared_queue(&qd)?.set_socket(Socket::Closing(socket.clone()));
                return Ok(());
            },
            // Closing an unbound socket.
            Socket::Inactive(None) => {
                return Ok(());
            },
            // Closing a bound socket.
            Socket::Inactive(Some(addr)) => (addr.clone(), Ok(())),
            // Closing a listening socket.
            Socket::Listening(socket) => {
                let cause: String = format!("cannot close a listening socket (qd={:?})", qd);
                error!("do_close(): {}", &cause);
                (socket.endpoint(), Err(Fail::new(libc::ENOTSUP, &cause)))
            },
            // Closing a connecting socket.
            Socket::Connecting(_) => {
                let cause: String = format!("cannot close a connecting socket (qd={:?})", qd);
                error!("do_close(): {}", &cause);
                return Err(Fail::new(libc::ENOTSUP, &cause));
            },
            // Closing a closing socket.
            Socket::Closing(_) => {
                let cause: String = format!("cannot close a socket that is closing (qd={:?})", qd);
                error!("do_close(): {}", &cause);
                return Err(Fail::new(libc::ENOTSUP, &cause));
            },
        };

        // TODO: remove active sockets from the addresses table.
        self.addresses.remove(&SocketId::Passive(addr));
        result
    }

    /// Closes a TCP socket.
    pub fn async_close(&self, qd: QDesc) -> Result<CloseFuture<N>, Fail> {
        let mut queue: SharedTcpQueue<N> = self.get_shared_queue(&qd)?;
        match queue.get_mut_socket() {
            // Closing an active socket.
            Socket::Established(socket) => {
                // Send FIN
                socket.close()?;
                // Move socket to closing state
                // Only using a clone here because we need to read and write the socket.
                self.get_shared_queue(&qd)?.set_socket(Socket::Closing(socket.clone()));
            },
            // Closing an unbound socket.
            Socket::Inactive(_) => (),
            // Closing a listening socket.
            Socket::Listening(_) => {
                // TODO: Remove this address from the addresses table
                let cause: String = format!("cannot close a listening socket (qd={:?})", qd);
                error!("do_close(): {}", &cause);
                return Err(Fail::new(libc::ENOTSUP, &cause));
            },
            // Closing a connecting socket.
            Socket::Connecting(_) => {
                let cause: String = format!("cannot close a connecting socket (qd={:?})", qd);
                error!("do_close(): {}", &cause);
                return Err(Fail::new(libc::ENOTSUP, &cause));
            },
            // Closing a closing socket.
            Socket::Closing(_) => {
                let cause: String = format!("cannot close a socket that is closing (qd={:?})", qd);
                error!("do_close(): {}", &cause);
                return Err(Fail::new(libc::ENOTSUP, &cause));
            },
        };
        // Schedule a co-routine to all of the cleanup
        Ok(CloseFuture { qd, peer: self.clone() })
    }

    pub fn remote_mss(&self, qd: QDesc) -> Result<usize, Fail> {
        let queue: SharedTcpQueue<N> = self.get_shared_queue(&qd)?;
        match queue.get_socket() {
            Socket::Established(socket) => Ok(socket.remote_mss()),
            _ => Err(Fail::new(libc::ENOTCONN, "connection not established")),
        }
    }

    pub fn current_rto(&self, qd: QDesc) -> Result<Duration, Fail> {
        let queue: SharedTcpQueue<N> = self.get_shared_queue(&qd)?;
        match queue.get_socket() {
            Socket::Established(socket) => Ok(socket.current_rto()),
            _ => return Err(Fail::new(libc::ENOTCONN, "connection not established")),
        }
    }

    pub fn endpoints(&self, qd: QDesc) -> Result<(SocketAddrV4, SocketAddrV4), Fail> {
        let queue: SharedTcpQueue<N> = self.get_shared_queue(&qd)?;
        match queue.get_socket() {
            Socket::Established(socket) => Ok(socket.endpoints()),
            _ => Err(Fail::new(libc::ENOTCONN, "connection not established")),
        }
    }

    /// Checks if the given `local` address is in use.
    fn addr_in_use(&self, local: SocketAddrV4) -> bool {
        for (socket_id, _) in &self.addresses {
            match socket_id {
                SocketId::Passive(addr) | SocketId::Active(addr, _) if *addr == local => return true,
                _ => continue,
            }
        }
        false
    }

    fn get_shared_queue(&self, qd: &QDesc) -> Result<SharedTcpQueue<N>, Fail> {
        self.runtime.get_shared_queue::<SharedTcpQueue<N>>(qd)
    }

    /// Processes an incoming TCP segment.
    pub fn receive(&mut self, ip_hdr: &Ipv4Header, buf: DemiBuffer) -> Result<(), Fail> {
        let (mut tcp_hdr, data): (TcpHeader, DemiBuffer) =
            TcpHeader::parse(ip_hdr, buf, self.tcp_config.get_rx_checksum_offload())?;
        debug!("TCP received {:?}", tcp_hdr);
        let local: SocketAddrV4 = SocketAddrV4::new(ip_hdr.get_dest_addr(), tcp_hdr.dst_port);
        let remote: SocketAddrV4 = SocketAddrV4::new(ip_hdr.get_src_addr(), tcp_hdr.src_port);

        if remote.ip().is_broadcast() || remote.ip().is_multicast() || remote.ip().is_unspecified() {
            let cause: String = format!("invalid remote address (remote={})", remote.ip());
            error!("receive(): {}", &cause);
            return Err(Fail::new(libc::EBADMSG, &cause));
        }

        // Retrieve the queue descriptor based on the incoming segment.
        let &qd: &QDesc = match self.addresses.get(&SocketId::Active(local, remote)) {
            Some(qdesc) => qdesc,
            None => match self.addresses.get(&SocketId::Passive(local)) {
                Some(qdesc) => qdesc,
                None => {
                    let cause: String = format!("no queue descriptor for remote address (remote={})", remote.ip());
                    error!("receive(): {}", &cause);
                    return Err(Fail::new(libc::EBADF, &cause));
                },
            },
        };

        // Dispatch to further processing depending on the socket state.
        // It is safe to call expect() here because qd must be on the queue table.
        let mut queue: SharedTcpQueue<N> = self.get_shared_queue(&qd)?;
        match queue.get_mut_socket() {
            Socket::Established(socket) => {
                debug!("Routing to established connection: {:?}", socket.endpoints());
                socket.receive(&mut tcp_hdr, data);
                return Ok(());
            },
            Socket::Connecting(socket) => {
                debug!("Routing to connecting connection: {:?}", socket.endpoints());
                socket.receive(&tcp_hdr);
                return Ok(());
            },
            Socket::Listening(socket) => {
                debug!("Routing to passive connection: {:?}", local);
                match socket.receive(ip_hdr, &tcp_hdr) {
                    Ok(()) => return Ok(()),
                    // Connection was refused.
                    Err(e) if e.errno == libc::ECONNREFUSED => {
                        // Fall through and send a RST segment back.
                    },
                    Err(e) => return Err(e),
                }
            },
            // The segment is for an inactive connection.
            Socket::Inactive(_) => {
                debug!("Routing to inactive connection: {:?}", local);
                // Fall through and send a RST segment back.
            },
            Socket::Closing(socket) => {
                debug!("Routing to closing connection: {:?}", socket.endpoints());
                socket.receive(&mut tcp_hdr, data);
                return Ok(());
            },
        }

        // Generate the RST segment accordingly to the ACK field.
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the
        // reset has sequence number zero and the ACK field is set to the sum
        // of the sequence number and segment length of the incoming segment.
        // Reference: https://datatracker.ietf.org/doc/html/rfc793#section-3.4
        let (seq_num, ack_num): (SeqNumber, Option<SeqNumber>) = if tcp_hdr.ack {
            (tcp_hdr.ack_num, None)
        } else {
            (
                SeqNumber::from(0),
                Some(tcp_hdr.seq_num + SeqNumber::from(tcp_hdr.compute_size() as u32)),
            )
        };

        debug!("receive(): sending RST (local={:?}, remote={:?})", local, remote);
        self.send_rst(&local, &remote, seq_num, ack_num)?;
        Ok(())
    }

    /// Sends a RST segment from `local` to `remote`.
    pub fn send_rst(
        &mut self,
        local: &SocketAddrV4,
        remote: &SocketAddrV4,
        seq_num: SeqNumber,
        ack_num: Option<SeqNumber>,
    ) -> Result<(), Fail> {
        // Query link address for destination.
        let dst_link_addr: MacAddress = match self.arp.try_query(remote.ip().clone()) {
            Some(link_addr) => link_addr,
            None => {
                // ARP query is unlikely to fail, but if it does, don't send the RST segment,
                // and return an error to server side.
                let cause: String = format!("missing ARP entry (remote={})", remote.ip());
                error!("send_rst(): {}", &cause);
                return Err(Fail::new(libc::EHOSTUNREACH, &cause));
            },
        };

        // Create a RST segment.
        let segment: TcpSegment = {
            let mut tcp_hdr: TcpHeader = TcpHeader::new(local.port(), remote.port());
            tcp_hdr.rst = true;
            tcp_hdr.seq_num = seq_num;
            if let Some(ack_num) = ack_num {
                tcp_hdr.ack = true;
                tcp_hdr.ack_num = ack_num;
            }
            TcpSegment {
                ethernet2_hdr: Ethernet2Header::new(dst_link_addr, self.local_link_addr, EtherType2::Ipv4),
                ipv4_hdr: Ipv4Header::new(local.ip().clone(), remote.ip().clone(), IpProtocol::TCP),
                tcp_hdr,
                data: None,
                tx_checksum_offload: self.tcp_config.get_rx_checksum_offload(),
            }
        };

        // Send it.
        let pkt: Box<TcpSegment> = Box::new(segment);
        self.transport.transmit(pkt);

        Ok(())
    }

    pub fn poll_connect_finished(&mut self, qd: QDesc, context: &mut Context) -> Poll<Result<SocketAddrV4, Fail>> {
        let mut queue: SharedTcpQueue<N> = match self.get_shared_queue(&qd) {
            Ok(queue) => queue,
            Err(e) => return Poll::Ready(Err(e)),
        };
        match queue.get_mut_socket() {
            Socket::Connecting(socket) => {
                let result: Result<SharedControlBlock<N>, Fail> = match socket.poll_result(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(r) => r,
                };
                match result {
                    Ok(cb) => {
                        let local = cb.get_local();
                        let new_socket = Socket::Established(
                            match EstablishedSocket::new(cb, qd, self.dead_socket_tx.clone(), self.runtime.clone()) {
                                Ok(socket) => socket,
                                Err(e) => return Poll::Ready(Err(e)),
                            },
                        );
                        queue.set_socket(new_socket);
                        Poll::Ready(Ok(local))
                    },
                    Err(fail) => Poll::Ready(Err(fail)),
                }
            },
            _ => Poll::Ready(Err(Fail::new(libc::EAGAIN, "socket not connecting"))),
        }
    }

    // TODO: Eventually use context to store the waker for this function in the established socket.
    pub fn poll_close_finished(&mut self, qd: QDesc, _context: &mut Context) -> Poll<Result<(), Fail>> {
        let sockid: Option<SocketId> = {
            let queue: SharedTcpQueue<N> = match self.get_shared_queue(&qd) {
                Ok(queue) => queue,
                Err(e) => return Poll::Ready(Err(e)),
            };
            match queue.get_socket() {
                // Closing an active socket.
                Socket::Closing(socket) => match socket.poll_close() {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(_) => Some(SocketId::Active(socket.endpoints().0, socket.endpoints().1)),
                },
                // Closing an unbound socket.
                Socket::Inactive(None) => None,
                // Closing a bound socket.
                Socket::Inactive(Some(addr)) => Some(SocketId::Passive(addr.clone())),
                // Closing a listening socket.
                Socket::Listening(_) => unimplemented!("Do not support async close for listening sockets yet"),
                // Closing a connecting socket.
                Socket::Connecting(_) => unimplemented!("Do not support async close for listening sockets yet"),
                // Closing a closing socket.
                Socket::Established(_) => unreachable!("Should have moved this socket to closing already!"),
            }
        };

        // Remove queue from qtable
        self.runtime
            .free_queue::<SharedTcpQueue<N>>(&qd)
            .expect("queue should exist");
        // Remove address from addresses backmap
        if let Some(addr) = sockid {
            self.addresses.remove(&addr);
        }
        Poll::Ready(Ok(()))
    }
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

impl<const N: usize> Deref for SharedTcpPeer<N> {
    type Target = TcpPeer<N>;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<const N: usize> DerefMut for SharedTcpPeer<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}
