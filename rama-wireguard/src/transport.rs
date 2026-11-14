//! UDP datagram I/O for the WireGuard runtime adapters.
use rama_net::address::SocketAddress;
use rama_udp::{
    DatagramError, DatagramMetadata, DatagramSenderExt, DatagramSocket, DatagramSocketExt,
    SendDatagram,
};

/// A thin async adapter around Rama's runtime-neutral UDP datagram traits.
pub struct DatagramTransport<S: DatagramSocket> {
    socket: S,
    sender: S::Sender,
}

impl<S: DatagramSocket> DatagramTransport<S> {
    #[must_use]
    pub fn new(socket: S) -> Self {
        let sender = socket.create_sender();
        Self { socket, sender }
    }

    /// Sends one WireGuard datagram through the Rama UDP abstraction.
    pub async fn send_to(
        &mut self,
        destination: impl Into<SocketAddress>,
        datagram: &[u8],
    ) -> Result<(), DatagramError> {
        self.sender
            .send(SendDatagram::new(destination, datagram))
            .await
    }

    /// Receives one datagram, preserving the socket metadata for routing decisions.
    pub async fn recv(&mut self, buffer: &mut [u8]) -> Result<DatagramMetadata, DatagramError> {
        self.socket.recv(buffer).await
    }

    #[must_use]
    pub fn socket(&self) -> &S {
        &self.socket
    }

    pub fn socket_mut(&mut self) -> &mut S {
        &mut self.socket
    }
}
