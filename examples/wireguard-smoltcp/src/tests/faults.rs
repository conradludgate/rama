//! Test-only relays for the fork's original in-memory socket API.
use parking_lot::Mutex;
use rama_net::address::SocketAddress;
use rama_udp::{
    DatagramError, DatagramSender, DatagramSenderExt as _, DatagramSocket as _,
    DatagramSocketExt as _, SendDatagram, test_utils::MemoryDatagramSocket,
};
use std::{num::NonZeroUsize, sync::Arc};

#[derive(Clone, Default)]
pub(super) struct Control(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    drop_next: usize,
    duplicate_next: usize,
    stats: Stats,
}

#[derive(Clone, Copy, Default)]
pub(super) struct Stats {
    pub(super) dropped: usize,
    pub(super) duplicated: usize,
}

impl Control {
    pub(super) fn drop_next(&self, count: usize) {
        self.0.lock().drop_next = count;
    }
    pub(super) fn duplicate_next(&self, count: usize) {
        self.0.lock().duplicate_next = count;
    }
    pub(super) fn stats(&self) -> Stats {
        self.0.lock().stats
    }
    fn copies(&self) -> usize {
        let mut state = self.0.lock();
        if state.drop_next != 0 {
            state.drop_next -= 1;
            state.stats.dropped += 1;
            0
        } else if state.duplicate_next != 0 {
            state.duplicate_next -= 1;
            state.stats.duplicated += 1;
            2
        } else {
            1
        }
    }
}

pub(super) struct Relays([tokio::task::JoinHandle<Result<(), DatagramError>>; 2]);

impl Relays {
    pub(super) async fn stop(self) {
        for task in &self.0 {
            task.abort();
        }
        for mut task in self.0 {
            match (&mut task).await {
                Err(error) if error.is_cancelled() => {}
                Ok(Err(DatagramError::Closed)) => {}
                other => panic!("unexpected relay completion: {other:?}"),
            }
        }
    }
}

pub(super) fn pair(
    a: SocketAddress,
    b: SocketAddress,
) -> (
    MemoryDatagramSocket,
    MemoryDatagramSocket,
    Control,
    Control,
    Relays,
) {
    let capacity = NonZeroUsize::new(128).unwrap();
    let (a_socket, a_relay) = MemoryDatagramSocket::pair(a, b, capacity);
    let (b_socket, b_relay) = MemoryDatagramSocket::pair(b, a, capacity);
    let a_sender = a_relay.create_sender();
    let b_sender = b_relay.create_sender();
    let a_faults = Control::default();
    let b_faults = Control::default();
    let tasks = Relays([
        tokio::spawn(relay(a_relay, b_sender, b, a_faults.clone())),
        tokio::spawn(relay(b_relay, a_sender, a, b_faults.clone())),
    ]);
    (a_socket, b_socket, a_faults, b_faults, tasks)
}

async fn relay(
    mut receiver: MemoryDatagramSocket,
    mut sender: impl DatagramSender,
    destination: SocketAddress,
    faults: Control,
) -> Result<(), DatagramError> {
    let mut buffer = vec![0; 65_535];
    loop {
        let metadata = receiver.recv(&mut buffer).await?;
        assert!(!metadata.truncated);
        for _ in 0..faults.copies() {
            sender
                .send(SendDatagram::new(destination, &buffer[..metadata.len]))
                .await?;
        }
    }
}
