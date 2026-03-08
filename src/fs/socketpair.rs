use alloc::sync::Arc;
use core::any::Any;

use crate::{bpf::BpfProgFile, mm::UserBuffer};

use super::pipe::{make_pipe, Pipe};
use super::File;

/// A minimal full-duplex endpoint used to implement `socketpair(AF_UNIX, SOCK_STREAM, ...)`.
///
/// Internally it is two independent pipes (A->B and B->A).
pub struct SocketPairEnd {
    read_end: Arc<Pipe>,
    write_end: Arc<Pipe>,
}

impl SocketPairEnd {
    fn new(read_end: Arc<Pipe>, write_end: Arc<Pipe>) -> Self {
        Self {
            read_end,
            write_end,
        }
    }

    pub fn poll_readable(&self) -> bool {
        self.read_end.poll_readable()
    }

    pub fn poll_writable(&self) -> bool {
        self.write_end.poll_writable()
    }

    pub fn read_to_slice(&self, out: &mut [u8], nonblock: bool) -> Result<usize, isize> {
        self.read_end.read_to_slice(out, nonblock)
    }

    pub fn write_from_slice(&self, data: &[u8], nonblock: bool) -> Result<usize, isize> {
        self.write_end.write_from_slice(data, nonblock)
    }

    pub fn attach_bpf(&self, prog: Arc<BpfProgFile>) {
        self.read_end.attach_bpf(prog);
    }
}

/// Create a bidirectional pair of endpoints.
pub fn make_socketpair() -> (Arc<SocketPairEnd>, Arc<SocketPairEnd>) {
    // Two one-way pipes to form a full-duplex channel.
    let (a_to_b_r, a_to_b_w) = make_pipe();
    let (b_to_a_r, b_to_a_w) = make_pipe();

    let end0 = Arc::new(SocketPairEnd::new(b_to_a_r, a_to_b_w));
    let end1 = Arc::new(SocketPairEnd::new(a_to_b_r, b_to_a_w));
    (end0, end1)
}

impl File for SocketPairEnd {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, buf: UserBuffer) -> usize {
        self.read_end.read(buf)
    }

    fn write(&self, buf: UserBuffer) -> usize {
        self.write_end.write(buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
