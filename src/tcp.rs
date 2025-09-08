// Mostly copied from hyper 0.14 (MIT licensed).

use futures_util::{ready, Stream};
use std::{
    fmt,
    future::Future,
    io::{self, Error},
    net::{SocketAddr, TcpListener as StdTcpListener},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{net::TcpListener, time::Sleep};
use tracing::{debug, error, trace};

pub use self::addr_stream::AddrStream;

/// A stream of connections from binding to an address.
#[must_use = "streams do nothing unless polled"]
pub struct AddrIncoming {
    addr: SocketAddr,
    listener: TcpListener,
    sleep_on_errors: bool,
    tcp_nodelay: bool,
    timeout: Option<Pin<Box<Sleep>>>,
}

impl AddrIncoming {
    pub(super) fn new(addr: &SocketAddr) -> crate::Result<Self> {
        let std_listener = StdTcpListener::bind(addr).map_err(new_listen_error)?;

        AddrIncoming::from_std(std_listener)
    }

    pub(super) fn from_std(std_listener: StdTcpListener) -> crate::Result<Self> {
        // TcpListener::from_std doesn't set O_NONBLOCK
        std_listener
            .set_nonblocking(true)
            .map_err(new_listen_error)?;
        let listener = TcpListener::from_std(std_listener).map_err(new_listen_error)?;
        AddrIncoming::from_listener(listener)
    }

    /// Creates a new `AddrIncoming` binding to provided socket address.
    pub fn bind(addr: &SocketAddr) -> crate::Result<Self> {
        AddrIncoming::new(addr)
    }

    /// Creates a new `AddrIncoming` from an existing `tokio::net::TcpListener`.
    pub fn from_listener(listener: TcpListener) -> crate::Result<Self> {
        let addr = listener.local_addr().map_err(new_listen_error)?;
        Ok(AddrIncoming {
            listener,
            addr,
            sleep_on_errors: true,
            tcp_nodelay: false,
            timeout: None,
        })
    }

    /// Get the local address bound to this listener.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Set the value of `TCP_NODELAY` option for accepted connections.
    pub fn set_nodelay(&mut self, enabled: bool) -> &mut Self {
        self.tcp_nodelay = enabled;
        self
    }
}

impl Stream for AddrIncoming {
    type Item = AddrStream;

    fn poll_next(
        mut self: std::pin::Pin<&mut AddrIncoming>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<AddrStream>> {
        // Check if a previous timeout is active that was set by IO errors.
        if let Some(ref mut to) = self.timeout {
            ready!(Pin::new(to).poll(cx));
        }
        self.timeout = None;

        loop {
            match ready!(self.listener.poll_accept(cx)) {
                Ok((socket, remote_addr)) => {
                    if let Err(e) = socket.set_nodelay(self.tcp_nodelay) {
                        trace!("error trying to set TCP nodelay: {}", e);
                    }
                    let Ok(local_addr) = socket.local_addr() else {
                        return Poll::Ready(None);
                    };
                    return Poll::Ready(Some(AddrStream::new(socket, remote_addr, local_addr)));
                }
                Err(e) => {
                    // Connection errors can be ignored directly, continue by
                    // accepting the next request.
                    if is_connection_error(&e) {
                        debug!("accepted connection already errored: {}", e);
                        continue;
                    }

                    if self.sleep_on_errors {
                        error!("accept error: {}", e);

                        // Sleep 1s.
                        let mut timeout = Box::pin(tokio::time::sleep(Duration::from_secs(1)));

                        match timeout.as_mut().poll(cx) {
                            Poll::Ready(()) => {
                                // Wow, it's been a second already? Ok then...
                                continue;
                            }
                            Poll::Pending => {
                                self.timeout = Some(timeout);
                                return Poll::Pending;
                            }
                        }
                    } else {
                        return Poll::Ready(None);
                    }
                }
            }
        }
    }
}

/// This function defines errors that are per-connection. Which basically
/// means that if we get this error from `accept()` system call it means
/// next connection might be ready to be accepted.
///
/// All other errors will incur a timeout before next `accept()` is performed.
/// The timeout is useful to handle resource exhaustion errors like ENFILE
/// and EMFILE. Otherwise, could enter into tight loop.
fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

impl fmt::Debug for AddrIncoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddrIncoming")
            .field("addr", &self.addr)
            .field("sleep_on_errors", &self.sleep_on_errors)
            .field("tcp_nodelay", &self.tcp_nodelay)
            .finish()
    }
}

mod addr_stream {
    use std::io;
    use std::net::SocketAddr;
    #[cfg(unix)]
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::TcpStream;

    pin_project_lite::pin_project! {
        /// A transport returned yieled by `AddrIncoming`.
        #[derive(Debug)]
        pub struct AddrStream {
            #[pin]
            inner: TcpStream,
            pub remote_addr: SocketAddr,
            pub local_addr: SocketAddr
        }
    }

    impl AddrStream {
        pub(super) fn new(
            tcp: TcpStream,
            remote_addr: SocketAddr,
            local_addr: SocketAddr,
        ) -> AddrStream {
            AddrStream {
                inner: tcp,
                remote_addr,
                local_addr,
            }
        }
    }

    impl AsyncRead for AddrStream {
        #[inline]
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.project().inner.poll_read(cx, buf)
        }
    }

    impl AsyncWrite for AddrStream {
        #[inline]
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.project().inner.poll_write(cx, buf)
        }

        #[inline]
        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            self.project().inner.poll_write_vectored(cx, bufs)
        }

        #[inline]
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            // TCP flush is a noop
            Poll::Ready(Ok(()))
        }

        #[inline]
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.project().inner.poll_shutdown(cx)
        }

        #[inline]
        fn is_write_vectored(&self) -> bool {
            // Note that since `self.inner` is a `TcpStream`, this could
            // *probably* be hard-coded to return `true`...but it seems more
            // correct to ask it anyway (maybe we're on some platform without
            // scatter-gather IO?)
            self.inner.is_write_vectored()
        }
    }

    #[cfg(unix)]
    impl AsRawFd for AddrStream {
        fn as_raw_fd(&self) -> RawFd {
            self.inner.as_raw_fd()
        }
    }
}

pub(super) fn new_listen_error<E>(error: E) -> Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    Error::other(error)
}
