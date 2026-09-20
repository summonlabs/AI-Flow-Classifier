// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/net/tcp.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

#if defined(AIFC_PLATFORM_WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace aifc {
namespace {

#if defined(AIFC_PLATFORM_WINDOWS)
using NativeSocket = SOCKET;
constexpr NativeSocket kBadSocket = INVALID_SOCKET;
#else
using NativeSocket = int;
constexpr NativeSocket kBadSocket = -1;
#endif

std::atomic<std::uint32_t> g_acquire_count{0};
std::mutex g_subsystem_mutex;

[[nodiscard]] NativeSocket to_native(std::uintptr_t handle) noexcept {
  return static_cast<NativeSocket>(handle);
}

[[nodiscard]] std::uintptr_t from_native(NativeSocket socket) noexcept {
  return static_cast<std::uintptr_t>(socket);
}

[[nodiscard]] ErrorCode last_socket_error() noexcept {
#if defined(AIFC_PLATFORM_WINDOWS)
  const int error = ::WSAGetLastError();
  switch (error) {
    case WSAECONNRESET:
    case WSAECONNABORTED:
      return ErrorCode::CONNECTION_RESET;
    case WSAETIMEDOUT:
      return ErrorCode::TIMEOUT;
    case WSAEWOULDBLOCK:
      return ErrorCode::TIMEOUT;
    default:
      return ErrorCode::IO_ERROR;
  }
#else
  switch (errno) {
    case ECONNRESET:
    case EPIPE:
      return ErrorCode::CONNECTION_RESET;
    case ETIMEDOUT:
      return ErrorCode::TIMEOUT;
    case EAGAIN:
      return ErrorCode::TIMEOUT;
    case EINTR:
      return ErrorCode::CANCELLED;
    default:
      return ErrorCode::IO_ERROR;
  }
#endif
}

[[nodiscard]] std::string describe_socket_error() noexcept {
#if defined(AIFC_PLATFORM_WINDOWS)
  return "winsock error " + std::to_string(::WSAGetLastError());
#else
  return std::string(std::strerror(errno));
#endif
}

void close_native(NativeSocket socket) noexcept {
  if (socket == kBadSocket) return;
#if defined(AIFC_PLATFORM_WINDOWS)
  ::closesocket(socket);
#else
  ::close(socket);
#endif
}

[[nodiscard]] std::string format_v4(const sockaddr_in& address) {
  const std::uint32_t host = ntohl(address.sin_addr.s_addr);
  std::string out;
  out += std::to_string((host >> 24) & 0xFFU);
  out += '.';
  out += std::to_string((host >> 16) & 0xFFU);
  out += '.';
  out += std::to_string((host >> 8) & 0xFFU);
  out += '.';
  out += std::to_string(host & 0xFFU);
  out += ':';
  out += std::to_string(static_cast<unsigned>(ntohs(address.sin_port)));
  return out;
}

}  // namespace

// --- SocketSubsystem -------------------------------------------------------

Status SocketSubsystem::acquire() {
  std::lock_guard<std::mutex> guard(g_subsystem_mutex);
  if (g_acquire_count.load(std::memory_order_acquire) == 0) {
#if defined(AIFC_PLATFORM_WINDOWS)
    WSADATA data{};
    const int result = ::WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
      return Status::failure(ErrorCode::IO_ERROR,
                             "WSAStartup failed with error " + std::to_string(result));
    }
#endif
  }
  g_acquire_count.fetch_add(1, std::memory_order_acq_rel);
  return Status::success();
}

void SocketSubsystem::release() {
  std::lock_guard<std::mutex> guard(g_subsystem_mutex);
  const std::uint32_t current = g_acquire_count.load(std::memory_order_acquire);
  if (current == 0) return;
  const std::uint32_t remaining = current - 1;
  g_acquire_count.store(remaining, std::memory_order_release);
  if (remaining == 0) {
#if defined(AIFC_PLATFORM_WINDOWS)
    ::WSACleanup();
#endif
  }
}

bool SocketSubsystem::acquired() noexcept {
  return g_acquire_count.load(std::memory_order_acquire) != 0;
}

std::uint32_t SocketSubsystem::acquire_count() noexcept {
  return g_acquire_count.load(std::memory_order_acquire);
}

// --- Socket ----------------------------------------------------------------

Socket Socket::adopt(std::uintptr_t handle) noexcept {
  Socket socket;
  socket.handle_ = handle;
  return socket;
}

Result<Socket> Socket::create() {
  // Creates a descriptor without taking a subsystem reference.  The reference belongs to whoever owns
  // the socket's lifetime -- listen_loopback and connect_loopback each take exactly one and hand it to
  // the socket -- because taking one here and another in the caller is how the process ended up
  // holding two references per connection and never settling back to zero.
  if (!SocketSubsystem::acquired()) {
    return Status::failure(ErrorCode::NOT_RUNNING,
                           "the socket subsystem has not been acquired; call "
                           "SocketSubsystem::acquire() before creating a socket");
  }
  const NativeSocket handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle == kBadSocket) {
    return Status::failure(last_socket_error(), "socket() failed: " + describe_socket_error());
  }
  return Socket::adopt(from_native(handle));
}

Socket::~Socket() { close(); }

Socket::Socket(Socket&& other) noexcept
    : handle_(other.handle_), holds_subsystem_(other.holds_subsystem_) {
  // The subsystem reference moves with the descriptor.  Dropping it here would release a reference
  // the new owner still needs, and the process would tear Winsock down underneath a live socket --
  // which surfaces as WSAENOTINITIALISED (10093) on the next operation, not as anything that points
  // at the move.
  other.handle_ = kInvalidHandle;
  other.holds_subsystem_ = false;
}

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    holds_subsystem_ = other.holds_subsystem_;
    other.handle_ = kInvalidHandle;
    other.holds_subsystem_ = false;
  }
  return *this;
}

void Socket::close() noexcept {
  if (handle_ == kInvalidHandle) {
    if (holds_subsystem_) {
      SocketSubsystem::release();
      holds_subsystem_ = false;
    }
    return;
  }
  close_native(to_native(handle_));
  handle_ = kInvalidHandle;
  if (holds_subsystem_) {
    // The subsystem reference is released only after the descriptor is gone, so the process is
    // never left with a live socket and a torn-down subsystem.
    SocketSubsystem::release();
    holds_subsystem_ = false;
  }
}

Status Socket::shutdown_send() {
  if (!valid()) {
    return Status::failure(ErrorCode::NOT_RUNNING, "socket is not open");
  }
#if defined(AIFC_PLATFORM_WINDOWS)
  if (::shutdown(to_native(handle_), SD_SEND) != 0) {
    return Status::failure(last_socket_error(), "shutdown(SD_SEND) failed: " + describe_socket_error());
  }
#else
  if (::shutdown(to_native(handle_), SHUT_WR) != 0) {
    // A peer that has already gone away reports ENOTCONN; that is not a failure of the
    // local half-close, it is the state we were trying to reach.
    if (errno != ENOTCONN) {
      return Status::failure(last_socket_error(),
                             "shutdown(SHUT_WR) failed: " + describe_socket_error());
    }
  }
#endif
  return Status::success();
}

Status Socket::abortive_close() {
  if (!valid()) {
    return Status::failure(ErrorCode::NOT_RUNNING, "socket is not open");
  }
  // SO_LINGER with a zero timeout makes close() emit a reset instead of a FIN, which
  // is how the adversarial tests produce an abrupt failure at the peer.
  linger option{};
  option.l_onoff = 1;
  option.l_linger = 0;
  (void)::setsockopt(to_native(handle_), SOL_SOCKET, SO_LINGER,
                     reinterpret_cast<const char*>(&option), sizeof(option));
  close();
  return Status::success();
}

Status Socket::set_no_delay(bool enabled) {
  if (!valid()) {
    return Status::failure(ErrorCode::NOT_RUNNING, "socket is not open");
  }
  const int value = enabled ? 1 : 0;
  if (::setsockopt(to_native(handle_), IPPROTO_TCP, TCP_NODELAY,
                   reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
    return Status::failure(last_socket_error(),
                           "setsockopt(TCP_NODELAY) failed: " + describe_socket_error());
  }
  return Status::success();
}

Status Socket::set_reuse_address(bool enabled) {
  if (!valid()) {
    return Status::failure(ErrorCode::NOT_RUNNING, "socket is not open");
  }
  const int value = enabled ? 1 : 0;
  if (::setsockopt(to_native(handle_), SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
    return Status::failure(last_socket_error(),
                           "setsockopt(SO_REUSEADDR) failed: " + describe_socket_error());
  }
  return Status::success();
}

Result<std::string> Socket::peer_address() const {
  if (!valid()) {
    return Status::failure(ErrorCode::NOT_RUNNING, "socket is not open");
  }
  sockaddr_in address{};
#if defined(AIFC_PLATFORM_WINDOWS)
  int length = static_cast<int>(sizeof(address));
#else
  socklen_t length = sizeof(address);
#endif
  if (::getpeername(to_native(handle_), reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    return Status::failure(last_socket_error(),
                           "getpeername failed: " + describe_socket_error());
  }
  return format_v4(address);
}

Result<std::string> Socket::local_address() const {
  if (!valid()) {
    return Status::failure(ErrorCode::NOT_RUNNING, "socket is not open");
  }
  sockaddr_in address{};
#if defined(AIFC_PLATFORM_WINDOWS)
  int length = static_cast<int>(sizeof(address));
#else
  socklen_t length = sizeof(address);
#endif
  if (::getsockname(to_native(handle_), reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    return Status::failure(last_socket_error(), "getsockname failed: " + describe_socket_error());
  }
  return format_v4(address);
}

Result<std::size_t> Socket::receive(std::uint8_t* out, std::size_t length) {
  if (!valid()) {
    return Status::failure(ErrorCode::NOT_RUNNING, "socket is not open");
  }
  for (;;) {
    const int received = ::recv(to_native(handle_), reinterpret_cast<char*>(out),
                                static_cast<int>(length), 0);
    if (received > 0) {
      return static_cast<std::size_t>(received);
    }
    if (received == 0) {
      return std::size_t{0};
    }
    const ErrorCode code = last_socket_error();
#if !defined(AIFC_PLATFORM_WINDOWS)
    if (code == ErrorCode::CANCELLED) continue;  // EINTR: retry, do not report failure
#endif
    return Status::failure(code, "recv failed: " + describe_socket_error());
  }
}

Result<std::size_t> Socket::send(const std::uint8_t* data, std::size_t length) {
  if (!valid()) {
    return Status::failure(ErrorCode::NOT_RUNNING, "socket is not open");
  }
  std::size_t written = 0;
  while (written < length) {
    const std::size_t remaining = length - written;
    const int chunk = remaining > (1U << 20) ? static_cast<int>(1U << 20) : static_cast<int>(remaining);
    const int sent =
        ::send(to_native(handle_), reinterpret_cast<const char*>(data + written), chunk, 0);
    if (sent > 0) {
      written += static_cast<std::size_t>(sent);
      continue;
    }
    if (sent == 0) {
      return Status::failure(ErrorCode::CONNECTION_CLOSED, "send reported a zero-length write");
    }
    const ErrorCode code = last_socket_error();
#if !defined(AIFC_PLATFORM_WINDOWS)
    if (code == ErrorCode::CANCELLED) continue;
#endif
    return Status::failure(code, "send failed: " + describe_socket_error());
  }
  return written;
}

Result<bool> Socket::wait_readable(std::chrono::milliseconds timeout) {
  if (!valid()) {
    return Status::failure(ErrorCode::NOT_RUNNING, "socket is not open");
  }
  const auto bounded = std::max<std::int64_t>(timeout.count(), 0);
#if defined(AIFC_PLATFORM_WINDOWS)
  WSAPOLLFD descriptor{};
  descriptor.fd = to_native(handle_);
  descriptor.events = POLLRDNORM;
  const int ready = ::WSAPoll(&descriptor, 1, static_cast<int>(bounded));
  if (ready > 0) return true;
  if (ready == 0) return false;
  return Status::failure(last_socket_error(), "WSAPoll failed: " + describe_socket_error());
#else
  pollfd descriptor{};
  descriptor.fd = to_native(handle_);
  descriptor.events = POLLIN;
  for (;;) {
    const int ready = ::poll(&descriptor, 1, static_cast<int>(bounded));
    if (ready > 0) return true;
    if (ready == 0) return false;
    if (errno == EINTR) continue;
    return Status::failure(last_socket_error(), "poll failed: " + describe_socket_error());
  }
#endif
}

Result<bool> Socket::wait_writable(std::chrono::milliseconds timeout) {
  if (!valid()) {
    return Status::failure(ErrorCode::NOT_RUNNING, "socket is not open");
  }
  const auto bounded = std::max<std::int64_t>(timeout.count(), 0);
#if defined(AIFC_PLATFORM_WINDOWS)
  WSAPOLLFD descriptor{};
  descriptor.fd = to_native(handle_);
  descriptor.events = POLLWRNORM;
  const int ready = ::WSAPoll(&descriptor, 1, static_cast<int>(bounded));
  if (ready > 0) return true;
  if (ready == 0) return false;
  return Status::failure(last_socket_error(), "WSAPoll failed: " + describe_socket_error());
#else
  pollfd descriptor{};
  descriptor.fd = to_native(handle_);
  descriptor.events = POLLOUT;
  for (;;) {
    const int ready = ::poll(&descriptor, 1, static_cast<int>(bounded));
    if (ready > 0) return true;
    if (ready == 0) return false;
    if (errno == EINTR) continue;
    return Status::failure(last_socket_error(), "poll failed: " + describe_socket_error());
  }
#endif
}

// --- TcpListener -----------------------------------------------------------

TcpListener::~TcpListener() { close(); }

TcpListener::TcpListener(TcpListener&& other) noexcept
    : socket_(std::move(other.socket_)), port_(other.port_) {
  other.port_ = 0;
}

TcpListener& TcpListener::operator=(TcpListener&& other) noexcept {
  if (this != &other) {
    close();
    socket_ = std::move(other.socket_);
    port_ = other.port_;
    other.port_ = 0;
  }
  return *this;
}

void TcpListener::close() noexcept {
  socket_.close();
  port_ = 0;
}

Result<TcpListener> TcpListener::listen_loopback(std::uint16_t port, std::uint32_t backlog) {
  Result<Socket> created = Socket::create();
  if (!created) {
    const Status failure = created.status();
    SocketSubsystem::release();
    return failure;
  }
  TcpListener listener;
  listener.socket_ = std::move(created).value();
  listener.socket_.owns_subsystem(true);
  const NativeSocket handle = to_native(listener.socket_.native_handle());

  const int reuse = 1;
  (void)::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse),
                     sizeof(reuse));

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  // Bound to the loopback address only.  The runtime is not reachable from another
  // host, which is a property the tests rely on and the README states.
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::bind(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    const ErrorCode code = last_socket_error();
    const std::string detail = describe_socket_error();
    listener.close();
    return Status::failure(ErrorCode::BIND_FAILED,
                           "bind to loopback port " + std::to_string(port) +
                               " failed: " + detail + " (" + std::string(to_string(code)) + ")");
  }
  if (::listen(handle, static_cast<int>(backlog)) != 0) {
    const std::string detail = describe_socket_error();
    listener.close();
    return Status::failure(ErrorCode::BIND_FAILED, "listen failed: " + detail);
  }

  sockaddr_in bound{};
#if defined(AIFC_PLATFORM_WINDOWS)
  int length = static_cast<int>(sizeof(bound));
#else
  socklen_t length = sizeof(bound);
#endif
  if (::getsockname(handle, reinterpret_cast<sockaddr*>(&bound), &length) != 0) {
    const std::string detail = describe_socket_error();
    listener.close();
    return Status::failure(ErrorCode::BIND_FAILED, "getsockname failed: " + detail);
  }
  listener.port_ = ntohs(bound.sin_port);
  return listener;
}

Result<Socket> TcpListener::accept(std::chrono::milliseconds timeout) {
  if (!socket_.valid()) {
    return Status::failure(ErrorCode::NOT_RUNNING, "listener is not open");
  }
  Result<bool> ready = socket_.wait_readable(timeout);
  if (!ready) return ready.status();
  if (!ready.value()) {
    // A timeout is not an error: the caller needs to be able to look at its shutdown
    // flag.  The returned socket is invalid, which is unambiguous.
    return Socket{};
  }
  sockaddr_in peer{};
#if defined(AIFC_PLATFORM_WINDOWS)
  int length = static_cast<int>(sizeof(peer));
#else
  socklen_t length = sizeof(peer);
#endif
  const NativeSocket handle =
      ::accept(to_native(socket_.native_handle()), reinterpret_cast<sockaddr*>(&peer), &length);
  if (handle == kBadSocket) {
    return Status::failure(last_socket_error(), "accept failed: " + describe_socket_error());
  }
  Socket accepted = Socket::adopt(from_native(handle));
  // The accepted socket takes its own subsystem reference, so a listener that is closed while a
  // connection is still live does not tear the subsystem down underneath it.
  const Status reference = SocketSubsystem::acquire();
  if (!reference) {
    accepted.close();
    return reference;
  }
  accepted.owns_subsystem(true);
  (void)accepted.set_no_delay(true);
  return accepted;
}

// --- connect ---------------------------------------------------------------

Result<Socket> connect_loopback(std::uint16_t port) {
  // One reference for the whole connection attempt.  Leaning on the temporary inside Socket::create
  // would mean the process leaves Winsock while the connected socket is still in use, which is a
  // lifetime that no call site can see.
  const Status acquired = SocketSubsystem::acquire();
  if (!acquired) return acquired;
  std::string last_detail = "connection was never attempted";
  ErrorCode last_code = ErrorCode::UNREACHABLE;
  for (std::uint16_t attempt = 0; attempt < kConnectAttempts; ++attempt) {
    Result<Socket> created = Socket::create();
    if (!created) return created.status();
    Socket socket = std::move(created).value();
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const NativeSocket handle = to_native(socket.native_handle());
    if (::connect(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0) {
      (void)socket.set_no_delay(true);
      return socket;
    }
    last_code = last_socket_error();
    last_detail = describe_socket_error();
    if (attempt + 1 < kConnectAttempts) {
      std::this_thread::sleep_for(kConnectRetryDelay);
    }
  }
  SocketSubsystem::release();
  return Status::failure(last_code == ErrorCode::OK ? ErrorCode::UNREACHABLE : last_code,
                         "connect to loopback port " + std::to_string(port) +
                             " failed after " + std::to_string(kConnectAttempts) +
                             " attempts: " + last_detail);
}

std::string loopback_endpoint(std::uint16_t port) {
  return "127.0.0.1:" + std::to_string(port);
}

}  // namespace aifc
