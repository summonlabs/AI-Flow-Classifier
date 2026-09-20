// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Real TCP transport over loopback.
//
// The coordinator's distributed behaviour is exercised over real operating system
// sockets, not over an in-process queue.  What that buys is genuine evidence: a
// connection that is closed by a killed process looks like a closed connection here,
// because it is one.
//
// What this does *not* claim: there is no TLS, no peer authentication and no kernel
// bypass.  A session is "authenticated" only in the sense that the coordinator binds
// it at admission time and treats the bound identity as authoritative thereafter.
// Running the coordinator on an untrusted network without an authenticating transport
// in front of it would be a real defect, and the README says so.

#ifndef AI_FLOW_CLASSIFIER_NET_TCP_HPP
#define AI_FLOW_CLASSIFIER_NET_TCP_HPP

#include <ostream>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc {

// One-time process-wide socket subsystem initialisation.  On Windows this is
// WSAStartup; on POSIX it is a no-op that still participates in the same
// acquire/release discipline so that the lifecycle tests exercise the same code path
// on every platform.
class SocketSubsystem {
 public:
  // Initialises the process-wide socket subsystem.  Idempotent and reference counted, so it is safe
  // to call from every component that needs sockets.
  static Status acquire();
  static void release();
  [[nodiscard]] static bool acquired() noexcept;
  [[nodiscard]] static std::uint32_t acquire_count() noexcept;
};

class Socket {
 public:
  Socket() = default;
  ~Socket();
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;

  [[nodiscard]] bool valid() const noexcept { return handle_ != kInvalidHandle; }
  [[nodiscard]] std::uintptr_t native_handle() const noexcept { return handle_; }

  void close() noexcept;

  // Half-closes the send direction, which lets a peer observe end of stream while the
  // local side can still drain what the peer already sent.  This is what the
  // shutdown path uses, because a hard close can discard buffered data.
  Status shutdown_send();

  // Forces a reset rather than a graceful close, used by the adversarial tests to
  // prove that the peer reports an abrupt failure rather than a clean end of stream.
  Status abortive_close();

  Status set_no_delay(bool enabled);
  Status set_reuse_address(bool enabled);

  [[nodiscard]] Result<std::string> peer_address() const;
  [[nodiscard]] Result<std::string> local_address() const;

  // Reads up to length bytes.  A return of zero means the peer closed the stream.
  Result<std::size_t> receive(std::uint8_t* out, std::size_t length);
  Result<std::size_t> send(const std::uint8_t* data, std::size_t length);

  // Waits until the socket is readable, writable or has failed.  Returns true when the
  // requested condition holds, false on timeout.  Used instead of a blocking read so
  // that shutdown never has to wait for a peer that has gone silent.
  Result<bool> wait_readable(std::chrono::milliseconds timeout);
  Result<bool> wait_writable(std::chrono::milliseconds timeout);

  static constexpr std::uintptr_t kInvalidHandle = static_cast<std::uintptr_t>(~0ULL);

  // Wraps an already-created native handle.  This is the single construction point for a
  // connected socket and the only way to build one, so ownership transfers into Socket in
  // exactly one place.  The accept path uses it and so does the connect path.
  [[nodiscard]] static Socket adopt(std::uintptr_t handle) noexcept;

  // Creates a fresh TCP socket and takes the process-wide subsystem reference on its behalf.  Every
  // path that creates a socket goes through here or through adopt(), so there is exactly one place
  // where the reference is taken and exactly one where it is released.
  [[nodiscard]] static Result<Socket> create();

  // Declares that this socket owns the process-wide subsystem reference and must release it when it
  // closes.  Called by the operations that take the reference on the socket's behalf.
  void owns_subsystem(bool owns) noexcept { holds_subsystem_ = owns; }

 private:
  // The listener accepts native descriptors and wraps them, so it is the one collaborator that
  // needs the private construction path rather than the public create().
  friend class TcpListener;

  // True when this socket holds a socket-subsystem reference that it must release.
  //
  // The reference is taken by whoever creates a socket through the public entry points, so a
  // caller that forgets SocketSubsystem::acquire() cannot end up in the state that used to be
  // reachable: a socket that connects successfully in one process and then fails with
  // "subsystem has not been acquired" in another, purely because of which helper was called.
  bool holds_subsystem_ = false;

  std::uintptr_t handle_ = kInvalidHandle;
};

inline constexpr std::uint16_t kConnectAttempts = 40;
inline constexpr std::chrono::milliseconds kConnectRetryDelay{25};

class TcpListener {
 public:
  TcpListener() = default;
  ~TcpListener();
  TcpListener(const TcpListener&) = delete;
  TcpListener& operator=(const TcpListener&) = delete;
  TcpListener(TcpListener&& other) noexcept;
  TcpListener& operator=(TcpListener&& other) noexcept;

  // Binds and listens on the loopback interface.  Port 0 asks the operating system for
  // an ephemeral port; the chosen port is then available from port().
  static Result<TcpListener> listen_loopback(std::uint16_t port, std::uint32_t backlog);

  [[nodiscard]] bool valid() const noexcept { return socket_.valid(); }
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }

  // Accepts one connection, waiting at most timeout for one to arrive.  A timeout is
  // reported as ok() with a default constructed Socket whose valid() is false, which
  // keeps the accept loop able to observe a shutdown request.
  Result<Socket> accept(std::chrono::milliseconds timeout);

  void close() noexcept;

 private:
  Socket socket_;
  std::uint16_t port_ = 0;
};

// Connects to a loopback address, retrying briefly so that a test which starts a
// listener and a client in either order does not race.
[[nodiscard]] Result<Socket> connect_loopback(std::uint16_t port);

// Formats a loopback endpoint for diagnostics.  Never used for authority.
[[nodiscard]] std::string loopback_endpoint(std::uint16_t port);

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_NET_TCP_HPP
