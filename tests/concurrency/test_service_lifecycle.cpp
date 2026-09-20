// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Lifecycle tests for aifc::CoordinatorService.
//
// REAL / SYNTHETIC
// ----------------
// REAL: real loopback TCP listeners on port 0 (ephemeral), real accept and worker threads,
// the shipped socket-subsystem acquire/release accounting, and real client sockets that are
// deliberately silent or abruptly closed.  SYNTHETIC: nothing here needs a second process or
// an external peer; every byte of evidence comes from this process.
//
// What is asserted after EVERY cycle:
//   * running() is false;
//   * stats() reports zero active connections and zero queued entries;
//   * the socket subsystem acquire count is back to the value it had before the cycle;
//   * cycles_started and cycles_stopped have each advanced by exactly one;
//   * the joined-thread total has advanced by exactly one acceptor plus the worker count,
//     so a cycle that leaked a thread cannot hide;
//   * the monotonic counters never move backwards.
//
// No test carries a timeout: the framework has none by design, and a hanging lifecycle is a
// defect to diagnose rather than a condition to survive.  What this file does instead is
// measure the wall clock and put the measured value into every failure message, so a cycle
// that does not settle names how long it took and how far the counters got.

#include <chrono>
#include <cstdint>
#include <string>
#include <thread>

#include "synthetic.hpp"
#include "test_framework.hpp"

namespace {

using SteadyClock = std::chrono::steady_clock;

[[nodiscard]] std::uint64_t elapsed_millis(SteadyClock::time_point start) {
  const auto elapsed = SteadyClock::now() - start;
  const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
  return millis < 0 ? 0U : static_cast<std::uint64_t>(millis);
}

constexpr std::uint32_t kWorkerThreads = 2U;
// The whole-case bound.  Twelve start/stop cycles of a service with two workers take tens of
// milliseconds on an idle machine; this bound is three orders of magnitude above that, so it
// cannot fail because of scheduling noise, and it does catch a lifecycle that accumulates a
// leak per cycle and therefore gets slower every time.
constexpr std::uint64_t kCycleCaseBudgetMillis = 120000U;
// The silent-client bound, asserted against a receive timeout of 20 s: if a stop() had to wait
// for the peer's own receive window to elapse, it would take at least 20 s.
constexpr std::uint64_t kPromptStopBoundMillis = 8000U;
constexpr std::uint64_t kSilentClientReceiveTimeoutMillis = 20000U;

[[nodiscard]] aifc::CoordinatorServiceOptions lifecycle_options() {
  aifc::CoordinatorServiceOptions options;
  options.port = 0;  // the operating system chooses an ephemeral port
  options.backlog = 8;
  options.worker_threads = kWorkerThreads;
  options.accept_slice = std::chrono::milliseconds{5};
  options.receive_timeout = std::chrono::milliseconds{1000};
  options.drain_timeout = std::chrono::milliseconds{2000};
  return options;
}

[[nodiscard]] std::string describe(const aifc::ServiceStats& stats) {
  std::string out;
  out += "cycles_started=" + std::to_string(stats.cycles_started);
  out += " cycles_stopped=" + std::to_string(stats.cycles_stopped);
  out += " accepted=" + std::to_string(stats.accepted);
  out += " rejected=" + std::to_string(stats.rejected);
  out += " connections_served=" + std::to_string(stats.connections_served);
  out += " queue_rejections=" + std::to_string(stats.queue_rejections);
  out += " queue_high_water=" + std::to_string(stats.queue_high_water);
  out += " threads_joined=" + std::to_string(stats.threads_joined);
  out += " active_connections=" + std::to_string(stats.active_connections);
  out += " queued=" + std::to_string(stats.queued);
  return out;
}

// All post-stop invariants for one cycle.  Returns false if anything failed, so the caller can
// stop instead of producing one failure per remaining cycle.
[[nodiscard]] bool check_settled_cycle(const aifc::CoordinatorService& service,
                                       std::uint32_t cycle, std::uint32_t baseline_acquires,
                                       std::uint64_t cycle_millis, std::uint64_t case_millis,
                                       const aifc::ServiceStats& previous) {
  const std::size_t before = aifc_test::Registry::instance().failures().size();
  const aifc::ServiceStats stats = service.stats();
  const std::string context =
      "cycle=" + std::to_string(cycle) + " cycle_millis=" + std::to_string(cycle_millis) +
      " case_millis=" + std::to_string(case_millis) + " stats={" + describe(stats) + "}";

  AIFC_CHECK_MSG(!service.running(), "the service is still running after stop(): " + context);
  AIFC_CHECK_MSG(stats.active_connections == 0U,
                 "the service still reports active connections after stop(): " + context);
  AIFC_CHECK_MSG(stats.queued == 0U,
                 "the service still reports queued entries after stop(): " + context);
  AIFC_CHECK_MSG(stats.cycles_started == cycle,
                 "cycles_started did not advance by exactly one per cycle: " + context);
  AIFC_CHECK_MSG(stats.cycles_stopped == cycle,
                 "cycles_stopped did not advance by exactly one per cycle: " + context);
  AIFC_CHECK_MSG(stats.threads_joined == static_cast<std::uint64_t>(cycle) * (1U + kWorkerThreads),
                 "the joined-thread total is not one acceptor plus " +
                     std::to_string(kWorkerThreads) + " workers per cycle: " + context);
  AIFC_CHECK_MSG(aifc::SocketSubsystem::acquire_count() == baseline_acquires,
                 "the socket subsystem acquire count is " +
                     std::to_string(aifc::SocketSubsystem::acquire_count()) +
                     " rather than the pre-cycle value " + std::to_string(baseline_acquires) +
                     ": " + context);
  AIFC_CHECK_MSG(stats.accepted >= previous.accepted &&
                     stats.connections_served >= previous.connections_served &&
                     stats.threads_joined > previous.threads_joined && stats.rejected >= previous.rejected,
                 "a monotonic counter moved backwards: previous={" + describe(previous) +
                     "} current={" + describe(stats) + "}");
  return aifc_test::Registry::instance().failures().size() == before;
}

// ---------------------------------------------------------------------------
// Case 1: twelve consecutive cycles, including connection churn
// ---------------------------------------------------------------------------

// SYNTHETIC peers, REAL service.  Twelve consecutive start/stop cycles.  Every fourth cycle a
// client connects and goes silent; every third cycle a client connects and closes at once.  A
// leak of a thread, a connection or a queue entry would show up as a counter that does not
// return to its starting value, not as a slow drift.
AIFC_TEST("service.lifecycle.twelve_cycles_return_to_a_clean_state") {
  const std::uint32_t baseline_acquires = aifc::SocketSubsystem::acquire_count();
  const SteadyClock::time_point case_start = SteadyClock::now();

  aifc::CoordinatorService service(lifecycle_options());
  constexpr std::uint32_t kCycles = 12U;
  aifc::ServiceStats previous = service.stats();

  std::uint32_t settled_cycles = 0;
  for (std::uint32_t cycle = 1; cycle <= kCycles; ++cycle) {
    const SteadyClock::time_point cycle_start = SteadyClock::now();
    const std::size_t failures_before = aifc_test::Registry::instance().failures().size();

    AIFC_CHECK_OK(service.start(aifc::CoordinatorBootId{cycle}));
    if (aifc_test::Registry::instance().failures().size() != failures_before) break;
    AIFC_CHECK_MSG(service.running(), "cycle " << cycle << " did not report running after start");
    AIFC_CHECK_MSG(service.port() != 0U, "cycle " << cycle << " did not bind an ephemeral port");
    AIFC_CHECK_MSG(aifc::SocketSubsystem::acquire_count() == baseline_acquires + 1U,
                   "cycle " << cycle << " should hold exactly one socket subsystem acquisition, but "
                            << "the count is " << aifc::SocketSubsystem::acquire_count()
                            << " and the baseline is " << baseline_acquires);
    if (aifc_test::Registry::instance().failures().size() != failures_before) break;

    // Connection churn: a client that closes immediately, and a client that says nothing.
    aifc::Result<aifc::Socket> client = aifc::connect_loopback(service.port());
    if (cycle % 4U == 0U) {
      // Silent client: it is destroyed at the end of this iteration, but stop() runs first.
      // Nothing is asserted about how far it got: a queued or a served connection are both
      // legitimate, and the point is that the stop path closes it either way.
      (void)client;
    } else {
      if (client) client.value().close();
    }

    AIFC_CHECK_OK(service.stop());
    const std::uint64_t cycle_millis = elapsed_millis(cycle_start);
    if (!check_settled_cycle(service, cycle, baseline_acquires, cycle_millis,
                             elapsed_millis(case_start), previous)) {
      break;
    }
    previous = service.stats();
    settled_cycles = cycle;
  }

  const std::uint64_t case_millis = elapsed_millis(case_start);
  AIFC_CHECK_MSG(settled_cycles == kCycles,
                 "only " << settled_cycles << " of " << kCycles
                         << " cycles settled; case_millis=" << case_millis
                         << " stats={" << describe(service.stats()) << "}");
  AIFC_CHECK_MSG(case_millis < kCycleCaseBudgetMillis,
                 kCycles << " start/stop cycles took " << case_millis
                         << " ms, above the budget of " << kCycleCaseBudgetMillis
                         << " ms; that is what an accumulating leak per cycle looks like: stats={"
                         << describe(service.stats()) << "}");
  AIFC_CHECK_MSG(!service.running(), "the service is still running at the end of the case");
  AIFC_CHECK_MSG(aifc::SocketSubsystem::acquire_count() == baseline_acquires,
                 "the socket subsystem acquire count is "
                     << aifc::SocketSubsystem::acquire_count() << " at the end of the case, not "
                     << baseline_acquires);
}

// ---------------------------------------------------------------------------
// Case 2: start twice, stop twice
// ---------------------------------------------------------------------------

// SYNTHETIC peers, REAL service.  Starting an already running service is ALREADY_RUNNING and
// must not disturb the running one; stop() is idempotent; a stop of a service that was never
// started is a successful no-op that does not advance the cycle counters.
AIFC_TEST("service.lifecycle.start_twice_refuses_and_stop_is_idempotent") {
  const std::uint32_t baseline_acquires = aifc::SocketSubsystem::acquire_count();
  aifc::CoordinatorService service(lifecycle_options());

  // stop() before start(): a successful no-op.
  AIFC_CHECK_OK(service.stop());
  AIFC_CHECK_MSG(!service.running(), "a never-started service reports running");
  AIFC_CHECK_MSG(service.stats().cycles_stopped == 0U,
                 "a stop of a never-started service advanced cycles_stopped: "
                     << describe(service.stats()));
  AIFC_CHECK_MSG(aifc::SocketSubsystem::acquire_count() == baseline_acquires,
                 "a stop of a never-started service changed the socket subsystem count from "
                     << baseline_acquires << " to " << aifc::SocketSubsystem::acquire_count());

  AIFC_CHECK_OK(service.start(aifc::CoordinatorBootId{1}));
  const std::uint16_t first_port = service.port();
  AIFC_CHECK_MSG(first_port != 0U, "the first start did not bind an ephemeral port");
  AIFC_CHECK_EQ(service.stats().cycles_started, 1U);
  AIFC_CHECK_MSG(aifc::SocketSubsystem::acquire_count() == baseline_acquires + 1U,
                 "a running service should hold exactly one acquisition, count="
                     << aifc::SocketSubsystem::acquire_count() << " baseline=" << baseline_acquires);

  const aifc::Status second_start = service.start(aifc::CoordinatorBootId{2});
  AIFC_CHECK_MSG(!second_start.ok(),
                 "starting an already running service succeeded: "
                     << aifc::render_status(second_start));
  AIFC_CHECK_MSG(second_start.code == aifc::ErrorCode::ALREADY_RUNNING,
                 "starting an already running service failed with "
                     << aifc::render_status(second_start) << " rather than ALREADY_RUNNING");
  AIFC_CHECK_MSG(service.running(), "the refused second start stopped the running service");
  AIFC_CHECK_MSG(service.port() == first_port,
                 "the refused second start rebound the listener: port " << service.port()
                                                                        << " was " << first_port);
  AIFC_CHECK_EQ(service.stats().cycles_started, 1U);
  AIFC_CHECK_MSG(aifc::SocketSubsystem::acquire_count() == baseline_acquires + 1U,
                 "the refused second start changed the socket subsystem count to "
                     << aifc::SocketSubsystem::acquire_count());

  AIFC_CHECK_OK(service.stop());
  AIFC_CHECK_EQ(service.stats().cycles_stopped, 1U);
  AIFC_CHECK_MSG(aifc::SocketSubsystem::acquire_count() == baseline_acquires,
                 "after the first stop the acquire count is "
                     << aifc::SocketSubsystem::acquire_count() << " rather than " << baseline_acquires);

  AIFC_CHECK_OK(service.stop());
  AIFC_CHECK_OK(service.stop());
  AIFC_CHECK_MSG(service.stats().cycles_stopped == 1U,
                 "a repeated stop advanced cycles_stopped: " << describe(service.stats()));
  AIFC_CHECK_MSG(service.stats().active_connections == 0U && service.stats().queued == 0U,
                 "a repeated stop left connection accounting behind: "
                     << describe(service.stats()));
  AIFC_CHECK_MSG(aifc::SocketSubsystem::acquire_count() == baseline_acquires,
                 "a repeated stop released the socket subsystem again: count="
                     << aifc::SocketSubsystem::acquire_count());

  // A start after a stop is a fresh cycle, not a resurrection of the old one.
  AIFC_CHECK_OK(service.start(aifc::CoordinatorBootId{3}));
  AIFC_CHECK_EQ(service.stats().cycles_started, 2U);
  AIFC_CHECK_OK(service.stop());
  AIFC_CHECK_EQ(service.stats().cycles_stopped, 2U);
  AIFC_CHECK_MSG(aifc::SocketSubsystem::acquire_count() == baseline_acquires,
                 "the second cycle did not return the acquire count to " << baseline_acquires
                                                                        << ", count="
                     << aifc::SocketSubsystem::acquire_count());
}

// ---------------------------------------------------------------------------
// Case 3: a client that never sends anything
// ---------------------------------------------------------------------------

// SYNTHETIC peer, REAL service.  A client connects and never writes a byte, so the only thing
// that can end its connection is the stop path closing it: receive_timeout is 20 s, and a stop
// that waited for the peer would take at least that long.
AIFC_TEST("service.lifecycle.silent_client_does_not_delay_a_prompt_stop") {
  const std::uint32_t baseline_acquires = aifc::SocketSubsystem::acquire_count();
  aifc::CoordinatorServiceOptions options = lifecycle_options();
  options.receive_timeout = std::chrono::milliseconds{kSilentClientReceiveTimeoutMillis};

  aifc::CoordinatorService service(options);
  const SteadyClock::time_point case_start = SteadyClock::now();
  AIFC_CHECK_OK(service.start(aifc::CoordinatorBootId{1}));
  const std::uint16_t port = service.port();
  AIFC_CHECK_MSG(port != 0U, "the service did not bind an ephemeral port");

  const aifc::Result<aifc::Socket> client = aifc::connect_loopback(port);
  AIFC_CHECK_OK(client);
  if (!client) {
    AIFC_CHECK_OK(service.stop());
    return;
  }

  // Wait, bounded, until the listener has actually accepted the connection, so that the stop
  // really is racing a live connection rather than a connect() that has not landed yet.
  const SteadyClock::time_point accept_start = SteadyClock::now();
  bool accepted = false;
  while (elapsed_millis(accept_start) < 5000U) {
    if (service.stats().accepted >= 1U) {
      accepted = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
  }
  AIFC_CHECK_MSG(accepted,
                 "the listener did not accept the silent client within 5000 ms: stats={"
                     << describe(service.stats()) << "}");

  const SteadyClock::time_point stop_start = SteadyClock::now();
  AIFC_CHECK_OK(service.stop());
  const std::uint64_t stop_millis = elapsed_millis(stop_start);
  const std::uint64_t case_millis = elapsed_millis(case_start);
  const aifc::ServiceStats stats = service.stats();

  AIFC_CHECK_MSG(!service.running(), "the service is still running after stopping with a silent "
                                     "client connected: stats={" << describe(stats) << "}");
  AIFC_CHECK_MSG(stats.active_connections == 0U,
                 "a connection survived the stop: stats={" << describe(stats) << "}");
  AIFC_CHECK_MSG(stats.queued == 0U,
                 "a queue entry survived the stop: stats={" << describe(stats) << "}");
  AIFC_CHECK_MSG(stats.cycles_started == 1U && stats.cycles_stopped == 1U,
                 "the silent-client cycle did not advance both cycle counters by one: stats={"
                     << describe(stats) << "}");
  AIFC_CHECK_MSG(aifc::SocketSubsystem::acquire_count() == baseline_acquires,
                 "the silent-client cycle did not return the acquire count to "
                     << baseline_acquires << ": count="
                     << aifc::SocketSubsystem::acquire_count());
  AIFC_CHECK_MSG(stop_millis < kPromptStopBoundMillis,
                 "stop() took " << stop_millis << " ms with a silent client connected; the receive "
                                << "timeout is " << kSilentClientReceiveTimeoutMillis
                                << " ms, so a stop that waited for the peer instead of closing its "
                                << "socket would take at least that long. case_millis="
                                << case_millis << " stats={" << describe(stats) << "}");
}

}  // namespace
