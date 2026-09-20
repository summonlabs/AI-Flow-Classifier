# Proof surfaces

Every test in this repository is a proof obligation, not decoration. This document states what
each surface proves, how to run it, and how the exercised capability is labelled.

## Labels

| Label | Meaning |
| --- | --- |
| **REAL** | The capability genuinely exists and was exercised on this host with the stated toolchain. |
| **SYNTHETIC** | The behaviour is real; the inputs are invented because the hardware or environment is not available. |
| **UNSUPPORTED** | Not present, not exercised, and not claimed. |

## Running everything

```
build_msvc.bat -DAIFC_BUILD_TESTS=ON
cd build/msvc && ctest --output-on-failure
```

or with any generator:

```
cmake -S . -B build/release -DCMAKE_BUILD_TYPE=Release -DAIFC_BUILD_TESTS=ON
cmake --build build/release --parallel
cd build/release && ctest --output-on-failure
```

**There are no test timeouts anywhere.** No `ctest --timeout`, no `TIMEOUT` test property, no
timeout parameter in the framework. A test that hangs is a defect in the code under test, and a
timeout would convert it into a passing build with a silent hole in it.

Every binary also accepts `--list` (print case names) and `--filter=<substring>` (run a subset),
which is how a single property failure is reproduced. A failing property test prints its
reproduction seed as `seed=0x...`.

## The surfaces

### unit/ — deterministic unit tests

| File | Proves |
| --- | --- |
| `test_foundation.cpp` | SHA-256 matches the published FIPS 180-4 vectors; CRC-32 matches the standard vector; checked arithmetic reports overflow instead of wrapping; `Confidence` renders and parses exactly and refuses values it cannot represent exactly; `BufferWriter`/`BufferReader` enforce bounds and reject trailing bytes; identity canonicalisation accepts and rejects the right sets; `Rng` is reproducible for a seed; `Counter` refuses to wrap; `ResourceLimits::effective()` clamps. |
| `test_domain.cpp` | Semantic class, source, state and transport vocabularies are canonical and round-trip; **a near-miss label is refused and never becomes `UNKNOWN`**; source ranking and confidence constants; `decode_*` maps unknown codes to the weakest value; flow identity is injective and stable; digests are sensitive to every authority-relevant field and insensitive to bookkeeping. |
| `test_policy.cpp` | A contradictory policy (an enabled adapter while heuristics are globally off, an unscoped hint, a duplicate name, an out-of-range confidence, a zero freshness window) is refused rather than silently neutralised; declaration order does not change the policy digest. |
| `test_store.cpp` | Registry bounds and idempotence; flow generation advance fences the previous incarnation; a retired generation cannot be resurrected; publisher boot advance, replay detection and liveness expiry; contract proposal/activation/retirement rules; evidence store eviction is counted; a record can never move back to `CURRENT`; a restored record is never `CURRENT`. |
| `test_decision_engine.cpp` | The pure precedence order, currentness rules, contradiction reporting and penalty, the publishable threshold, the consideration cap, and the engine's own final invariant — all driven directly through `DecisionEngine::decide`. |
| `test_freshness_and_ticks.cpp` | Freshness and liveness are expressed in ticks the caller supplies, so a test can stand exactly on a boundary: a record is current at its deadline and stale one tick later; a publisher that goes idle past the window stops carrying authority, and a heartbeat restores liveness without restoring an elapsed freshness window; two classifiers at different ticks agree on the decision digest, which is what makes the digest independent of when it was computed. |

### integration/ — components together

| File | Proves |
| --- | --- |
| `test_classifier_flows.cpp` | `UNKNOWN` before any evidence with confidence `0.0000`; a generation advance stales evidence *and* recorded classifications; a superseded generation is answered as historical, not current; batch classification reports per-key statuses while the batch itself succeeds. |
| `test_classifier_evidence.cpp` | The authenticated path end to end, including that a peer claiming a higher source than its session ceiling is **clamped and told**, that the envelope decides identity, that a contract may only be cited by its owner, and that ending a session stales that publisher's evidence with a stated reason. |
| `test_coordinator_inprocess.cpp` | The coordinator state machine driven by hand-encoded frames: handshake, registration, publication, classification, stale epoch refusal, unauthenticated refusal, unsupported version refusal, undefined message kind refusal. |

### property/ — seeded randomized runs

| File | Proves |
| --- | --- |
| `test_precedence_properties.cpp` | Over randomly generated evidence sets: the precedence order is irreflexive, antisymmetric and transitive; the selected record is the maximum under it; a stronger source on an otherwise identical record never loses; a current authenticated declaration always beats a current heuristic record. |
| `test_contradiction_properties.cpp` | A contradiction is reported exactly when two or more current authoritative records disagree; the list is stable under permutation; the penalty always equals the configured value when the list is non-empty; a heuristic disagreement is never a contradiction. |
| `test_determinism_properties.cpp` | The same canonical evidence set produces the same decision digest **across processes, submission orders and reconstructions**, and changing any single content-bearing field changes it. |

Every property test prints the seed on failure so the failure can be replayed exactly.

### concurrency/

| File | Proves |
| --- | --- |
| `test_classifier_concurrency.cpp` | Many threads submitting, classifying and querying one classifier with deterministic barriers: no crash, no deadlock, no lost submission, and consistent results. |
| `test_service_lifecycle.cpp` | Repeated start/stop cycles: no leaked thread, connection or queue entry; the socket subsystem reference count returns to its starting value; starting twice is refused; a client that connects and then goes silent cannot hold shutdown open. |

### adversarial/

| File | Proves |
| --- | --- |
| `test_codec_fuzz.cpp` | Seeded fuzzing of every decoder with bit flips, truncation at every length, absurd declared lengths, huge counts, reversed fields and trailing garbage: every malformed input is refused with a specific code, and **nothing is allocated past the declared bound**. |
| `test_label_privilege.cpp` | The central claim: **a malformed label cannot produce a privileged semantic class.** Every mutation is driven through the real submission path, and the result is either the legitimate class of the admissible evidence or `UNKNOWN`. |
| `test_frame_adversarial.cpp` | Bad magic, wrong version, undefined kind, lying lengths, corrupted integrity tags, truncation at every offset, glued frames, split frames, and a peer that stops mid-frame. |

### persistence/

| File | Proves |
| --- | --- |
| `test_snapshot_roundtrip.cpp` | Every field of every collection survives a write/read cycle, and the image is deterministic apart from the wall-clock stamp. |
| `test_snapshot_corruption.cpp` | Bad magic, unsupported format version, unsupported persistence generation, lying body length, flipped header byte, flipped body byte, truncation at every length, trailing bytes — each refused with its specific code, **and with the target state untouched**. |
| `test_restart_authority.cpp` | Persistence is not currentness: after a restart every session is gone, every restored record is stale with a stated reason, history keeps the old digest as a historical fact, and authority returns only when a publisher actually re-establishes it. |

### protocol/ — real loopback TCP

| File | Proves |
| --- | --- |
| `test_loopback_transport.cpp` | A complete exchange over real `127.0.0.1` sockets: listen, connect, handshake, register, declare, publish, classify. Plus stale-epoch refusal, unsupported-version refusal, unauthenticated refusal, and a corrupted frame causing the coordinator to close the connection without answering. |
| `test_message_roundtrip.cpp` | Every message codec round-trips field by field, re-encodes to identical bytes, rejects trailing bytes and truncation, and — importantly — **the evidence message contains no field in which a peer could assert a publisher, session, epoch or source ceiling**. |

### multiprocess/ — real independent OS processes

| File | Proves |
| --- | --- |
| `test_publisher_processes.cpp` | A real publisher process is **killed with an immediate termination** (no destructor, no flush, no goodbye) and its evidence stops being current. A coordinator that is killed abruptly leaves durable state that is readable and that a fresh incarnation can start on, with the pre-restart evidence not current. |
| `test_coordinator_restart.cpp` | A publisher restart advances the boot fence and the superseded boot is refused; an evidence generation replay is refused; a coordinator restart advances the epoch and does not resurrect liveness; a publisher must **learn** the new epoch by handshaking rather than assuming it. |

### scale/

| File | Proves |
| --- | --- |
| `test_indexed_lookup.cpp` | Per-classification cost does not grow with the size of the runtime: the same probe flows are measured against a population of 512 and then 8704, and the ratio must stay far below what a per-flow scan would produce. Also asserts that derived flow identities are unique across thousands of flows and that batch classification is bounded by policy and reports per-key failures without failing as a whole. |

### tests/downstream_consumer/

An independent CMake project that is **not part of this build**. It is configured separately
against an installed prefix and links `AIFlowClassifier::ai_flow_classifier`, exercising the
public API end to end. See `docs/release.md` for the exact commands.

## Environment and toolchain labels

| Item | Status on this host |
| --- | --- |
| Compiler | MSVC 19.44.35209 (Visual Studio 2022 17.14), x64. |
| Warnings | `/W4 /permissive- /utf-8` plus the curated extra warnings, with `/WX`. Zero first-party warnings. |
| AddressSanitizer | **UNSUPPORTED.** Probed: `cl /fsanitize=address` links only for x86 here, because this installation ships `clang_rt.asan_*-i386` but not the x86-64 runtime; an x64 link fails with `LNK1104: cannot open file 'clang_rt.asan_static_runtime_thunk-x86_64.lib'`. `AIFC_ENABLE_SANITIZERS` performs the same probe and reports UNSUPPORTED rather than adding flags that cannot link. No sanitizer coverage is claimed. |
| UndefinedBehaviorSanitizer | **UNSUPPORTED** on MSVC. |
| ThreadSanitizer | **UNSUPPORTED** on MSVC. |
| AI fabric hardware | **ABSENT.** All collective, RDMA, checkpoint and topology dimensions are SYNTHETIC metadata. |

## What is deliberately not proven

* Physical validation on NVLink, InfiniBand, RoCE, RDMA, SmartNIC/DPU or programmable switches.
* Transport security. There is no TLS, no peer certificate and no message authentication code;
  the coordinator binds loopback and the README states the limitation.
* Memory-safety guarantees beyond what the language and the bounds discipline provide: no
  sanitizer ran on this host.
* Multi-host behaviour, because the listener is loopback-only by design.
