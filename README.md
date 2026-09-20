# AI Flow Classifier

Open-source, vendor-neutral C++20 runtime for classifying network flows by AI workload
semantics, provenance, lifecycle, and generation-bound evidence rather than relying on ports or
five-tuples alone.

The question this runtime answers is:

> **What AI workload semantic class does this flow belong to now, based on explicit evidence and
> provenance, how certain is that classification, and which facts must remain unknown rather than
> guessed?**

It answers that question with a typed classification, an explicit evidence state, a confidence
value that is a fixed-point function of the evidence rather than a measurement, and an
explanation that cites the exact records that produced the answer -- including the ones that
lost and the reason each one lost.

Version 1.0.0. C++20. CMake. Windows and POSIX. No third-party dependencies whatsoever: the
runtime uses only the C++ standard library and the operating system's socket API.

---

## 1. What this runtime owns, and what it does not

### Owned

* **Semantic classification** of AI-related flows, bound to a flow generation and a policy
  generation.
* **Evidence and provenance**: where a claim came from, how strongly it counts, whether it is
  still current, and what it lost to.
* **Confidence and evidence state** as an explicit, reproducible function of the evidence set.
* **Explanations** that list every record considered, its disposition, and the precedence rule
  that decided it.
* **Contradiction and revocation records**, including supersession of a replaced evidence
  generation.
* **Generation and incarnation fencing**: flow, workload, evidence, publisher boot, coordinator
  epoch and boot, and policy generation.
* **Durable coordinator state** in a versioned, integrity-checked format, with an explicit
  durability point.

### Explicitly not owned

| Adjacent system | Why it is not here |
| --- | --- |
| Packet capture | This runtime is given flow metadata; it does not observe traffic. |
| DPI of arbitrary application payloads | Payload content is never required. See the privacy note in §9. |
| Routing, QoS enforcement, admission control | Those consume a classification; they are policy decisions. |
| Workload scheduling and lifecycle | A classification describes work; it does not start, stop or place it. |
| Authentication of peers | The coordinator binds a session at admission; it does not implement TLS. See §10. |
| Policy that acts on the classification | The runtime states a class and its evidence. A consumer decides what to do. |

The boundary is deliberately narrow, because a classifier that also enforces is a classifier
whose evidence nobody can audit.

---

## 2. Core model and authority semantics

### Identities

| Type | Meaning |
| --- | --- |
| `FlowId` | Opaque 128-bit identity derived from the canonical flow key. |
| `FlowGeneration` | One incarnation of a flow key. Never inferred from the identity. |
| `PublisherId` | The stable name of a metadata source. |
| `PublisherBootId` | The incarnation of a publisher *process*. |
| `WorkloadId` / `WorkloadGeneration` | A named unit of AI work and the generation of its declaration. |
| `EvidenceId` / `EvidenceGeneration` | A record's identity (minted by the coordinator) and its publication generation. |
| `CoordinatorEpoch` / `CoordinatorBootId` | The incarnation of the authority that accepted a record. |
| `ClassifierPolicyGeneration` | The policy under which a decision was made. |

Identifiers are strongly typed: a `PublisherId` cannot be passed where a `WorkloadId` is
expected, and an identifier is never a substitute for a generation.

### Semantic classes

`UNKNOWN`, `COLLECTIVE`, `TRAINING_SYNC`, `INFERENCE_REQUEST`, `PREFILL_DECODE_HANDOFF`,
`KV_STATE_TRANSFER`, `MODEL_STATE_TRANSFER`, `SHUFFLE`, `CHECKPOINT`, `STORAGE_DATA`,
`CONTROL_PLANE`, `TELEMETRY`.

The vocabulary is closed at the wire level and open at the extension level. An unknown numeric
code decodes to `UNKNOWN` -- the weakest value -- and a class at or above the extension base
exists only while a matching registration is live, so an extension is a deliberate, visible act.

### Evidence sources, strongest first

| Source | Rank | Confidence it can justify | Requires a live session |
| --- | ---: | ---: | --- |
| `DECLARED_AUTHENTICATED` | 5 | 0.9000 | yes |
| `CONTRACT_DERIVED` | 4 | 0.8000 | no -- governed by the contract's own currentness |
| `COORDINATOR_CORRELATED` | 3 | 0.7000 | yes |
| `TOPOLOGY_CORRELATED` | 2 | 0.5000 | yes |
| `HEURISTIC` | 1 | 0.2000 on a citation; never a winner | no -- it never had authority to lose |
| `UNKNOWN` | 0 | 0.0000 | — |

These are constants of the policy, not measurements. A peer's claim about its own quality is
clamped down to the ceiling its session was admitted at; it can never be raised. There is no
field in any request message in which a peer can assert a source at all for the *envelope* —
the source is a coordinator-side decision recorded at admission time.

### Evidence states

`EVIDENCE_CURRENT`, `EVIDENCE_STALE`, `EVIDENCE_SUPERSEDED`, `EVIDENCE_REVOKED`,
`EVIDENCE_INSUFFICIENT`, `EVIDENCE_REJECTED`, `EVIDENCE_NONE`.

Only `EVIDENCE_CURRENT` carries authority. A record can move to a weaker state and can never
move back: re-establishing authority requires a new publication with a new generation, never a
state edit.

---

## 3. The decision rule, in full

The engine is a pure function of its inputs. It takes no locks, performs no I/O and reads no
clock; freshness is supplied as a tick.

**Precedence, applied in order:**

1. **Currentness.** A record that is not `EVIDENCE_CURRENT` cannot win, whatever it says.
2. **Source rank.** Higher rank wins outright.
3. **Workload generation.** A higher generation outranks a lower one: same declaration, later.
4. **Acceptance order.** A later accepted sequence outranks an earlier one.
5. **Evidence identity.** The lexicographically smaller id wins.

Rules 4 and 5 exist to make the order *total*. A total order is what makes "which record won" a
question with exactly one answer, reproducible in any process.

**Currentness is re-derived at decision time, not trusted from the record.** A record is current
only if all of the following hold:

* it is bound to the flow generation being asked about;
* it was accepted in the coordinator epoch that is running now;
* its source requires a live session, and that publisher *incarnation* (identity **and** boot)
  is live right now;
* the requested tick has not passed its freshness deadline.

**Contradictions.** Two current, authoritative records that disagree produce a
`CONTRADICTED` classification: the winner is chosen by the order above, both are cited, the
disagreement is listed, and the configured penalty is applied **and reported** in
`applied_penalty_basis_points`. Heuristic records never contradict: a guess that disagrees with
a declaration is a guess that lost, and it is recorded as `SUBORDINATE`.

**The publishable threshold.** A winner whose penalised confidence falls below
`minimum_publishable_confidence` does not become a weaker class, and does not silently become
`UNKNOWN`. It becomes `UNKNOWN` with state `INSUFFICIENT` and confidence `0.0000`, and the
candidate that fell short is still cited as `BELOW_THRESHOLD`. This is the mechanism that keeps
`UNKNOWN` honest.

**The final invariant.** Before returning, the engine asserts that a non-`UNKNOWN` class is
justified by at least one cited, current record bearing that class. If it is not, the answer is
`UNKNOWN`/`INSUFFICIENT`. The check is in the code path, not only in a test.

### Denial and error reasons

Every failure carries a stable `ErrorCode` and an `ErrorClass`. Nothing in this runtime returns
a bare boolean for an operation that can fail for more than one reason. Representative codes:

| Code | Class | Meaning |
| --- | --- | --- |
| `STALE_GENERATION` | AUTHORITY | The cited generation has been superseded. |
| `STALE_BOOT_ID` | AUTHORITY | The publisher incarnation presented is not the current one. |
| `STALE_EPOCH` | AUTHORITY | The frame or session predates the running coordinator incarnation. |
| `REPLAY_DETECTED` | AUTHORITY | The evidence generation is at or below the observed high-water mark. |
| `PUBLISHER_DEAD` | AUTHORITY | The session is gone, so its claims are not current. |
| `UNAUTHENTICATED` | AUTHORITY | No publisher is registered on the session, or the envelope does not match it. |
| `UNAUTHORIZED` | AUTHORITY | The publisher does not own the workload or contract it cites. |
| `HEURISTIC_DISABLED` | DENIAL | The policy does not permit heuristic evidence. |
| `INTEGRITY_FAILURE` | INTEGRITY | A digest or integrity tag does not match. |
| `TRAILING_GARBAGE` | INTEGRITY | A canonical record or frame had bytes left over. |
| `UNSUPPORTED_FORMAT_VERSION` | INTEGRITY | A persisted format this build does not understand. |
| `CAPACITY_EXCEEDED` | RESOURCE | A declared length or count exceeded its bound, refused before allocation. |
| `CONTRADICTORY_EVIDENCE` | DENIAL | Reported when a caller asks about a contested generation. |

---

## 4. Determinism and reproducibility

* Confidence is **fixed point** (basis points, denominator 10000). No decision involves
  floating-point arithmetic, so a confidence is bit-for-bit reproducible.
* Every classification carries a **decision digest** computed over the content only: flow id and
  generation, class, state, confidence, selected evidence and source, corroboration count,
  applied penalty, policy generation and policy digest, sorted citations, and contradictions.
  Tick, epoch and boot are excluded, so the same canonical evidence set produces the same digest
  in a different process, in a different epoch, after a restart.
* The **policy digest** covers the policy's content with the generation number excluded, which is
  precisely what detects content that changed while the generation did not. Installing a policy
  whose content is unchanged does *not* advance the generation.
* Citations are sorted canonically before rendering, so an explanation is a pure function of the
  decision.
* The decision **memo** is keyed by (flow id, flow generation, evidence-set digest, policy
  generation). It is a cache with no authority: a miss means recomputation, and a stale entry is
  unreachable by construction.

---

## 5. Persistence semantics

**Format.** A fixed header (magic `AIFS`, format version, persistence generation, body length,
epoch, boot, sequence high-water mark, written-at, SHA-256 of the body, CRC-32 of the header)
followed by a canonical body of independently versioned records.

**Rules.** A body longer than the configured bound is refused before allocation. A format
version or persistence generation this build does not understand is refused as
`UNSUPPORTED_FORMAT_VERSION` and nothing is applied. Both the header checksum and the body digest
are verified before decoding. The body is decoded into a staging structure and handed to the
caller only once every record has decoded successfully, so a torn or corrupted file can never be
partially applied.

**Mutation semantics.** `plan → validate authority → prepare → perform effect if applicable →
verify → durable commit → publish authoritative result`. The only durability acknowledgement is
`flush(kDurable)`; `atomic_replace` writes a sibling temporary, makes it durable, renames it
over the destination, and then makes the directory entry durable (POSIX), or uses
`MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` (Windows). A reader therefore
sees either the complete old content or the complete new content.

**What is persisted, and what deliberately is not.** Publishers (durable descriptors), workloads,
contracts, flows, evidence records, classifications, revocations and supersessions are persisted.
**Sessions, liveness, freshness and the decision memo are not.** A restart therefore cannot
resurrect liveness or freshness, because the state that would have to be resurrected is never
read back. This is not a flag that could be forgotten; it is a property of the format.

---

## 6. Process, epoch and generation behaviour

```
coordinator start
  ├─ read durable state (if any)
  ├─ install the persisted policy
  ├─ restore records -- every restored publisher has NO live session,
  │                      every restored evidence record is STALE
  └─ advance epoch and boot incarnation
        ├─ drop every session
        └─ mark every record accepted in an earlier epoch stale, with a stated reason
```

* A **publisher restart** advances `PublisherBootId`. Evidence bound to the old boot becomes
  stale; the new incarnation starts its own evidence-generation high-water mark, so generations
  the previous incarnation used are not fenced against it.
* A **flow generation advance** stales evidence bound to the earlier incarnation *and* marks
  recorded classifications for that incarnation stale, so history does not report a superseded
  decision as the current answer.
* A **workload generation advance** retires the contracts bound to lower generations and stales
  the records that cited them.
* A **contract replacement** retires the previous active contract and stales derived evidence
  that cited it. An ACTIVE contract is immutable: changing it means retiring it and activating a
  new generation.
* A **policy change** advances `ClassifierPolicyGeneration` only when the content actually
  changes.

---

## 7. Supported, synthetic and unsupported proof surfaces

Every exercised capability in this repository is labelled. Nothing here claims validation on
hardware that does not exist.

| Dimension | Label | Detail |
| --- | --- | --- |
| C++20 runtime, codecs, decision engine | **REAL** | Built and tested with MSVC 19.44 (`/W4 /WX`) on Windows x64. |
| Loopback TCP transport | **REAL** | Real `WSAStartup`/`socket`/`bind`/`listen`/`connect`/`send`/`recv` over `127.0.0.1`. A killing test really kills a process and the peer really observes the closed socket. |
| Independent OS-process behaviour | **REAL** | Coordinators and publishers run as separate processes started from their own image and are terminated with an immediate kill. |
| Durable state across process death | **REAL** | Snapshots are written to the real filesystem with real durability calls. |
| Cryptographic hashing and integrity tags | **REAL** | SHA-256 implemented from FIPS 180-4 and verified against published vectors; CRC-32 verified against the standard vector. Neither is a signature. |
| Publisher/coordinator sessions | **PARTIAL** | Session binding is real; **peer authentication and transport encryption are not implemented**. There is no TLS and no message authentication code. See §10. |
| AI fabric topology (NVLink, InfiniBand, RoCE, RDMA, SmartNIC/DPU, programmable switches) | **SYNTHETIC** | Modelled as key/contract/evidence metadata. No such hardware was present or exercised. |
| Packet capture and payload inspection | **UNSUPPORTED** | Out of boundary. Flow metadata is supplied by publishers. |
| AddressSanitizer / UBSan coverage | **UNSUPPORTED on this host** | `cl /fsanitize=address` was probed: this Visual Studio 2022 17.14 installation ships the x86 ASan runtime only, and linking x64 fails with `LNK1104: cannot open file 'clang_rt.asan_static_runtime_thunk-x86_64.lib'`. The CMake probe is retained and reported honestly, and no sanitizer coverage is claimed. See `docs/proof-surfaces.md`. |
| ThreadSanitizer | **UNSUPPORTED on this toolchain** | Not provided by MSVC. |
| Multi-host deployment | **UNSUPPORTED** | The coordinator binds loopback only. It is not reachable from another host, by design. |

---

## 8. Build, test, install and consume

### Prerequisites

* CMake 3.24 or newer.
* A C++20 compiler: MSVC 19.36+ (Visual Studio 2022), GCC 11+, or Clang 14+.
* Ninja, or any CMake generator you prefer.

No third-party libraries are required at any point.

### Build

```
cmake -S . -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release --parallel
```

On Windows the scripts below establish the Visual Studio environment themselves, so they work from an
ordinary shell. They are thin wrappers over CMake and contain no build logic of their own.

| Script | What it does |
| --- | --- |
| `build_msvc.bat` | Configures and builds Debug into `build/msvc`. Pass CMake arguments through, for example `build_msvc.bat -DAIFC_BUILD_TESTS=ON`. |
| `build_one.bat <target>` | Builds a single target, for when one test surface is being worked on and an unrelated failure elsewhere should not stop the build. |
| `validate.bat` | Configures, builds and runs the whole registered suite. This is the command to run before believing a change. |
| `validate_release.bat` | Release configure, build, {`ctest`}, install to `build/prefix`, then build and run the independent downstream consumer against it. |
| `consumer_check.bat` | Only the consumer half of the above, against an already-installed `build/prefix`. |

Useful options: `AIFC_BUILD_TOOLS`, `AIFC_BUILD_EXAMPLES`, `AIFC_BUILD_TESTS`,
`AIFC_WARNINGS_AS_ERRORS` (default `ON`), `AIFC_ENABLE_SANITIZERS`, `AIFC_ENABLE_TSAN`,
`AIFC_INSTALL_TOOLS`, `AIFC_REQUIRE_ALL_SURFACES` (default `ON`; fails configuration if a proof
surface is missing).

### Test

```
cd build/release && ctest --output-on-failure
```

No test carries a timeout. A hanging test is a defect to diagnose, not a condition to survive.

### Install and consume

```
cmake --install build/release --prefix /some/clean/prefix
```

A downstream project finds the package with:

```cmake
find_package(AI_Flow_Classifier 1.0 REQUIRED)
target_link_libraries(my_target PRIVATE AIFlowClassifier::ai_flow_classifier)
```

`tests/downstream_consumer/` is a complete independent consumer that exercises the public API
end to end against an installed copy. It distinguishes a real consumer from an installed
`Config.cmake` that nobody has ever used.

### Examples

```
build/release/bin/example_declared_classification
build/release/bin/example_contradiction
build/release/bin/example_heuristic_adapter
build/release/bin/example_end_to_end
```

Each exits non-zero if the runtime's answer is not the expected one, so they double as smoke
tests. They print the explanation the runtime produced, not a summary written by the example.

### Command line tooling

```
ai-flow-classifier version
ai-flow-classifier banner
ai-flow-classifier classes
ai-flow-classifier vocabularies
ai-flow-classifier policy-check <policy.json>
ai-flow-classifier scenario <scenario.json> [--state PATH] [--json] [--explain] [--verbose]
```

Exit codes: `0` success, `3` a classification was produced and the class is `UNKNOWN`, `64` usage
error, `65` integrity or format failure, `69` the coordinator is not in a usable state, `70`
other runtime failure, `77` authority failure. The tool contains no classification logic: every
value it prints was decided by the library.

---

## 9. Privacy

Payload content is not required by any code path in this runtime, and none is accepted: the
protocol carries flow metadata, workload identity, contract scope and an operator-supplied
reason string, and nothing else. There is no capture module, no payload store, and no field in
which a peer could submit packet bytes. The reason string is refused outright if it contains a
control character, so it cannot inject line breaks into an explanation.

Two caveats stated plainly, because they are the honest limits of that claim:

* Flow metadata is still metadata. A five-tuple, a timing relationship and a workload name can
  be sensitive. The runtime does not encrypt them on the wire.
* The explanation text is intended for operators and includes publisher identities and reason
  strings verbatim. Treat an explanation as the sensitive artefact it is.

---

## 10. Limitations actually observed

These are real, and each one is a deliberate boundary rather than an unfinished item.

1. **No transport security.** Sessions are bound by the coordinator at admission and treated as
   authoritative thereafter, but there is no TLS, no peer certificate and no message
   authentication code. Deploying the coordinator on an untrusted network without an
   authenticating transport in front of it would be a genuine defect. The listener is bound to
   loopback, so this is currently a programmatic interface rather than a network service.
2. **CRC-32 is not a signature.** Frame integrity detects accidental corruption. It is not a
   security primitive, and the header comment says so.
3. **No sanitizer coverage on this host.** See §7. The probe is retained so that a host which
   does ship the runtime can enable it without a code change.
4. **No multi-host or fabric validation.** All topology, RDMA, collective and checkpoint
   dimensions are exercised as SYNTHETIC metadata.
5. **The coordinator is a single authority.** There is no consensus, no replication and no
   leader election. A coordinator restart is a new incarnation with an advanced epoch and
   deliberately no inherited authority.
6. **Evidence retention is bounded and lossy at the boundary.** The evidence store is a bounded
   ring. When it is full the oldest record is evicted, counted in `stats()`, and reported; a very
   old classification can therefore become unreproducible from the store alone. The snapshot
   holds what was committed.
7. **Explanations are bounded by the policy consideration cap.** Decisive citations are never
   dropped, but non-decisive ones past the cap are reported as `EXCLUDED_BY_LIMIT`.
8. **The heuristic surface is a declared lookup table, not a model.** A heuristic submission is
   admitted only when the policy permits heuristics, at least one adapter is enabled by name, and the
   submission cites a declared port hint that an enabled adapter names. There is no learned classifier
   in this repository, no adapter is enabled by default, and the runtime does not observe ports itself
   -- it has no capture path, so a hint is a permission and a label rather than a measurement. A
   heuristic record can never win on its own, and it never contradicts a declaration.

---

## 11. Public API sketch

```cpp
#include <ai_flow_classifier/ai_flow_classifier.hpp>

aifc::Classifier classifier(aifc::ClassifierOptions{aifc::ClassifierPolicy::initial(),
                                                     aifc::Logger{},
                                                     aifc::CoordinatorEpoch{1},
                                                     aifc::CoordinatorBootId{1}});

// A publisher is admitted at a stated authority ceiling. The peer does not choose it.
auto registration = classifier.register_publisher(
    aifc::make_publisher_id("trainer-node-7"),
    aifc::PublisherBootId{1},
    aifc::EvidenceSource::DECLARED_AUTHENTICATED,
    aifc::SessionId("session-7"),
    "training node");

// The envelope says who is speaking; the payload says what is claimed. They are different types
// on purpose, and only the envelope can carry authority.
aifc::SessionEnvelope envelope = aifc::make_session_envelope(registration.value(), 0);
aifc::EvidencePayload payload;
payload.flow_key = key;
payload.flow_generation = flow.generation;
payload.evidence_generation = aifc::EvidenceGeneration{1};
payload.semantic = aifc::SemanticClass::COLLECTIVE;
payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;  // clamped to the ceiling
auto outcome = classifier.submit_evidence(envelope, payload);

// Classification cites its evidence; Explanation renders it.
aifc::ClassificationQuery query;
query.flow_key = key;
query.explain = true;
auto classified = classifier.classify(query);
std::printf("%s %s\n",
            std::string(aifc::to_string(classified.value().classification.semantic)).c_str(),
            classified.value().classification.confidence.to_decimal().c_str());
std::printf("%s\n", classified.value().explanation.c_str());
```

The full surface is in `include/ai_flow_classifier/`; `ai_flow_classifier.hpp` includes all of it.

---

## 12. Repository layout

```
include/ai_flow_classifier/   public headers, grouped by layer
  foundation/                 identities, errors, bytes, hashing, clock, math, logging
  domain/                     semantic classes, evidence, flows, workloads, policy, classifications
  store/                      bounded, indexed registries
  classify/                   the decision engine and the classifier facade
  codec/                      canonical record encoders and decoders
  protocol/                   framing and message codecs
  net/                        TCP sockets and the framed channel
  state/                      the durable snapshot format
  runtime/                    coordinator and coordinator service
  io/                         durable file primitives
src/                          the implementation, mirroring the header layout
tools/                        the ai-flow-classifier CLI
examples/                     four runnable examples of real supported paths
tests/                        the nine proof surfaces plus the downstream consumer
docs/                         design, proof surfaces, and the release procedure
```

---

## 13. Further reading

* `docs/design.md` -- the authority model, the decision rule, and the concurrency and lifecycle
  audit.
* `docs/proof-surfaces.md` -- every test surface, what it proves, and its REAL/SYNTHETIC label.
* `docs/release.md` -- the exact closure procedure, including the install and fresh-clone
  validation.

---

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
