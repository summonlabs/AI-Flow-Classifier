# Design notes

This document records the design decisions that are not obvious from the headers, the
concurrency and lifecycle audit that was performed deliberately rather than discovered by tests,
and the reasoning behind the boundary.

---

## 1. The one idea

Almost every defect in a system like this reduces to one of two confusions:

* **observation is treated as authority** -- something was seen, therefore it is true now;
* **an identifier is treated as a generation** -- the name is the same, therefore it is the same
  thing.

Every type, rule and test in this repository exists to make those two confusions unrepresentable
rather than merely discouraged.

The concrete mechanism is that **authority is never stored inside the thing it authorises**.
An evidence record does not contain a flag saying it counts. The record contains its *claims*
(identity, boot, epoch, generation, source, tick window) and the coordinator holds the *current*
facts (which sessions are live, which epoch is running, which generation each publisher has
reached). A decision re-derives currentness from both, every time.

The consequence is the property the closure checks demand: a record whose publisher died cannot
be selected, not because something remembered to clear a flag, but because the coordinator's set
of live incarnations does not contain it.

---

## 2. Authority model

```
                 durable, coordinator-owned            volatile, per-incarnation
                 ─────────────────────────            ──────────────────────────
publisher        PublisherRecord                       PublisherRegistration
                   id, highest boot, highest             session, state, last seen,
                   generation, source ceiling            liveness
contract         WorkloadContract (ACTIVE)             —
flow             FlowRecord (id, key, generation)      —
evidence         EvidenceRecord (claims + deadline)    state (CURRENT or weaker)
decision         Classification (digest, policy)       memo entry (not authority)
```

Three rules follow, and they are the ones the tests hammer:

1. **A boot incarnation is part of the identity of a claim.** `is_live(publisher, boot)` is an
   exact pair match. A publisher that reconnects with a new boot is a different claimant, and
   the old claimant's records cannot be current because the registry only holds one live boot
   per publisher.
2. **An epoch is part of the identity of an acceptance.** `accepted_epoch` is checked against
   the running epoch at decision time. A coordinator restart advances the epoch, so every
   pre-restart record fails this check without any explicit invalidation pass being required for
   correctness (the pass exists to make the store's state match, not to make the rule true).
3. **A contract is authoritative on its own terms.** It is not an observation by a session; it is
   a declaration the coordinator owns and re-validates (state `ACTIVE`, workload generation
   equal to the workload's current generation, scope covering the key). It is therefore exempt
   from the session-liveness rule, which is why a restart does not discard a still-current
   contract while it does discard every session-bound observation.

### Why a contract is not "just another publisher claim"

Because it is versioned, immutable once active, owned (ownership is not transferable), scoped,
and re-validated at every decision. A publisher cannot mutate an active contract; it must retire
it and activate a new generation, which is a visible act that stales the old derived evidence.

---

## 3. The decision rule as an algorithm

```
decide(input):
  candidates := input.evidence
              + synthesise_contract_evidence(active contracts that are ACTIVE,
                                             generation-current, and covering the key)

  for each candidate:
     if it duplicates another identity          -> REJECTED
     if bound to a different flow generation    -> STALE
     if its accepted epoch is not the current   -> STALE
     if its source requires a live session and
        that incarnation is not live            -> STALE
     if its source is heuristic and heuristics
        are disabled by policy                  -> REJECTED
     if the tick is past its deadline           -> STALE
     if it is heuristic and current             -> SUBORDINATE
     otherwise                                  -> SELECTED (eligible)

  winner := the eligible, non-UNKNOWN candidate that is maximal under the total order
            (source rank, workload generation, acceptance sequence, evidence id)

  if the generation is revoked                   -> REVOKED / UNKNOWN / 0.0000
  if there is no winner                          -> STALE if anything was stale,
                                                    otherwise INSUFFICIENT; class UNKNOWN

  contradictions := current authoritative candidates whose class differs from the winner
  confidence     := min(winner source confidence, winner record confidence)
                    then reduced by the configured penalty if contradictions exist
  state          := CONTRADICTED if contradictions, CORROBORATED if any agreement,
                    otherwise CURRENT
  if confidence < minimum_publishable:           -> INSUFFICIENT / UNKNOWN, winner cited
                                                    as BELOW_THRESHOLD
  apply the consideration cap, keeping decisive citations
  assert: a non-UNKNOWN class is justified by a cited current record of that class
  digest := content-only digest
```

### Why the order is total

Rules 4 and 5 look like tie-breakers, and in a sense they are. Their purpose is not fairness; it
is that "which record won" must have exactly one answer. Without a total order, two processes fed
the same evidence could pick different winners when their hash iteration orders differed, and the
determinism property would be a coincidence of the standard library implementation rather than a
property of this code.

### Why a heuristic disagreement is not a contradiction

A contradiction is two *authoritative* statements that disagree. A guess is not an authoritative
statement. Treating a guess as a contradiction would let any observer with a port-number rule
manufacture a contested state for a flow it does not own, which would be a denial-of-service
primitive disguised as diligence.

---

## 4. Bounds and what happens at them

Every collection in this runtime is bounded, and the behaviour at the bound is chosen
deliberately:

| Structure | At the bound |
| --- | --- |
| Flow registry | Refuses the insert with `CAPACITY_EXCEEDED`. Never evicts a live flow: silently dropping live state would be a correctness bug, not a resource policy. |
| Publisher registry | Refuses the insert. |
| Workload/contract registry | Refuses the insert. Pending contracts have their own, smaller bound. |
| Evidence store | Evicts the oldest accepted record, counts it in `stats()`, and reports it. A bounded store that silently discards is worse than one that says it did. |
| Per-flow evidence index | A ring. The record stays in the store until the global ring reaches it; it is simply no longer reachable from its flow, which is what bounds classification cost. |
| Decision history per flow | A ring; evictions counted. |
| Decision memo | Insertion-ordered eviction. The memo has no authority, so an approximate policy costs only recomputation. |
| Contradiction, supersession, revocation records | Bounded rings, oldest first. |
| Frame payload, blob, string, collection count, batch size | Refused before allocation, with the declared length checked against the remaining bytes first. |
| Socket receive buffer | Exactly one maximum frame plus a header. A peer that never completes a frame cannot make the reader allocate. |

**No externally supplied size reaches an allocation unchecked.** A declared length is compared
against the effective limit and then against the bytes that actually remain, in that order,
before anything is reserved. This is the single most repeated pattern in the codec layer.

---

## 5. Locking and call paths

### The discipline

1. Each mutable component owns one `std::mutex`. There is no lock hierarchy because there is no
   nested locking: no function acquires a second mutex while holding the first.
2. **No callback, sink, thread operation or *state* access happens while a lock is held, and no
   component hands out a reference to its locked state.** The logger copies its sink (the `Logger`
   value is copied, not shared), the coordinator handler *returns* a response value rather than
   writing to a socket, and the service collects the channels to close under the lock and closes
   them with the lock released.
3. Read-modify-write on shared state happens under one acquisition, never "read under a lock,
   release, then re-acquire to write".
4. **A lock is not held across a blocking socket write.** `Channel::send` serialises frame writes on
   its own send mutex and does hold that mutex across `Socket::send`, because a channel has exactly
   one writer and interleaving two frames on one connection would corrupt the stream. That mutex is
   private to the channel, is never taken while any other lock is held, and is never held while
   calling back into the runtime. The blanket phrasing "no socket write happens under a lock" would
   be false; this is the precise rule.

### The persistence path, and a defect it caused

An earlier version of this file claimed the audit found no violations. It was wrong, and the way it
was wrong is worth recording.

`Coordinator::snapshot()` assembled its image by calling five store accessors on the classifier:
`publisher_registry()`, `workload_registry()`, `flow_registry()`, `evidence_store()` and
`classification_index()`. Each accessor returned a reference to state guarded by the classifier's
mutex **without taking it**, and the snapshot then walked those containers. Under
`persist_on_mutation` with more than one handler thread, that walk ran concurrently with
insertions, and the result was reproducible heap corruption rather than a wrong answer. It was found
by an adversarial review with an A/B reproduction: the same binary completed 800 publications with
`persist_on_mutation=false` and died with `STATUS_HEAP_CORRUPTION` with it enabled.

The fix is structural rather than local. The accessors are gone. In their place:

* `Classifier::durable_state()` takes the classifier mutex once and returns a **value** containing
  every durable collection;
* `Classifier::publisher_registrations()` and `Classifier::recorded_decision()` are bounded queries
  that lock and copy what they return;
* `Classifier::policy()` returns the policy **by value**, because handing out a reference to state
  that a concurrent `set_policy` can replace is a use-after-unlock regardless of how briefly the
  reference is held.

The general rule this produced, which is now the one the code follows: **a component never hands out
a reference or pointer to state that its own mutex protects.** A caller cannot take a lock it cannot
name, so an accessor that returns a reference is an invitation to a data race that no amount of care
at the call site can avoid.

### Audit results, path by path

| Path | Re-entrancy risk | Finding |
| --- | --- | --- |
| `Classifier::classify` | Calls `engine_.decide` (pure, no locks, no I/O) and store methods on the same lock it already holds. | Safe: the engine never touches a mutex, so a read lock is never followed by an attempted write acquisition. |
| `Classifier::classify_batch` | Deliberately re-enters the classification logic directly instead of calling the public `classify()`. | This is the one place where the same lock is reused, and it is visible as such. Calling `classify()` would deadlock on a non-recursive mutex; releasing the lock between keys would make the batch non-atomic with respect to concurrent mutation. |
| `Classifier::explain` | Calls `classify()` (which takes the lock and releases it) and then takes the lock again for the explanation inputs. | Safe because the two acquisitions do not overlap. It is *not* atomic with respect to concurrent mutation, and it does not need to be: the explanation is rendered from the classification that was already returned. |
| `CoordinatorService::accept_loop` | Pushes to the queue and notifies under the lock. | No callback and no socket operation under the lock beyond closing a rejected socket, which is a local operation on a socket nobody else holds. |
| `CoordinatorService::worker_loop` | Waits, pops under the lock, releases, then serves. | The wait predicate covers the stop flag, so a stop with an empty queue wakes every worker. |
| `CoordinatorService::stop` | Closes the listener, drains, closes connections, then joins. | **No join happens while the mutex is held.** Joining while holding a lock the workers need is the classic shutdown deadlock; the joins are outside every critical section. |
| `Coordinator::handle` | Dispatches to handlers that call the classifier and return a `CoordinatorResponse` value. | No socket is written from inside a handler, so a slow or blocked peer cannot hold a coordinator lock. |
| `Channel::send` | Serialises frame writes on a send mutex. | The sequence number advances only after a successful write, so a failed send does not consume a sequence number. No other lock is taken inside. |
| `Atomic_replace` | Writes, flushes durably, closes, then renames. | The file handle is closed before the rename, which is required on Windows. No lock is involved. |
| `Logger` | Copies the sink into the `Logger` value. | Invoking a sink cannot deadlock against a logger lock because there is no logger lock. |

### Shutdown

`CoordinatorService::stop` follows a fixed order: set the stopping flag so no new work is
admitted; close the listener so a pending accept returns immediately; wait for the queue to drain,
bounded; clear the queue; close every active connection, which unblocks each reader rather than
making it wait out its receive window; notify; join every thread; release the socket subsystem.

The drain is bounded by `drain_timeout` on purpose. A peer that connects and then sends nothing
must not be able to hold shutdown open, and the lifecycle test asserts exactly that.

### Cancellation and stale completion

* A channel's receive window is a polling period, not a request timeout: it exists so a blocked
  reader notices the stop flag. It is not a promise to a peer.
* A frame is either fully decoded and integrity-checked, or it is not acted upon. There is no
  partial application of a frame anywhere.
* The one documented ambiguous case is a publisher that has an acknowledgement and then loses the
  coordinator. Its acknowledgement is still true of the moment it was issued; what it cannot do is
  keep the authority current, because a restart advances the epoch. The multiprocess surface tests
  exactly this and asserts that the publisher must re-establish authority by handshaking again
  rather than by caching numbers.

---

## 6. Protocol decisions

* **Fixed framing with explicit lengths and a version.** The magic is checked before anything
  else, so a stream that is not this protocol fails immediately rather than being
  reinterpreted.
* **Canonical decoding.** A record that decodes with bytes left over is `TRAILING_GARBAGE`, not a
  success. Trailing bytes are how a peer smuggles a second interpretation past a first one.
* **Unknown numeric codes decode to the weakest value, never the strongest.** An unknown source
  becomes `UNKNOWN` rank 0, an unknown transport becomes `UNKNOWN`, an unknown evidence state
  becomes `REJECTED`. This is the decode-side half of "a malformed label cannot produce a
  privileged class".
* **A malformed label is a failure, not `UNKNOWN`.** `parse_semantic_class` refuses
  `"collective"`, `"COLLECTIVE "` and `"KV STATE TRANSFER"`. `UNKNOWN` is a legitimate
  classification, and it must not be reachable by misspelling -- otherwise a peer could push a
  flow to `UNKNOWN` by sending garbage, and `UNKNOWN` would stop meaning "no class was
  established".
* **Identity binding from the envelope.** `REGISTER_PUBLISHER` is the only message that names a
  publisher, and after it the session remembers. `PUBLISH_EVIDENCE` has no publisher, no session,
  no epoch and no source ceiling field: a peer has nowhere to put the claim.
* **The coordinator mints evidence identities.** A peer cannot choose its own evidence id, which
  removes a class of collision and replay games.
* **Deterministic error codes.** Every refusal crosses the wire as an `ErrorCode` plus a stable
  message, never a boolean.

---

## 7. Persistence decisions

* **Nothing is applied until everything has decoded.** The body is decoded into a staging
  structure; on any error the caller's state is untouched. The corruption tests assert this by
  checking that the target classifier still holds its original value.
* **A restored record is never current.** `EvidenceStore::restore_record` rewrites `CURRENT` to
  `STALE` with a reason. `PublisherRegistry::restore_records` creates registrations with no
  session. This is enforced at the single point where a record enters memory from disk, not
  scattered across callers.
* **The memo is not restored.** A memo entry is only valid if it was produced from the same
  evidence set in this process, and the evidence set is not part of the snapshot, so restoring
  the memo would be restoring a guess about inputs that are known to have changed.
* **Torn tails are rejected, not repaired.** A file that does not verify is an error the operator
  sees. Guessing at a partial state would be worse than refusing to start: it would produce a
  runtime that confidently reports a past that never happened.
* **Orphan temporaries are removed at startup.** `atomic_replace` only ever creates a temporary
  for a file it is about to replace, so a leftover `.tmp-` file is never committed state.

---

## 8. What was rejected, and why

* **A liveness flag inside the evidence record.** Rejected: it is exactly the "observation is
  authority" confusion. A flag can be stale, and clearing it requires remembering to clear it.
* **Making heuristic evidence a contradiction when it disagrees.** Rejected as a denial-of-service
  primitive (see §3).
* **Averaging disagreeing authoritative declarations.** Rejected: a synthesised class is a class
  nobody declared, and it would hide the disagreement that an operator most needs to see.
* **Clamping an out-of-range confidence from the wire.** Rejected: clamping would let a peer ask
  for maximum confidence by sending an absurd number. It is an error instead.
* **Treating an unknown label as `UNKNOWN`.** Rejected (see §6).
* **Evicting live flows at the registry bound.** Rejected (see §4).
* **Carrying payload bytes "for future use".** Rejected: an unused field is an undeclared
  capability, and the privacy claim in the README would stop being true.
* **Restoring liveness from the snapshot.** Rejected: the whole point of the restart path is that
  persistence is not currentness.
