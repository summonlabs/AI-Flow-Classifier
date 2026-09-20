# Changelog

All notable changes to this project are recorded here. The format follows the spirit of
Keep a Changelog, and the version numbers are the product version, which is also the release tag.

## [1.0.0] - 2026-01-01

Initial release.

### Added

* **Semantic classification** of AI-related flows with an explicit evidence state, a fixed-point
  confidence, and an explanation that cites every record considered together with the reason each
  one won, lost, was superseded or was excluded.
* **Strongly typed identities and generations**: `FlowId`, `FlowGeneration`, `PublisherId`,
  `PublisherBootId`, `WorkloadId`, `WorkloadGeneration`, `SemanticClass`, `EvidenceId`,
  `EvidenceGeneration`, `CoordinatorEpoch`, `CoordinatorBootId`, `ClassifierPolicyGeneration`.
* **Evidence quality model** with six sources whose ranks are constants of the policy, and a
  session authority ceiling that clamps a peer's claim down and reports the reduction.
* **A deterministic decision engine** as a pure function: total precedence order, contradiction
  detection with a configured and reported penalty, a publishable threshold that keeps `UNKNOWN`
  honest, and a final invariant that refuses to return a class it cannot cite.
* **Registries and indexes**: flow keys and incarnations indexed in both directions, publisher
  registry with a durable/volatile split, workload and contract registry with generation fencing,
  a bounded evidence store with a per-flow index, and classification history with revocation and
  supersession records.
* **Canonical, hostile-input-resistant codecs** for every record and message, with checked
  lengths, bounded allocations, trailing-garbage rejection, and unknown codes decoding to the
  weakest value.
* **A framed, versioned, integrity-checked protocol** with identity binding from the authenticated
  session envelope rather than from peer-supplied provenance fields.
* **Real loopback TCP transport** with a coordinator service that shuts down deterministically and
  never joins a thread while holding state the workers need.
* **Versioned, integrity-checked durable state** with atomic replacement, durable commit before
  acknowledgement, and a restore path that deliberately does not restore liveness or freshness.
* **CLI tooling** that reports what the library decided and contains no classification logic of
  its own.
* **Four examples** that execute real supported paths and fail loudly if the runtime's answer is
  not the expected one.
* **Nine test surfaces** (unit, integration, property, concurrency, adversarial, persistence,
  protocol, multiprocess, scale) plus an independent downstream `find_package` consumer.
* **Install and export rules** so the core library is reusable by a project that has never seen
  this source tree.

### Notes

* No third-party dependencies.
* No telemetry transmission of any kind.
* Transport security (TLS, peer authentication, message authentication codes) is not implemented;
  see the limitations section of the README.
* Sanitizer coverage is UNSUPPORTED on the toolchain used for this release, and is reported as
  such rather than claimed.
