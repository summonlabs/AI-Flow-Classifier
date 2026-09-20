# Release procedure

This is the exact procedure used to close version 1.0.0. It is written down so that the next
release is a repetition rather than a reconstruction.

Nothing in this procedure uses a timeout. Every test and validation command runs plainly and is
allowed to finish.

---

## 0. Preconditions

* A clean working tree, or a tree whose only changes are the ones being released.
* MSVC 2022 (or GCC 11+/Clang 14+) and CMake 3.24+ on `PATH`.
* The remote configured (`git remote -v` shows the intended `origin`).

---

## 1. Release configuration

```
build_msvc.bat -DAIFC_BUILD_TESTS=ON -DAIFC_BUILD_EXAMPLES=ON -DAIFC_BUILD_TOOLS=ON
```

This configures Debug with `AIFC_WARNINGS_AS_ERRORS=ON` and `AIFC_REQUIRE_ALL_SURFACES=ON`. The
last one is a release gate: configuration **fails** if any of the documented proof surfaces is
missing, so a release cannot be cut with a hole in the suite that nobody noticed.

## 2. Debug validation

```
cd build/msvc
ctest --output-on-failure
```

Every test is expected to pass. A failure is a defect: fix the root cause and re-run the whole
suite, not only the failing case.

Then run the examples, which exit non-zero if the runtime's answer is not the expected one:

```
bin/example_declared_classification
bin/example_contradiction
bin/example_heuristic_adapter
bin/example_end_to_end
```

## 3. Release validation

```
cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release ^
      -DAIFC_WARNINGS_AS_ERRORS=ON -DAIFC_BUILD_TESTS=ON
cmake --build build/release --parallel
cd build/release && ctest --output-on-failure
```

Zero warnings in both configurations. The Release configuration matters separately from Debug
because optimisation changes inlining and therefore what the compiler can warn about.

## 4. Sanitizers

```
cmake -S . -B build/sanitizers -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
      -DAIFC_ENABLE_SANITIZERS=ON -DAIFC_BUILD_TESTS=ON
```

The probe decides. If the toolchain cannot link the sanitizer runtime, the configure output says
**UNSUPPORTED** and no sanitizer flags are added, rather than failing the build or, worse,
silently adding flags that do not take effect. On a host with a complete ASan runtime this step
adds real coverage; on a host without one, the correct outcome is an honest UNSUPPORTED and no
claim of coverage.

## 5. Install to a clean prefix

```
cmake --install build/release --prefix "<clean absolute prefix>"
```

`install_manifest.txt` is generated in the build directory and must be inspected: the tree that
lands in the prefix is part of the artefact, and files that were not meant to be installed are a
defect.

## 6. Downstream consumer

```
cmake -S tests/downstream_consumer -B build/consumer -G Ninja ^
      -DCMAKE_PREFIX_PATH="<clean absolute prefix>"
cmake --build build/consumer --parallel
build/consumer/consumer
```

The consumer is a separate CMake project that has never seen this source tree. It must configure
with `find_package(AI_Flow_Classifier 1.0 REQUIRED)`, link
`AIFlowClassifier::ai_flow_classifier`, and run to success. A package that configures but whose
consumer cannot link or run is not an installed library.

## 7. Surface and hygiene gate

```
cmake -DSOURCE_DIR="<repo>" -P tools/verify_surfaces.cmake
```

This checks two things at once: that every documented proof surface exists, and that no committed
source file contains a machine-specific absolute path.

It also checks that `README.md` ends exactly with the required License section and that nothing
follows it.

## 8. Manual tree inspection

Before committing:

* `git status --porcelain` — every entry is intended.
* `git diff --cached --stat` — the change is the change you think it is.
* Read the top-level listing. There must be no build directory, no log, no dump, no temporary
  output, no stale fixture and no abandoned script checked in. `.gitignore` covers the build
  trees, but `.gitignore` is a convenience, not an inspection.
* Grep the staged diff for secrets and for machine-specific paths. The surface gate does this for
  sources; do it by eye for everything else.
* Confirm no `Co-authored-by` trailer and no AI attribution exists in the history being pushed.

## 9. Commit, tag, push

```
git add -A
git commit -m "<a message that says what changed and why>"
git tag -a v1.0.0 -m "AI Flow Classifier 1.0.0"
git push origin main
git push origin v1.0.0
```

Use the repository's configured Git identity. Do not alter repository visibility.

## 10. Verify the remote

```
git ls-remote origin refs/heads/main refs/tags/v1.0.0
```

Both must resolve, and the tag must resolve to the same commit as `main` — an annotated tag
points at a tag object, so resolve it with `git rev-list -n 1 v1.0.0` on a fresh clone rather
than comparing the raw hashes.

## 11. Fresh clone validation

```
git clone --branch v1.0.0 <remote> <clean directory>
```

In the clone, repeat steps 1, 2, 3, 5, 6 and 7. This is the step that catches a file which was
only ever present locally, a build script that depended on an untracked helper, and a package
configuration that referenced something outside the repository.

## 12. Final report

Only after step 11 succeeds, write the report: what was built, the final architecture, the
invariants and authority rules, the defects found and fixed during hardening, test results, the
property/race/adversarial results, the real multiprocess and transport results, the
hardware/network labels, the persistence and restart results, the install and downstream consumer
result, the benchmark and scale results where they are meaningful, the fresh-clone result, the
final commit and tag verification, and the genuine remaining limitations.

Report verified facts only. Where something was not verified, say so.
