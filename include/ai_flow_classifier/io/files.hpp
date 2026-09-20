// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Durable file primitives.
//
// The persistence layer is built on three guarantees from this file:
//
//   * read_all() never allocates more than the caller's bound, whatever the file
//     size claims to be;
//   * flush(kDurable) is the only thing that constitutes a durability
//     acknowledgement, and it is explicit;
//   * atomic_replace() writes to a sibling temporary, makes the temporary durable,
//     moves it over the destination, and then makes the directory entry durable.
//     A caller that gets success from atomic_replace has the guarantee that a
//     subsequent reader sees either the complete old content or the complete new
//     content, never a mixture and never a torn tail.

#ifndef AI_FLOW_CLASSIFIER_IO_FILES_HPP
#define AI_FLOW_CLASSIFIER_IO_FILES_HPP

#include <ostream>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "ai_flow_classifier/foundation/bytes.hpp"
#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc {

enum class OpenMode {
  kReadOnly,
  kCreateTruncate,
};

enum class FlushMode {
  // Push the application buffer to the operating system.  Not a durability
  // acknowledgement.
  kBuffers,
  // Push to durable storage.  Only after this returns OK may a caller treat the
  // bytes as committed.
  kDurable,
};

class File {
 public:
  File() = default;
  ~File();
  File(const File&) = delete;
  File& operator=(const File&) = delete;
  File(File&& other) noexcept;
  File& operator=(File&& other) noexcept;

  static Result<File> open(std::string_view path, OpenMode mode);

  [[nodiscard]] bool is_open() const noexcept { return handle_ != kInvalidHandle; }
  [[nodiscard]] const std::string& path() const noexcept { return path_; }

  Result<std::uint64_t> size() const;
  Status seek(std::uint64_t offset);
  Result<std::size_t> read_at(std::uint64_t offset, std::uint8_t* out, std::size_t length);
  Status write_all(const std::uint8_t* data, std::size_t length);
  Status flush(FlushMode mode);
  Status truncate(std::uint64_t size);
  void close() noexcept;

 private:
#if defined(AIFC_PLATFORM_WINDOWS)
  using NativeHandle = void*;
  static constexpr NativeHandle kInvalidHandle = nullptr;
#else
  using NativeHandle = int;
  static constexpr NativeHandle kInvalidHandle = -1;
#endif

  NativeHandle handle_ = kInvalidHandle;
  std::string path_;
};

// Reads an entire file.  Fails with CAPACITY_EXCEEDED when the file is larger than
// max_bytes, before allocating.  An absent file is NOT_FOUND rather than an empty
// read.
[[nodiscard]] Result<ByteBuffer> read_all(std::string_view path, std::uint64_t max_bytes);

[[nodiscard]] bool path_exists(std::string_view path);
[[nodiscard]] Status remove_file(std::string_view path);
[[nodiscard]] Status create_directories(std::string_view path);

[[nodiscard]] std::string path_with_suffix(std::string_view path, std::string_view suffix);
[[nodiscard]] std::string path_directory(std::string_view path);

// Atomically replaces the contents of path with data.
[[nodiscard]] Status atomic_replace(std::string_view path, const std::uint8_t* data,
                                    std::size_t length);

// Lists regular files directly inside a directory, sorted by name.  Used to find
// snapshot siblings; never recursive.
[[nodiscard]] Result<std::vector<std::string>> list_directory(std::string_view path);

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_IO_FILES_HPP
