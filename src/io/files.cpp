// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/io/files.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/hash.hpp"

#if defined(AIFC_PLATFORM_WINDOWS)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace aifc {
namespace {

[[nodiscard]] Status io_failure(std::string_view what, std::string_view path, std::string detail) {
  return Status::failure(ErrorCode::IO_ERROR, std::string(what) + " failed for " +
                                                  std::string(path) + ": " + std::move(detail));
}

#if defined(AIFC_PLATFORM_WINDOWS)

[[nodiscard]] std::wstring to_wide(std::string_view utf8) {
  if (utf8.empty()) return std::wstring();
  const int needed =
      ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
  if (needed <= 0) return std::wstring();
  std::wstring wide(static_cast<std::size_t>(needed), L'\0');
  const int written = ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
                                            static_cast<int>(utf8.size()), wide.data(), needed);
  if (written != needed) return std::wstring();
  return wide;
}

[[nodiscard]] std::string last_error_text(unsigned long code) {
  return "windows error " + std::to_string(code);
}

#endif

}  // namespace

// --- File ------------------------------------------------------------------

File::~File() { close(); }

File::File(File&& other) noexcept : handle_(other.handle_), path_(std::move(other.path_)) {
  other.handle_ = kInvalidHandle;
}

File& File::operator=(File&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    path_ = std::move(other.path_);
    other.handle_ = kInvalidHandle;
  }
  return *this;
}

void File::close() noexcept {
  if (handle_ == kInvalidHandle) return;
#if defined(AIFC_PLATFORM_WINDOWS)
  ::CloseHandle(static_cast<HANDLE>(handle_));
#else
  ::close(handle_);
#endif
  handle_ = kInvalidHandle;
}

Result<File> File::open(std::string_view path, OpenMode mode) {
  File file;
  file.path_ = std::string(path);
#if defined(AIFC_PLATFORM_WINDOWS)
  const std::wstring wide = to_wide(path);
  if (wide.empty()) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT, "file path is empty or not valid UTF-8");
  }
  const DWORD access = (mode == OpenMode::kReadOnly) ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
  const DWORD disposition = (mode == OpenMode::kReadOnly) ? OPEN_EXISTING : CREATE_ALWAYS;
  const HANDLE handle = ::CreateFileW(wide.c_str(), access, FILE_SHARE_READ, nullptr, disposition,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const unsigned long error = ::GetLastError();
    if (mode == OpenMode::kReadOnly &&
        (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)) {
      return Status::failure(ErrorCode::NOT_FOUND, "no such file: " + std::string(path));
    }
    return io_failure("CreateFile", path, last_error_text(error));
  }
  file.handle_ = handle;
  return file;
#else
  const int flags = (mode == OpenMode::kReadOnly) ? O_RDONLY : (O_RDWR | O_CREAT | O_TRUNC);
  const int descriptor = ::open(std::string(path).c_str(), flags, 0644);
  if (descriptor < 0) {
    if (mode == OpenMode::kReadOnly && errno == ENOENT) {
      return Status::failure(ErrorCode::NOT_FOUND, "no such file: " + std::string(path));
    }
    return io_failure("open", path, std::string(std::strerror(errno)));
  }
  file.handle_ = descriptor;
  return file;
#endif
}

Result<std::uint64_t> File::size() const {
  if (handle_ == kInvalidHandle) {
    return Status::failure(ErrorCode::NOT_RUNNING, "file is not open");
  }
#if defined(AIFC_PLATFORM_WINDOWS)
  LARGE_INTEGER size{};
  if (::GetFileSizeEx(static_cast<HANDLE>(handle_), &size) == 0) {
    return io_failure("GetFileSizeEx", path_, last_error_text(::GetLastError()));
  }
  if (size.QuadPart < 0) {
    return Status::failure(ErrorCode::IO_ERROR, "negative file size reported for " + path_);
  }
  return static_cast<std::uint64_t>(size.QuadPart);
#else
  struct stat info {};
  if (::fstat(handle_, &info) != 0) {
    return io_failure("fstat", path_, std::string(std::strerror(errno)));
  }
  if (info.st_size < 0) {
    return Status::failure(ErrorCode::IO_ERROR, "negative file size reported for " + path_);
  }
  return static_cast<std::uint64_t>(info.st_size);
#endif
}

Status File::seek(std::uint64_t offset) {
  if (handle_ == kInvalidHandle) {
    return Status::failure(ErrorCode::NOT_RUNNING, "file is not open");
  }
#if defined(AIFC_PLATFORM_WINDOWS)
  LARGE_INTEGER distance{};
  distance.QuadPart = static_cast<LONGLONG>(offset);
  if (::SetFilePointerEx(static_cast<HANDLE>(handle_), distance, nullptr, FILE_BEGIN) == 0) {
    return io_failure("SetFilePointerEx", path_, last_error_text(::GetLastError()));
  }
  return Status::success();
#else
  if (::lseek(handle_, static_cast<off_t>(offset), SEEK_SET) < 0) {
    return io_failure("lseek", path_, std::string(std::strerror(errno)));
  }
  return Status::success();
#endif
}

Result<std::size_t> File::read_at(std::uint64_t offset, std::uint8_t* out, std::size_t length) {
  if (handle_ == kInvalidHandle) {
    return Status::failure(ErrorCode::NOT_RUNNING, "file is not open");
  }
  if (length == 0) return std::size_t{0};
#if defined(AIFC_PLATFORM_WINDOWS)
  OVERLAPPED overlapped{};
  overlapped.Offset = static_cast<DWORD>(offset & 0xFFFFFFFFULL);
  overlapped.OffsetHigh = static_cast<DWORD>((offset >> 32) & 0xFFFFFFFFULL);
  DWORD read = 0;
  if (::ReadFile(static_cast<HANDLE>(handle_), out, static_cast<DWORD>(length), &read, &overlapped) ==
      0) {
    const unsigned long error = ::GetLastError();
    if (error == ERROR_HANDLE_EOF) {
      return std::size_t{0};
    }
    return io_failure("ReadFile", path_, last_error_text(error));
  }
  return static_cast<std::size_t>(read);
#else
  const ssize_t read = ::pread(handle_, out, length, static_cast<off_t>(offset));
  if (read < 0) {
    return io_failure("pread", path_, std::string(std::strerror(errno)));
  }
  return static_cast<std::size_t>(read);
#endif
}

Status File::write_all(const std::uint8_t* data, std::size_t length) {
  if (handle_ == kInvalidHandle) {
    return Status::failure(ErrorCode::NOT_RUNNING, "file is not open");
  }
  std::size_t written = 0;
#if defined(AIFC_PLATFORM_WINDOWS)
  while (written < length) {
    const std::size_t remaining = length - written;
    const std::size_t chunk = remaining > (1U << 20) ? (1U << 20) : remaining;
    DWORD chunk_written = 0;
    if (::WriteFile(static_cast<HANDLE>(handle_), data + written, static_cast<DWORD>(chunk),
                    &chunk_written, nullptr) == 0) {
      return io_failure("WriteFile", path_, last_error_text(::GetLastError()));
    }
    if (chunk_written == 0) {
      return io_failure("WriteFile", path_, "zero-length write");
    }
    written += static_cast<std::size_t>(chunk_written);
  }
#else
  while (written < length) {
    const ssize_t chunk = ::write(handle_, data + written, length - written);
    if (chunk < 0) {
      if (errno == EINTR) continue;
      return io_failure("write", path_, std::string(std::strerror(errno)));
    }
    if (chunk == 0) {
      return io_failure("write", path_, "zero-length write");
    }
    written += static_cast<std::size_t>(chunk);
  }
#endif
  return Status::success();
}

Status File::flush(FlushMode mode) {
  if (handle_ == kInvalidHandle) {
    return Status::failure(ErrorCode::NOT_RUNNING, "file is not open");
  }
#if defined(AIFC_PLATFORM_WINDOWS)
  (void)mode;  // FlushFileBuffers is the durable primitive on this platform
  if (::FlushFileBuffers(static_cast<HANDLE>(handle_)) == 0) {
    return Status::failure(ErrorCode::DURABILITY_FAILURE,
                           "FlushFileBuffers failed for " + path_ + ": " +
                               last_error_text(::GetLastError()));
  }
  return Status::success();
#else
  if (mode == FlushMode::kBuffers) {
    return Status::success();
  }
  if (::fsync(handle_) != 0) {
    return Status::failure(ErrorCode::DURABILITY_FAILURE,
                           "fsync failed for " + path_ + ": " + std::string(std::strerror(errno)));
  }
  return Status::success();
#endif
}

Status File::truncate(std::uint64_t size) {
  if (handle_ == kInvalidHandle) {
    return Status::failure(ErrorCode::NOT_RUNNING, "file is not open");
  }
#if defined(AIFC_PLATFORM_WINDOWS)
  LARGE_INTEGER distance{};
  distance.QuadPart = static_cast<LONGLONG>(size);
  if (::SetFilePointerEx(static_cast<HANDLE>(handle_), distance, nullptr, FILE_BEGIN) == 0) {
    return io_failure("SetFilePointerEx", path_, last_error_text(::GetLastError()));
  }
  if (::SetEndOfFile(static_cast<HANDLE>(handle_)) == 0) {
    return io_failure("SetEndOfFile", path_, last_error_text(::GetLastError()));
  }
  return Status::success();
#else
  if (::ftruncate(handle_, static_cast<off_t>(size)) != 0) {
    return io_failure("ftruncate", path_, std::string(std::strerror(errno)));
  }
  return Status::success();
#endif
}

// --- Free functions --------------------------------------------------------

Result<ByteBuffer> read_all(std::string_view path, std::uint64_t max_bytes) {
  Result<File> file = File::open(path, OpenMode::kReadOnly);
  if (!file) return file.status();
  Result<std::uint64_t> file_size = file.value().size();
  if (!file_size) return file_size.status();
  if (file_size.value() > max_bytes) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "file " + std::string(path) + " is " +
                               std::to_string(file_size.value()) +
                               " bytes, exceeding the bound of " + std::to_string(max_bytes));
  }
  ByteBuffer out(static_cast<std::size_t>(file_size.value()));
  std::size_t filled = 0;
  while (filled < out.size()) {
    Result<std::size_t> read =
        file.value().read_at(filled, out.data() + filled, out.size() - filled);
    if (!read) return read.status();
    if (read.value() == 0) {
      // The file shrank between the size query and the read.  Reporting a
      // truncated read is more honest than returning a partially filled buffer.
      return Status::failure(ErrorCode::TRUNCATED_STATE,
                             "file " + std::string(path) + " shrank while being read");
    }
    filled += read.value();
  }
  return out;
}

bool path_exists(std::string_view path) {
#if defined(AIFC_PLATFORM_WINDOWS)
  const std::wstring wide = to_wide(path);
  if (wide.empty()) return false;
  const DWORD attributes = ::GetFileAttributesW(wide.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES;
#else
  struct stat info {};
  return ::stat(std::string(path).c_str(), &info) == 0;
#endif
}

Status remove_file(std::string_view path) {
#if defined(AIFC_PLATFORM_WINDOWS)
  const std::wstring wide = to_wide(path);
  if (wide.empty()) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT, "file path is empty or not valid UTF-8");
  }
  if (::DeleteFileW(wide.c_str()) == 0) {
    const unsigned long error = ::GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      return Status::failure(ErrorCode::NOT_FOUND, "no such file: " + std::string(path));
    }
    return io_failure("DeleteFile", path, last_error_text(error));
  }
  return Status::success();
#else
  if (::unlink(std::string(path).c_str()) != 0) {
    if (errno == ENOENT) {
      return Status::failure(ErrorCode::NOT_FOUND, "no such file: " + std::string(path));
    }
    return io_failure("unlink", path, std::string(std::strerror(errno)));
  }
  return Status::success();
#endif
}

Status create_directories(std::string_view path) {
  if (path.empty()) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT, "directory path is empty");
  }
  std::error_code error;
  std::filesystem::create_directories(std::filesystem::path(std::string(path)), error);
  if (error) {
    return io_failure("create_directories", path, error.message());
  }
  return Status::success();
}

std::string path_with_suffix(std::string_view path, std::string_view suffix) {
  std::string out(path);
  out += suffix;
  return out;
}

std::string path_directory(std::string_view path) {
  const std::size_t slash = path.find_last_of("/\\");
  if (slash == std::string_view::npos) return std::string(".");
  if (slash == 0) return std::string(path.substr(0, 1));
  return std::string(path.substr(0, slash));
}

Status atomic_replace(std::string_view path, const std::uint8_t* data, std::size_t length) {
  const std::string destination(path);
  // The temporary lives in the same directory as the destination so that the final
  // move is a same-volume rename, the only operation that is atomic on both
  // supported platforms.
  const std::string temporary =
      path_with_suffix(destination, ".tmp-" + std::to_string(wall_clock_unix_millis()) + "-" +
                                       std::to_string(stable_hash_bytes(data, length)));

  {
    Result<File> file = File::open(temporary, OpenMode::kCreateTruncate);
    if (!file) return file.status();
    Status status = file.value().write_all(data, length);
    if (!status) {
      file.value().close();
      (void)remove_file(temporary);
      return status;
    }
    // The bytes must be durable before the rename.  Otherwise a crash can leave a
    // renamed but empty file, which is strictly worse than not writing at all.
    status = file.value().flush(FlushMode::kDurable);
    file.value().close();
    if (!status) {
      (void)remove_file(temporary);
      return status;
    }
  }

#if defined(AIFC_PLATFORM_WINDOWS)
  const std::wstring wide_temporary = to_wide(temporary);
  const std::wstring wide_destination = to_wide(destination);
  if (wide_temporary.empty() || wide_destination.empty()) {
    (void)remove_file(temporary);
    return Status::failure(ErrorCode::INVALID_ARGUMENT, "path is not valid UTF-8");
  }
  if (::MoveFileExW(wide_temporary.c_str(), wide_destination.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    const unsigned long error = ::GetLastError();
    (void)remove_file(temporary);
    return Status::failure(ErrorCode::DURABILITY_FAILURE,
                           "MoveFileEx failed for " + destination + ": " +
                               last_error_text(error));
  }
  return Status::success();
#else
  if (::rename(temporary.c_str(), destination.c_str()) != 0) {
    const std::string detail = std::strerror(errno);
    (void)remove_file(temporary);
    return Status::failure(ErrorCode::DURABILITY_FAILURE,
                           "rename failed for " + destination + ": " + detail);
  }
  // Make the directory entry durable.  Without this the rename itself can be lost
  // across a power failure even though the file content was flushed.
  const std::string directory = path_directory(destination);
  const int dir_fd = ::open(directory.c_str(), O_RDONLY);
  if (dir_fd >= 0) {
    const int fsync_result = ::fsync(dir_fd);
    ::close(dir_fd);
    if (fsync_result != 0) {
      return Status::failure(ErrorCode::DURABILITY_FAILURE,
                             "directory fsync failed for " + directory + ": " +
                                 std::string(std::strerror(errno)));
    }
  }
  return Status::success();
#endif
}

Result<std::vector<std::string>> list_directory(std::string_view path) {
  std::vector<std::string> out;
  std::error_code error;
  std::filesystem::directory_iterator iterator(std::filesystem::path(std::string(path)), error);
  if (error) {
    return io_failure("directory_iterator", path, error.message());
  }
  for (const std::filesystem::directory_entry& entry : iterator) {
    std::error_code entry_error;
    if (!entry.is_regular_file(entry_error) || entry_error) continue;
    out.push_back(entry.path().filename().string());
  }
  std::sort(out.begin(), out.end());
  return out;
}

}  // namespace aifc
