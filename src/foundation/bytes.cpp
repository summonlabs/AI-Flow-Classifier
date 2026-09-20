// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/foundation/bytes.hpp"

#include <string>

namespace aifc {
namespace {

// A length prefix is always four bytes little endian.  Zero length is legal for
// blobs and for strings; the distinction between "absent" and "empty" is carried
// by an explicit presence flag in the record that needs it.
constexpr std::size_t kLengthPrefixBytes = 4;

[[nodiscard]] Status too_large(std::string_view what, std::size_t length, std::uint32_t limit) {
  return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                         std::string(what) + " of " + std::to_string(length) +
                             " bytes exceeds limit of " + std::to_string(limit));
}

}  // namespace

Status BufferWriter::ensure(std::size_t extra) const {
  if (extra > static_cast<std::size_t>(max_bytes_) ||
      bytes_.size() > static_cast<std::size_t>(max_bytes_) - extra) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "encoded record of " + std::to_string(bytes_.size() + extra) +
                               " bytes exceeds encoder bound of " + std::to_string(max_bytes_));
  }
  return Status::success();
}

Status BufferWriter::put_u8(std::uint8_t value) {
  Status status = ensure(1);
  if (!status) return status;
  bytes_.push_back(value);
  return Status::success();
}

Status BufferWriter::put_bool(bool value) { return put_u8(value ? 1U : 0U); }

Status BufferWriter::put_u16(std::uint16_t value) {
  Status status = ensure(2);
  if (!status) return status;
  std::uint8_t raw[2];
  store_u16_le(raw, value);
  bytes_.insert(bytes_.end(), raw, raw + 2);
  return Status::success();
}

Status BufferWriter::put_u32(std::uint32_t value) {
  Status status = ensure(4);
  if (!status) return status;
  std::uint8_t raw[4];
  store_u32_le(raw, value);
  bytes_.insert(bytes_.end(), raw, raw + 4);
  return Status::success();
}

Status BufferWriter::put_u64(std::uint64_t value) {
  Status status = ensure(8);
  if (!status) return status;
  std::uint8_t raw[8];
  store_u64_le(raw, value);
  bytes_.insert(bytes_.end(), raw, raw + 8);
  return Status::success();
}

Status BufferWriter::put_i64(std::int64_t value) {
  return put_u64(static_cast<std::uint64_t>(value));
}

Status BufferWriter::put_blob(const std::uint8_t* data, std::size_t length) {
  Status status = ensure(kLengthPrefixBytes + length);
  if (!status) return status;
  const auto prefix = static_cast<std::uint32_t>(length);
  status = put_u32(prefix);
  if (!status) return status;
  if (length != 0) {
    bytes_.insert(bytes_.end(), data, data + length);
  }
  return Status::success();
}

Status BufferWriter::put_raw(std::string_view data) {
  Status status = ensure(data.size());
  if (!status) return status;
  bytes_.insert(bytes_.end(), data.begin(), data.end());
  return Status::success();
}

Status BufferWriter::put_string(std::string_view value) {
  return put_blob(reinterpret_cast<const std::uint8_t*>(value.data()), value.size());
}

Status BufferReader::require(std::size_t count) const {
  if (count > remaining()) {
    return Status::failure(ErrorCode::MALFORMED_RECORD,
                           "truncated record: need " + std::to_string(count) + " bytes, have " +
                               std::to_string(remaining()));
  }
  return Status::success();
}

Result<std::uint8_t> BufferReader::get_u8() {
  Status status = require(1);
  if (!status) return status;
  const std::uint8_t value = data_[offset_];
  offset_ += 1;
  return value;
}

Result<bool> BufferReader::get_bool() {
  Result<std::uint8_t> raw = get_u8();
  if (!raw) return raw.status();
  if (raw.value() > 1U) {
    return Status::failure(ErrorCode::MALFORMED_RECORD, "boolean field is not 0 or 1");
  }
  return raw.value() == 1U;
}

Result<std::uint16_t> BufferReader::get_u16() {
  Status status = require(2);
  if (!status) return status;
  const std::uint16_t value = load_u16_le(data_ + offset_);
  offset_ += 2;
  return value;
}

Result<std::uint32_t> BufferReader::get_u32() {
  Status status = require(4);
  if (!status) return status;
  const std::uint32_t value = load_u32_le(data_ + offset_);
  offset_ += 4;
  return value;
}

Result<std::uint64_t> BufferReader::get_u64() {
  Status status = require(8);
  if (!status) return status;
  const std::uint64_t value = load_u64_le(data_ + offset_);
  offset_ += 8;
  return value;
}

Result<std::int64_t> BufferReader::get_i64() {
  Result<std::uint64_t> raw = get_u64();
  if (!raw) return raw.status();
  return static_cast<std::int64_t>(raw.value());
}

Result<ByteBuffer> BufferReader::get_blob(std::uint32_t max_length) {
  Result<std::uint32_t> declared = get_u32();
  if (!declared) return declared.status();
  const std::uint32_t length = declared.value();
  if (length > max_length) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "declared blob length " + std::to_string(length) +
                               " exceeds limit of " + std::to_string(max_length));
  }
  // The declared length is checked against the remaining bytes *before* any
  // allocation, so a hostile length cannot reserve memory.
  Status status = require(length);
  if (!status) return status;
  ByteBuffer out(data_ + offset_, data_ + offset_ + length);
  offset_ += length;
  return out;
}

Result<std::string> BufferReader::get_long_string(std::uint32_t max_length) {
  Result<ByteBuffer> raw = get_blob(max_length);
  if (!raw) return raw.status();
  const ByteBuffer& bytes = raw.value();
  return std::string(bytes.begin(), bytes.end());
}

Result<std::string> BufferReader::get_string() {
  Result<ByteBuffer> raw = get_blob(max_string_bytes_);
  if (!raw) return raw.status();
  const ByteBuffer& bytes = raw.value();
  return std::string(bytes.begin(), bytes.end());
}

Result<std::uint32_t> BufferReader::get_count(std::uint32_t max_count) {
  Result<std::uint32_t> declared = get_u32();
  if (!declared) return declared.status();
  if (declared.value() > max_count) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "declared collection count " + std::to_string(declared.value()) +
                               " exceeds limit of " + std::to_string(max_count));
  }
  return declared.value();
}

Status BufferReader::finish() const {
  if (offset_ != size_) {
    return Status::failure(ErrorCode::TRAILING_GARBAGE,
                           std::to_string(size_ - offset_) + " trailing bytes after canonical record");
  }
  return Status::success();
}

Status BufferReader::finish_with_trailer(std::uint32_t max_extra) {
  const std::size_t extra = remaining();
  if (extra > max_extra) {
    return Status::failure(ErrorCode::TRAILING_GARBAGE,
                           std::to_string(extra) + " trailing bytes exceed permitted trailer of " +
                               std::to_string(max_extra));
  }
  offset_ = size_;
  return Status::success();
}

bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t length) noexcept {
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < length; ++i) {
    diff = static_cast<std::uint8_t>(diff | (a[i] ^ b[i]));
  }
  return diff == 0;
}

}  // namespace aifc
