/*  Copyright 2011 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include "maidsafe/encrypt/self_encryptor.h"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>
#include <memory>
#include <functional>
#include <future>

#ifdef __MSVC__
#pragma warning(push, 1)
#endif
#include "cryptopp/aes.h"
#include "cryptopp/gzip.h"
#include "cryptopp/modes.h"
#include "cryptopp/mqueue.h"
#include "cryptopp/sha.h"
#ifdef __MSVC__
#pragma warning(pop)
#endif

#include "boost/exception/all.hpp"
#include "maidsafe/common/config.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/on_scope_exit.h"
#include "maidsafe/common/profiler.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/data_map_encryptor.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/xor.h"
#include "maidsafe/encrypt/data_map.pb.h"

namespace maidsafe {

namespace encrypt {

SelfEncryptor::SelfEncryptor(DataMap& data_map, DataBuffer<std::string>& buffer,
                             std::function<NonEmptyString(const std::string&)> get_from_store)
    : data_map_(data_map),
      kOriginalDataMap_(data_map),
      sequencer_(kMaxChunkSize * 3),  // space for  min first 3 chunks 
      chunks_(),
      buffer_(buffer),
      get_from_store_(get_from_store),
      file_size_(data_map.size()),
      closed_(false),
      data_mutex_() {
  if (!get_from_store) {
    LOG(kError) << "Need to have a non-null get_from_store functor.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  auto pos(0);
  if (!data_map_.chunks.empty()) {
    assert(data_map_.chunks.size() >= 3);
    for (uint32_t i(0); i < data_map_.chunks.size(); ++i)
      chunks_.insert(std::make_pair(i, ChunkStatus::remote));
    for (uint32_t i(0); i < data_map_.chunks.size(); ++i) {
      if (i < 3) {  // just populate first three chunks
        ByteVector temp(DecryptChunk(i));
        for (const auto& t : temp)
          sequencer_[pos++] = t;
      }
    }
  } else if (data_map_.content.size() > 0) {
    for (const auto& t : data_map_.content)
      sequencer_[pos++] = t;
    chunks_.insert(std::make_pair(0, ChunkStatus::stored));
  }
}

SelfEncryptor::~SelfEncryptor() { assert(closed_ && "file not closed"); }

bool SelfEncryptor::Write(const char* data, uint32_t length, uint64_t position) {
  if (closed_)
    BOOST_THROW_EXCEPTION(MakeError(EncryptErrors::encryptor_closed));
  on_scope_exit ose([this] { CleanUpAfterException(); });
  SCOPED_PROFILE

  file_size_ = std::max(file_size_, length + position);
  PrepareWindow(length, position, true);
  for (uint32_t i(0); i < length; ++i)
    sequencer_[position + i] = data[i];  // direct as may be overwrite
  ose.Release();
  return true;
}

bool SelfEncryptor::Read(char* data, uint32_t length, uint64_t position) {
  if (closed_)
    BOOST_THROW_EXCEPTION(MakeError(EncryptErrors::encryptor_closed));
  if ((position + length) > file_size_)
    return false;  // This is unclear whether to allow the read and fill any unwritten parts with
                   // zero if reading past EOF. Seems if a file is writtem past EOF then this shoudl
                   // be OK, this object follows the pattern that a write past EOF is fine, any read
                   // within that file will work, even on sparse files
  on_scope_exit ose([this] { CleanUpAfterException(); });
  SCOPED_PROFILE
  PrepareWindow(length, position, false);
  for (uint32_t i(0); i < length; ++i)
    data[i] = sequencer_[position + i];
  ose.Release();
  return true;
}

bool SelfEncryptor::Truncate(uint64_t position) {
  if (closed_)
    BOOST_THROW_EXCEPTION(MakeError(EncryptErrors::encryptor_closed));
  on_scope_exit ose([this] { CleanUpAfterException(); });
  SCOPED_PROFILE

  auto old_size = file_size_;
  file_size_ = position;  //  All helper methods calculate from file size
  if (position < old_size) {
    for (auto& t : chunks_)
      if (t.first > position)
        chunks_.erase(chunks_.find(t.first));  // this is the only erase on chunks_
  } else {
    assert(position - old_size < std::numeric_limits<uint32_t>::max());
    PrepareWindow(static_cast<uint32_t>(position - old_size), old_size, true);
  }
  ose.Release();
  return true;
}

bool SelfEncryptor::Flush() {
  if (closed_)
    BOOST_THROW_EXCEPTION(MakeError(EncryptErrors::encryptor_closed));
  closed_ = true;
  return true;
}  // noop until we can tell if this is required when asked

void SelfEncryptor::Close() {
  if (closed_)
    return;  // can call close multiple times, safely
  on_scope_exit ose([this] { CleanUpAfterException(); });
  SCOPED_PROFILE

  if (file_size_ < (3 * kMinChunkSize)) {
    data_map_.content.clear();
    data_map_.content.reserve(file_size_);
    std::copy_n(std::begin(sequencer_), file_size_, std::back_inserter(data_map_.content));
    ose.Release();
    closed_ = true;
    return;
  }
  assert(GetNumChunks() > 2 && "Try to close with less than 3 chunks");
  data_map_.chunks.resize(GetNumChunks());
  std::vector<std::future<void>> fut;
  for (auto& chunk : chunks_) {
    if (chunk.second == ChunkStatus::to_be_hashed ||
        data_map_.chunks[chunk.first].pre_hash.empty() || GetNumChunks() == 3) {
      auto this_size(GetChunkSize(chunk.first));
      auto pos = GetStartEndPositions(chunk.first);

      fut.emplace_back(std::async([=]() {
        ByteVector tmp(this_size);
        for (uint32_t i(0); i < this_size; ++i)
          tmp[i] = sequencer_[i + pos.first];
        assert(tmp.size() == this_size && "vector diff size from chunk size");
        {
          std::lock_guard<std::mutex> guard(data_mutex_);
          data_map_.chunks[chunk.first].pre_hash.clear();
          data_map_.chunks[chunk.first].pre_hash.resize(crypto::SHA512::DIGESTSIZE);
        }
        ByteVector tmp2(crypto::SHA512::DIGESTSIZE);
        CryptoPP::SHA512().CalculateDigest(&tmp2.data()[0], &tmp.data()[0],
                                           crypto::SHA512::DIGESTSIZE);
        {
          std::lock_guard<std::mutex> guard(data_mutex_);
          std::swap(data_map_.chunks[chunk.first].pre_hash, tmp2);
          assert(crypto::SHA512::DIGESTSIZE == data_map_.chunks[chunk.first].pre_hash.size() &&
                 "Hash size wrong");
        }
      }));
      chunk.second = ChunkStatus::to_be_encrypted;
    }
  }
  // thread barrier emulation
  for (auto& res : fut)
    res.wait();
  std::vector<std::future<void>> fut2;
  for (auto& chunk : chunks_) {
    if (chunk.second == ChunkStatus::to_be_encrypted) {
      auto this_size(GetChunkSize(chunk.first));
      auto pos = GetStartEndPositions(chunk.first);

      fut2.emplace_back(std::async([=]() {
        ByteVector tmp(this_size);
        for (uint32_t i(0); i < this_size; ++i)
          tmp[i] = sequencer_[i + pos.first];
        EncryptChunk(chunk.first, tmp, this_size);
      }));
      chunk.second = ChunkStatus::stored;
    }
  }
  // thread barrier emulation
  for (auto& res : fut2)
    res.wait();
  ose.Release();
  closed_ = true;
}

//##############################Private######################

void SelfEncryptor::PrepareWindow(uint32_t length, uint64_t position, bool write) {
  if (sequencer_.size() < file_size_) {
    sequencer_.resize(file_size_);
    assert(sequencer_.size() == file_size_);
  }
  if (file_size_ < (3 * kMinChunkSize))
    return;
  auto first_chunk(GetChunkNumber(position));
  auto last_chunk(GetChunkNumber(position + length));
  if (write && (sequencer_.size() < (position + length))) {
    sequencer_.resize(position + length);
    assert(sequencer_.size() == (position + length) && "could not resize sequencer");
  }
  if (file_size_ < 3 * kMaxChunkSize) {
    first_chunk = 0;  // in this case encrypt all.
    last_chunk = 3;
    chunks_.clear();  // make sure to mark all correctly
  } else {            // do not read ahead unless possible
    for (auto i(1); i < 3; ++i)
      if (last_chunk + i < GetNumChunks() - 1)
        ++last_chunk;
  }

  std::vector<std::future<void>> fut2;
  for (auto i(first_chunk); i < last_chunk; ++i) {
    auto current_chunk_itr = chunks_.find(i);
    if (current_chunk_itr == std::end(chunks_)) {
      write ? chunks_.insert({i, ChunkStatus::to_be_hashed})
            : chunks_.insert({i, ChunkStatus::stored});
    } else {
      auto pos(GetStartEndPositions(i).first);
      if (current_chunk_itr->second == ChunkStatus::remote) {
        fut2.emplace_back(std::async([=]() {
          auto ins = pos;
          ByteVector tmp(DecryptChunk(i));
          for (const auto& t : tmp)
            sequencer_[ins++] = t;
        }));
        write ? current_chunk_itr->second = ChunkStatus::to_be_hashed : current_chunk_itr->second =
                                                                            ChunkStatus::stored;
      } else {
        current_chunk_itr->second = ChunkStatus::to_be_hashed;
      }
    }
  }
  // thread barrier emulation
  for (auto& res : fut2)
    res.wait();
}

ByteVector SelfEncryptor::DecryptChunk(uint32_t chunk_num) {
  SCOPED_PROFILE
  if (data_map_.chunks.size() < chunk_num) {
    LOG(kWarning) << "Can't decrypt chunk " << chunk_num << " of " << data_map_.chunks.size();
    BOOST_THROW_EXCEPTION(MakeError(EncryptErrors::failed_to_decrypt));
  }

  uint32_t length = data_map_.chunks[chunk_num].size;
  ByteVector data(length);
  ByteVector pad(kPadSize);
  ByteVector key(crypto::AES256_KeySize);
  ByteVector iv(crypto::AES256_IVSize);
  GetPadIvKey(chunk_num, key, iv, pad);
  assert(pad.size() == kPadSize && "pad size incorrect");
  assert(key.size() == crypto::AES256_KeySize && "key size incorrect");
  assert(iv.size() == crypto::AES256_IVSize && "iv size incorrect");
  NonEmptyString content;
  try {
    content = get_from_store_(std::string(std::begin(data_map_.chunks[chunk_num].hash),
                                          std::end(data_map_.chunks[chunk_num].hash)));
  }
  catch (const std::exception& e) {
    LOG(kInfo) << boost::diagnostic_information(e);
    throw;
  }
  // asserts on vector sizes
  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(&key.data()[0], crypto::AES256_KeySize,
                                                          &iv.data()[0]);
  CryptoPP::StringSource filter(
      content.string(), true,
      new XORFilter(new CryptoPP::StreamTransformationFilter(
                        decryptor, new CryptoPP::Gunzip(new CryptoPP::MessageQueue)),
                    &pad.data()[0]));
  filter.Get(&data.data()[0], length);
  auto chunk_itr(chunks_.find(chunk_num));
  assert(chunk_itr != std::end(chunks_) && "chunks status not found");
  chunk_itr->second = ChunkStatus::stored;

  return data;
}

void SelfEncryptor::GetPadIvKey(uint32_t chunk_number, ByteVector& key, ByteVector& iv,
                                ByteVector& pad) {
  SCOPED_PROFILE
  assert(pad.size() == kPadSize && "pad size incorrect");
  assert(key.size() == crypto::AES256_KeySize && "key size incorrect");
  assert(iv.size() == crypto::AES256_IVSize && "iv size incorrect");
  uint32_t n_1_chunk(GetPreviousChunkNumber(chunk_number));
  uint32_t n_2_chunk(GetPreviousChunkNumber(n_1_chunk));
#ifndef NDEBUG
  auto chunk_n_1_itr(chunks_.find(n_1_chunk));
  auto chunk_n_2_itr(chunks_.find(n_2_chunk));
#endif
  assert(chunks_.size() >= n_1_chunk);
  assert(chunks_.size() >= n_2_chunk);
  assert(chunk_n_1_itr != std::end(chunks_) && "chunk_n_1 chunkstatus not found");
  assert(chunk_n_2_itr != std::end(chunks_) && "chunk_n_2 chunkstatus not found");

  const ByteVector n_1_pre_hash{data_map_.chunks[n_1_chunk].pre_hash};
  const ByteVector n_2_pre_hash{data_map_.chunks[n_2_chunk].pre_hash};

  assert(n_1_pre_hash.size() == crypto::SHA512::DIGESTSIZE);
  assert(n_2_pre_hash.size() == crypto::SHA512::DIGESTSIZE);
  key.clear();
  // cannot use copy_n as there is an apparent bug in MSVC 2013 :-(
  std::copy(std::begin(n_2_pre_hash), std::begin(n_2_pre_hash) + crypto::AES256_KeySize,
            std::back_inserter(key));
  iv.clear();
  std::copy(std::begin(n_2_pre_hash) + crypto::AES256_KeySize,
            std::begin(n_2_pre_hash) + crypto::AES256_KeySize + crypto::AES256_IVSize,
            std::back_inserter(iv));
  // pad
  assert(kPadSize == (2 * crypto::SHA512::DIGESTSIZE) + crypto::SHA512::DIGESTSIZE -
                         crypto::AES256_KeySize - crypto::AES256_IVSize &&
         "pad size wrong");
  pad.clear();
  std::copy_n(std::begin(n_1_pre_hash), crypto::SHA512::DIGESTSIZE, std::back_inserter(pad));
  std::copy_n(std::begin(data_map_.chunks[chunk_number].pre_hash), crypto::SHA512::DIGESTSIZE,
              std::back_inserter(pad));  // + crypto::SHA512::DIGESTSIZE);
  std::copy_n(std::begin(n_2_pre_hash) + crypto::AES256_KeySize + crypto::AES256_IVSize,
              crypto::SHA512::DIGESTSIZE - crypto::AES256_KeySize - crypto::AES256_IVSize,
              std::back_inserter(pad));  // + crypto::SHA512::DIGESTSIZE * 2);
  assert(pad.size() == kPadSize && "pad size incorrect");
  assert(key.size() == crypto::AES256_KeySize && "key size incorrect");
  assert(iv.size() == crypto::AES256_IVSize && "iv size incorrect");
}

void SelfEncryptor::EncryptChunk(uint32_t chunk_number, ByteVector data, uint32_t length) {
  SCOPED_PROFILE
  assert(data_map_.chunks.size() >= chunk_number);
  assert(chunks_.size() >= chunk_number);

  assert(chunks_.size() >= chunk_number);
  auto chunk_n_itr(chunks_.find(chunk_number));
  assert(chunk_n_itr != std::end(chunks_) && "this chunk chunkstatus not found");
#ifndef NDEBUG
  uint32_t n_1_chunk(GetPreviousChunkNumber(chunk_number));
  uint32_t n_2_chunk(GetPreviousChunkNumber(n_1_chunk));
  auto chunk_n_1_itr(chunks_.find(n_1_chunk));
  auto chunk_n_2_itr(chunks_.find(n_2_chunk));
#endif

  assert(chunk_n_1_itr->second != ChunkStatus::to_be_hashed && "chunk_n_1 hash invalid");
  assert(chunk_n_2_itr->second != ChunkStatus::to_be_hashed && "chunk_n_2 hash invalid");

  ByteVector pad(kPadSize);
  ByteVector key(crypto::AES256_KeySize);
  ByteVector iv(crypto::AES256_IVSize);
  GetPadIvKey(chunk_number, key, iv, pad);
  assert(pad.size() == kPadSize && "pad size incorrect");
  assert(key.size() == crypto::AES256_KeySize && "key size incorrect");
  assert(iv.size() == crypto::AES256_IVSize && "iv size incorrect");

  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(&key.data()[0], crypto::AES256_KeySize,
                                                          &iv.data()[0]);

  std::string chunk_content;
  chunk_content.reserve(length);
  CryptoPP::Gzip aes_filter(
      new CryptoPP::StreamTransformationFilter(
          encryptor, new XORFilter(new CryptoPP::StringSink(chunk_content), &pad.data()[0])),
      1);
  aes_filter.Put2(&data.data()[0], length, -1, true);

  CryptoPP::SHA512 hash;
  std::string result;
  CryptoPP::StringSource(chunk_content, true,
                         new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(result)));

  {
  std::lock_guard<std::mutex> guard(data_mutex_);
  buffer_.Store(result, NonEmptyString(chunk_content));
}
  chunk_n_itr->second = ChunkStatus::stored;
  {
    std::lock_guard<std::mutex> guard(data_mutex_);
    ByteVector tmp2(std::begin(result), std::end(result));
    std::swap(data_map_.chunks[chunk_number].hash, tmp2);
    assert(crypto::SHA512::DIGESTSIZE == data_map_.chunks[chunk_number].hash.size() &&
           "Hash size wrong");

    data_map_.chunks[chunk_number].size = length;  // keep pre-compressed length
    data_map_.chunks[chunk_number].storage_state = ChunkDetails::kPending;
  }
}

//####################Helpers############################

uint32_t SelfEncryptor::GetChunkSize(uint32_t chunk) const {
  if (file_size_ < 3 * kMinChunkSize)
    return 0;
  assert(GetNumChunks() != 0 && "file size has no chunks");
  if (file_size_ < 3 * kMaxChunkSize) {
    if (chunk < 2)
      return static_cast<uint32_t>(file_size_ / 3);
    else
      return static_cast<uint32_t>(file_size_ - (2 * (file_size_ / 3)));
  }
  // handle all but last 2 chunks
  if (chunk < GetNumChunks() - 2)
    return kMaxChunkSize;

  uint32_t remainder(static_cast<uint32_t>(file_size_ % kMaxChunkSize));
  bool penultimate((GetNumChunks() - 2) == chunk);

  if (remainder == 0)
    return kMaxChunkSize;
  // if the last chunk is goind to be less than kMinChunkSize we reduce the penultimate chunk by
  // kMinChunkSize
  if (remainder < kMinChunkSize) {
    if (penultimate)
      return kMaxChunkSize - kMinChunkSize;
    else
      return kMinChunkSize + remainder;
  } else {
    if (penultimate)
      return kMaxChunkSize;
    else
      return remainder;
  }
}

uint32_t SelfEncryptor::GetNumChunks() const {
  if (file_size_ < 3 * kMinChunkSize)
    return 0;
  if (file_size_ < 3 * kMaxChunkSize)
    return 3;
  if (static_cast<uint32_t>(file_size_ % kMaxChunkSize == 0))
    return static_cast<uint32_t>(file_size_ / kMaxChunkSize);
  else
    return static_cast<uint32_t>(file_size_ / kMaxChunkSize) + 1;
}

std::pair<uint64_t, uint64_t> SelfEncryptor::GetStartEndPositions(uint32_t chunk_number) const {
  assert(GetNumChunks() > 2 && "less than 3 chunks");
  if (GetNumChunks() == 0)
    return {0, 0};
  auto start(0);
  bool penultimate((GetNumChunks() - 2) == chunk_number);
  bool last((GetNumChunks() - 1) == chunk_number);

  if (last) {
    start = ((GetChunkSize(0) * (chunk_number - 2)) + GetChunkSize(chunk_number - 2) +
             GetChunkSize(chunk_number - 1));
  } else if (penultimate) {
    start = ((GetChunkSize(0) * (chunk_number - 1)) + GetChunkSize(chunk_number - 1));
  } else {

    start = (GetChunkSize(0) * (chunk_number));
  }

  return std::make_pair(start, start + GetChunkSize(chunk_number));
}

uint32_t SelfEncryptor::GetNextChunkNumber(uint32_t chunk_number) const {
  if (GetNumChunks() == 0)
    return 0;
  return (GetNumChunks() + chunk_number + 1) % GetNumChunks();
}

uint32_t SelfEncryptor::GetPreviousChunkNumber(uint32_t chunk_number) const {
  if (GetNumChunks() == 0)
    return 0;
  return (GetNumChunks() + chunk_number - 1) % GetNumChunks();
}

uint32_t SelfEncryptor::GetChunkNumber(uint64_t position) const {
  if (GetNumChunks() == 0 || position == 0)
    return 0;
  if (static_cast<uint32_t>(position % GetChunkSize(0)) == 0 || position < 3 * kMaxChunkSize)
    return static_cast<uint32_t>(position / GetChunkSize(0));
  else
    return static_cast<uint32_t>(position / GetChunkSize(0)) + 1;
}

}  // namespace encrypt

}  // namespace maidsafe
