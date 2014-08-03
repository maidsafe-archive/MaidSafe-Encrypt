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
#include "maidsafe/common/on_scope_exit.h"
#include "maidsafe/common/profiler.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/data_map_encryptor.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/xor.h"
#include "maidsafe/encrypt/cache.h"
#include "maidsafe/encrypt/data_map.pb.h"

namespace maidsafe {

namespace encrypt {


SelfEncryptor::SelfEncryptor(DataMap& data_map, DataBuffer<std::string>& buffer,
                             std::function<NonEmptyString(const std::string&)> get_from_store)
    : data_map_(data_map),
      kOriginalDataMap_(data_map),
      sequencer_(std::numeric_limits<uint64_t>::max()),  // could be that large
      chunks_(),
      read_cache_(new Cache(kMaxChunkSize * 8)),
      buffer_(buffer),
      get_from_store_(get_from_store),
      file_size_(data_map_.size()),
      closed_(false),
      data_mutex_() {
  if (!get_from_store) {
    LOG(kError) << "Need to have a non-null get_from_store functor.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  auto pos(0);
  if (!data_map_.chunks.empty()) {
    assert(data_map_.chunks.size() >= 3);
    for (size_t i(0); i < data_map_.chunks.size(); ++i) {
      if (i < 3) {  // just populate first three chunks
        ByteVector temp(DecryptChunk(i));
        for (const auto& t : temp)
          sequencer_.insert_element(pos++, t);
        chunks_.insert(std::make_pair(i, ChunkStatus::stored));
      } else {
        chunks_.insert(std::make_pair(i, ChunkStatus::remote));
      }
    }
  } else if (data_map_.content.size() > 0) {
    for (const auto& t : data_map_.content)
      sequencer_.insert_element(pos++, t);
    chunks_.insert(std::make_pair(0, ChunkStatus::stored));
  }
}

SelfEncryptor::~SelfEncryptor() {
  assert(!closed_ && "file not closed closed");
}

bool SelfEncryptor::Write(const char* data, uint32_t length, uint64_t position) {
  if (closed_)
    BOOST_THROW_EXCEPTION(MakeError(EncryptErrors::encryptor_closed));
  on_scope_exit ose([this] { CleanUpAfterException(); });
  SCOPED_PROFILE
  ByteVector to_be_written(data, data + length);  // copy - inefficient
  read_cache_->Put(to_be_written, position);

  file_size_ = std::max(file_size_, length + position);
  PrepareWindow(length, position, true);
  for (const auto& entry : to_be_written)
    sequencer_[position++] = entry;  // direct as may be overwrite
  ose.Release();
  return true;
}

bool SelfEncryptor::Read(char* data, uint32_t length, uint64_t position) {
  if (closed_)
    BOOST_THROW_EXCEPTION(MakeError(EncryptErrors::encryptor_closed));
  on_scope_exit ose([this] { CleanUpAfterException(); });
  SCOPED_PROFILE
  file_size_ = std::max(file_size_, length + position);
  // if (length == 0)
  //   return true;
  ByteVector temp;
  temp.reserve(length);
  if (read_cache_->Get(temp, length, position)) {
   memcpy(data, temp.data(), length);
   LOG(kInfo) << " Cache hit";
  } else {
   LOG(kInfo) << " Cache miss";
  }

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
  file_size_ = position;
  ose.Release();
  return true;
}

bool SelfEncryptor::Flush() {
  if (closed_)
    BOOST_THROW_EXCEPTION(MakeError(EncryptErrors::encryptor_closed));
  on_scope_exit ose([this] { CleanUpAfterException(); });
  ose.Release();
  return true;
}  // noop until we can tell if this is required when asked

void SelfEncryptor::Close() {
  on_scope_exit ose([this] { CleanUpAfterException(); });
  SCOPED_PROFILE

  if (file_size_ < 3 * kMinChunkSize) {
    data_map_.content.clear();
    data_map_.content.reserve(file_size_);
    std::copy_n(std::begin(sequencer_), file_size_, std::begin(data_map_.content));
    return;
  }
  data_map_.chunks.resize(GetNumChunks());
  assert(GetNumChunks() > 2 && "Try to close with less than 3 chunks");
  std::vector<std::future<void>> fut;
  for (auto& chunk : chunks_) {
    if (chunk.second == ChunkStatus::to_be_hashed) {
      auto this_size(GetChunkSize(chunk.first));
      auto pos = GetStartEndPositions(chunk.first);

      fut.emplace_back(std::async([=]() {
        ByteVector tmp(this_size);
        for (uint32_t i(0); i < this_size; ++i)
          tmp[i] = sequencer_[i + pos.first];
        assert(tmp.size() == this_size && "vector diff size from chunk size");
        data_map_.chunks[chunk.first].pre_hash.resize(crypto::SHA512::DIGESTSIZE);
        CryptoPP::SHA512().CalculateDigest(&data_map_.chunks[chunk.first].pre_hash.data()[0],
                                           &tmp.data()[0], tmp.size());
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
  if (file_size_ < 3 * kMinChunkSize)
    return;
  auto first_chunk(GetChunkNumber(position));
  auto last_chunk(GetChunkNumber(position + length));
  // read ahead 2 chunks if possible
  for (auto i(1); i < 3; ++i)
    if (last_chunk + i < GetNumChunks())
      ++last_chunk;

  for (auto i(first_chunk); i <= last_chunk; ++i) {
    auto current_chunk_itr = chunks_.find(i);
    auto pos(GetStartEndPositions(i).first);
    if (current_chunk_itr != std::end(chunks_)) {
      if (current_chunk_itr->second == ChunkStatus::remote) {
        ByteVector tmp(DecryptChunk(i));
        if (write)
          current_chunk_itr->second = ChunkStatus::to_be_hashed;
        for (const auto& t : tmp)
          sequencer_[pos++] = t;
      }
    } else {
      write ? chunks_.insert({i, ChunkStatus::to_be_hashed})
            : chunks_.insert({i, ChunkStatus::stored});
    }
  }
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
    LOG(kInfo) << boost::current_exception_diagnostic_information(true);
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
  return data;
}

void SelfEncryptor::GetPadIvKey(uint32_t this_chunk_num, ByteVector& key, ByteVector& iv,
                                ByteVector& pad) {
  SCOPED_PROFILE
  assert(pad.size() == kPadSize && "pad size incorrect");
  assert(key.size() == crypto::AES256_KeySize && "key size incorrect");
  assert(iv.size() == crypto::AES256_IVSize && "iv size incorrect");

  uint32_t n_1_chunk(GetPreviousChunkNumber(this_chunk_num));
  uint32_t n_2_chunk(GetPreviousChunkNumber(n_1_chunk));

  const ByteVector n_1_pre_hash = data_map_.chunks[n_1_chunk].pre_hash;
  const ByteVector n_2_pre_hash = data_map_.chunks[n_2_chunk].pre_hash;

  assert(n_1_pre_hash.size() == crypto::SHA512::DIGESTSIZE);
  assert(n_2_pre_hash.size() == crypto::SHA512::DIGESTSIZE);

  std::copy_n(std::begin(n_2_pre_hash), crypto::AES256_KeySize, std::begin(key));
  std::copy_n(std::begin(n_2_pre_hash) + crypto::AES256_KeySize, crypto::AES256_IVSize,
              std::begin(iv));
  // pad
  assert(kPadSize == (2 * crypto::SHA512::DIGESTSIZE) + crypto::SHA512::DIGESTSIZE -
                         crypto::AES256_KeySize - crypto::AES256_IVSize &&
         "pad size wrong");
  std::copy_n(std::begin(n_1_pre_hash), crypto::SHA512::DIGESTSIZE, std::begin(pad));
  std::copy_n(std::begin(data_map_.chunks[this_chunk_num].pre_hash), crypto::SHA512::DIGESTSIZE,
              std::begin(pad) + crypto::SHA512::DIGESTSIZE);
  std::copy_n(std::begin(n_2_pre_hash) + crypto::AES256_KeySize + crypto::AES256_IVSize,
              crypto::SHA512::DIGESTSIZE - crypto::AES256_KeySize - crypto::AES256_IVSize,
              std::begin(pad) + crypto::SHA512::DIGESTSIZE * 2);
}

void SelfEncryptor::EncryptChunk(uint32_t chunk_num, ByteVector data, uint32_t length) {
  SCOPED_PROFILE
  assert(data_map_.chunks.size() > chunk_num);
  assert(chunks_.size() > chunk_num);

  assert(chunks_.size() > chunk_num);
  auto chunk_n_itr(chunks_.find(chunk_num));
#ifndef NDEBUG
  uint32_t n_1_chunk(GetPreviousChunkNumber(chunk_num));
  uint32_t n_2_chunk(GetPreviousChunkNumber(n_1_chunk));
  auto chunk_n_1_itr(chunks_.find(n_1_chunk));
  auto chunk_n_2_itr(chunks_.find(n_2_chunk));
#endif
  assert(chunks_.size() > n_1_chunk);
  assert(chunks_.size() > n_2_chunk);
  assert(chunk_n_itr != std::end(chunks_) && "this chunk chunkstatus not found");
  assert(chunk_n_1_itr != std::end(chunks_) && "chunk_n_1 chunkstatus not found");
  assert(chunk_n_2_itr != std::end(chunks_) && "chunk_n_2 chunkstatus not found");
  assert(chunk_n_1_itr->second != ChunkStatus::to_be_hashed && "chunk_n_1 hash invalid");
  assert(chunk_n_2_itr->second != ChunkStatus::to_be_hashed && "chunk_n_2 hash invalid");

  ByteVector pad(kPadSize);
  ByteVector key(crypto::AES256_KeySize);
  ByteVector iv(crypto::AES256_IVSize);
  GetPadIvKey(chunk_num, key, iv, pad);
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

  try {
    std::lock_guard<std::mutex> guard(data_mutex_);
    buffer_.Store(std::string(std::begin(data_map_.chunks[chunk_num].hash),
                              std::end(data_map_.chunks[chunk_num].hash)),
                  NonEmptyString(chunk_content));
  }
  catch (const std::exception& e) {
    LOG(kError) << e.what() << "Could not store "
                << Base64Substr(std::string(std::begin(data_map_.chunks[chunk_num].hash),
                                            std::begin(data_map_.chunks[chunk_num].hash)));
    LOG(kInfo) << boost::current_exception_diagnostic_information(true);
    throw;
  }
  chunk_n_itr->second = ChunkStatus::stored;
  {
    std::lock_guard<std::mutex> guard(data_mutex_);

    data_map_.chunks[chunk_num].hash.resize(crypto::SHA512::DIGESTSIZE);
    CryptoPP::SHA512().CalculateDigest(&data_map_.chunks[chunk_num].hash.data()[0],
                                       reinterpret_cast<const byte*>(&chunk_content.data()[0]),
                                       chunk_content.size());
    data_map_.chunks[chunk_num].size = length;  // keep pre-compressed length
    data_map_.chunks[chunk_num].storage_state = ChunkDetails::kPending;
  }
}


void SelfEncryptor::DeleteChunk(uint32_t chunk_num) {
  SCOPED_PROFILE
  std::lock_guard<std::mutex> data_guard(data_mutex_);
  if (data_map_.chunks[chunk_num].hash.empty())
    return;

  try {
    buffer_.Delete(std::string(std::begin(data_map_.chunks[chunk_num].hash),
                               std::end(data_map_.chunks[chunk_num].hash)));
  }
  catch (std::exception& e) {
    LOG(kInfo) << boost::current_exception_diagnostic_information(true);
    throw(e);
  }
}

//####################Helpers############################

uint32_t SelfEncryptor::GetChunkSize(uint32_t chunk) {
  assert(GetNumChunks() != 0 && "file size has no chunks");
  if (file_size_ < 3U * kMaxChunkSize) {
    if (chunk < 2U)
      return file_size_ / 3U;
    else
      return file_size_ - (2 * (file_size_ / 3U));
  }
  if (chunk < GetNumChunks())
    return kMaxChunkSize;
  else
    return file_size_ - ((GetNumChunks() - 1) * kMaxChunkSize);
}

uint32_t SelfEncryptor::GetNumChunks() {
  if (data_map_.size() == file_size_) {
    return static_cast<uint32_t>(data_map_.chunks.size());
  } else if (file_size_ < 3 * kMinChunkSize) {
    return 0;
  } else if (file_size_ <= 3 * kMaxChunkSize) {
    return 3;
  } else {
    return file_size_ % kMaxChunkSize == 0 ? file_size_ / kMaxChunkSize
                                           : (file_size_ / kMaxChunkSize) + 1;
  }
}

std::pair<uint64_t, uint64_t> SelfEncryptor::GetStartEndPositions(uint32_t chunk_number) {
  assert(GetNumChunks() > 2 && "less than 3 chunks");
  auto start(GetChunkSize(0) * chunk_number);
  return std::make_pair(start, start + GetChunkSize(chunk_number));
}

uint32_t SelfEncryptor::GetNextChunkNumber(uint32_t chunk_number) {
  assert(GetNumChunks() > 2 && "less than 3 chunks");
  return (GetNumChunks() + chunk_number + 1) % GetNumChunks();
}

uint32_t SelfEncryptor::GetPreviousChunkNumber(uint32_t chunk_number) {
  assert(GetNumChunks() > 2 && "less than 3 chunks");
  return (GetNumChunks() + chunk_number - 1) % GetNumChunks();
}

uint32_t SelfEncryptor::GetChunkNumber(uint64_t position) {
  assert(GetNumChunks() > 2 && "less than 3 chunks");
  return position == 0 ? position : file_size_ / position;
}

}  // namespace encrypt

}  // namespace maidsafe
