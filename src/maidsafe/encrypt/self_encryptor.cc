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
#include <set>
#include <tuple>
#include <utility>
#include <memory>

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
#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/profiler.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/config.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/on_scope_exit.h"

#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/xor.h"
#include "maidsafe/encrypt/cache.h"
#include "maidsafe/encrypt/data_map.pb.h"

namespace maidsafe {

namespace encrypt {

const EncryptionAlgorithm kSelfEncryptionVersion = EncryptionAlgorithm::kSelfEncryptionVersion0;
const EncryptionAlgorithm kDataMapEncryptionVersion =
    EncryptionAlgorithm::kDataMapEncryptionVersion0;

namespace {

DataMap DecryptUsingVersion0(const Identity& parent_id, const Identity& this_id,
                             const protobuf::EncryptedDataMap& protobuf_encrypted_data_map) {
  if (protobuf_encrypted_data_map.data_map_encryption_version() !=
      static_cast<uint32_t>(EncryptionAlgorithm::kDataMapEncryptionVersion0)) {
    BOOST_THROW_EXCEPTION(MakeError(EncryptErrors::invalid_encryption_version));
  }

  size_t inputs_size(parent_id.string().size() + this_id.string().size());
  byte* enc_hash = new byte[crypto::SHA512::DIGESTSIZE];
  byte* xor_hash = new byte[crypto::SHA512::DIGESTSIZE];
  on_scope_exit([=] {
    delete enc_hash;
    delete xor_hash;
  });
  CryptoPP::SHA512().CalculateDigest(
      enc_hash, reinterpret_cast<const byte*>((parent_id.string() + this_id.string()).data()),
      inputs_size);
  CryptoPP::SHA512().CalculateDigest(
      xor_hash, reinterpret_cast<const byte*>((this_id.string() + parent_id.string()).data()),
      inputs_size);

  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(enc_hash, crypto::AES256_KeySize,
                                                          enc_hash + crypto::AES256_KeySize);

  std::string serialised_data_map;
  CryptoPP::StringSource filter(
      protobuf_encrypted_data_map.contents(), true,
      new XORFilter(
          new CryptoPP::StreamTransformationFilter(
              decryptor, new CryptoPP::Gunzip(new CryptoPP::StringSink(serialised_data_map))),
          xor_hash, crypto::SHA512::DIGESTSIZE));

  DataMap data_map;
  ParseDataMap(serialised_data_map, data_map);
  return data_map;
}

}  // unnamed namespace

crypto::CipherText EncryptDataMap(const Identity& parent_id, const Identity& this_id,
                                  const DataMap& data_map) {
  assert(parent_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(this_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));

  std::string serialised_data_map;
  SerialiseDataMap(data_map, serialised_data_map);

  ByteVector array_data_map(serialised_data_map.data(),
                            serialised_data_map.data() + serialised_data_map.size());

  size_t inputs_size(parent_id.string().size() + this_id.string().size());
  byte* enc_hash = new byte[crypto::SHA512::DIGESTSIZE];
  byte* xor_hash = new byte[crypto::SHA512::DIGESTSIZE];
  on_scope_exit([=] {
    delete[] enc_hash;
    delete[] xor_hash;
  });

  CryptoPP::SHA512().CalculateDigest(
      enc_hash, reinterpret_cast<const byte*>((parent_id.string() + this_id.string()).data()),
      inputs_size);
  CryptoPP::SHA512().CalculateDigest(
      xor_hash, reinterpret_cast<const byte*>((this_id.string() + parent_id.string()).data()),
      inputs_size);

  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(enc_hash, crypto::AES256_KeySize,
                                                          enc_hash + crypto::AES256_KeySize);

  protobuf::EncryptedDataMap protobuf_encrypted_data_map;
  protobuf_encrypted_data_map.set_data_map_encryption_version(
      static_cast<uint32_t>(kDataMapEncryptionVersion));
  CryptoPP::Gzip aes_filter(
      new CryptoPP::StreamTransformationFilter(
          encryptor,
          new XORFilter(new CryptoPP::StringSink(*protobuf_encrypted_data_map.mutable_contents()),
                        xor_hash, crypto::SHA512::DIGESTSIZE)),
      1);
  aes_filter.Put2(&array_data_map[0], array_data_map.size(), -1, true);

  assert(!protobuf_encrypted_data_map.contents().empty());

  return crypto::CipherText(NonEmptyString(protobuf_encrypted_data_map.SerializeAsString()));
}

DataMap DecryptDataMap(const Identity& parent_id, const Identity& this_id,
                       const std::string& encrypted_data_map) {
  assert(parent_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(this_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(!encrypted_data_map.empty());

  protobuf::EncryptedDataMap protobuf_encrypted_data_map;
  if (!protobuf_encrypted_data_map.ParseFromString(encrypted_data_map))
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));

  // Don't switch here - just assume most current encryption version is being used and try
  // progressively older versions until one works
  // try {
  //   return DecryptUsingVersion1(parent_id, this_id, protobuf_encrypted_data_map);
  // }
  // catch (const encrypt_error& error) {
  //   if (error.code() != MakeError(EncryptErrors::invalid_encryption_version).code())
  //     throw;
  // }

  return DecryptUsingVersion0(parent_id, this_id, protobuf_encrypted_data_map);
}

SelfEncryptor::SelfEncryptor(DataMap& data_map, DataBuffer<std::string>& buffer,
                             std::function<NonEmptyString(const std::string&)> get_from_store)
    : data_map_(data_map),
      kOriginalDataMap_(data_map),
      sequencer_(std::numeric_limits<uint64_t>::max()),  // could be that large
      chunks_(),
      read_cache_(new Cache(kQueueSize)),
      buffer_(buffer),
      get_from_store_(get_from_store),
      file_size_(0),
      data_mutex_() {
  if (data_map.self_encryption_version != EncryptionAlgorithm::kSelfEncryptionVersion0)
    BOOST_THROW_EXCEPTION(MakeError(EncryptErrors::invalid_encryption_version));
  if (!get_from_store) {
    LOG(kError) << "Need to have a non-null get_from_store functor.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  PopulateMainQueue();
}

SelfEncryptor::~SelfEncryptor() {
  SCOPED_PROFILE
  FlushAll();
}

bool SelfEncryptor::Write(const char* data, uint32_t length, uint64_t position) {
  SCOPED_PROFILE
  if (length == 0)
    return true;
  ByteVector to_be_written(data, data + length);  // copy - inefficient
  // read_cache_->Put(to_be_written, position);

  file_size_ = std::max(file_size_, length + position);
  PrepareWindow(length, position);
  for (const auto& entry : to_be_written)
    sequencer_[position++] = entry;  // direct as may be overwrite
  return true;
}

bool SelfEncryptor::Read(char* data, uint32_t length, uint64_t position) {
  SCOPED_PROFILE
  if (length == 0)
    return true;
  ByteVector temp;
  temp.reserve(length);
  if (read_cache_->Get(temp, length, position)) {
    memcpy(data, temp.data(), length);
    LOG(kInfo) << " Cache hit";
  } else {
    LOG(kInfo) << " Cache miss";
  }
  for (uint32_t i(0); i < length; ++i)
    data[i] = sequencer_[position + i];
  return true;
}

bool SelfEncryptor::Truncate(uint64_t position) {
  SCOPED_PROFILE
  file_size_ = position;
  return true;
}

bool SelfEncryptor::Flush() {
  return true;
}  // noop until we can tell if this is required when asked

//##############################Private######################
void SelfEncryptor::FlushAll() {
  SCOPED_PROFILE
  if (file_size_ < 3 * kMinChunkSize) {
    data_map_.content.clear();
    data_map_.content.reserve(file_size_);
    std::copy_n(std::begin(sequencer_), file_size_, std::begin(data_map_.content));
    return;
  }
  for (const auto& chunk : chunks_) {
    if (chunk.second == ChunkStatus::to_be_encrypted) {
      auto this_size(GetChunkSize(chunk.first));
      auto start(0);
      // either we are chunk 0 or we are not :-)
      if (this_size > GetChunkSize(GetPreviousChunkNumber(chunk.first)))
        start = 0;
      else
        start = this_size * chunk.first;
      ByteVector tmp(this_size);
      for (uint32_t i(start); i < this_size; ++i)
        tmp[i] = sequencer_[i];
      CalculatePreHash(chunk.first, &tmp.data()[0], this_size);
    }
  }
  for (auto& chunk : chunks_) {
    if (chunk.second == ChunkStatus::to_be_encrypted) {
      auto this_size(GetChunkSize(chunk.first));
      auto start(0);
      // either we are chunk 0 or we are not :-)
      if (this_size > GetChunkSize(GetPreviousChunkNumber(chunk.first)))
        start = 0;
      else
        start = this_size * chunk.first;
      ByteVector tmp(this_size);
      for (uint32_t i(start); i < this_size; ++i)
        tmp[i] = sequencer_[i];
      EncryptChunk(chunk.first, tmp, this_size);
      chunk.second = ChunkStatus::stored;
    }
  }
}

void SelfEncryptor::PopulateMainQueue() {
  SCOPED_PROFILE
  file_size_ = data_map_.size();
  // dump at least the first three chunks in sequencer
  uint64_t pos(0);
  if (!data_map_.chunks.empty()) {
    assert(data_map_.chunks.size() >= 3);
    for (auto i(0); i != 3; ++i) {
      ByteVector temp(DecryptChunk(i));
      for (const auto& t : temp)
        sequencer_.insert_element(pos++, t);
      chunks_.insert(std::make_pair(i, ChunkStatus::to_be_encrypted));
    }
  } else {
    for (const auto& t : data_map_.content)
      sequencer_.insert_element(pos++, t);
  }
}

void SelfEncryptor::PrepareWindow(uint32_t length, uint64_t position) {
  auto first_chunk(position / kMaxChunkSize);

  if (first_chunk < 3)  // we keep at least three chunks in sequencer at all times
    return;
  // we do not write around to chunk zeero here as we are writing forward
  auto last_chunk(first_chunk + (length / kMaxChunkSize));
  if (position % kMaxChunkSize != 0)
    ++last_chunk;


  for (; first_chunk <= last_chunk; ++first_chunk) {
    auto current_chunk_itr = chunks_.find(first_chunk);
    auto pos(first_chunk * kMaxChunkSize);
    if (current_chunk_itr != std::end(chunks_)) {
      if (current_chunk_itr->second == ChunkStatus::remote) {
        ByteVector tmp(DecryptChunk(first_chunk));
        for (const auto& t : tmp)
          sequencer_[pos++] = t;
        current_chunk_itr->second = ChunkStatus::to_be_encrypted;
      }
    } else {
      chunks_.insert(std::make_pair(first_chunk, ChunkStatus::to_be_encrypted));
    }
  }

  // get window plus next 2 chunks as they
  auto current_chunk_itr = chunks_.find(first_chunk);
  auto pos(first_chunk * kMaxChunkSize);
  if (current_chunk_itr != std::end(chunks_)) {
    if (current_chunk_itr->second == ChunkStatus::remote) {
      ByteVector tmp(DecryptChunk(first_chunk));
      for (const auto& t : tmp)
        sequencer_[pos++] = t;
      current_chunk_itr->second = ChunkStatus::to_be_encrypted;
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
  NonEmptyString content;
  try {
    content = get_from_store_(std::string(std::begin(data_map_.chunks[chunk_num].hash),
                                          std::end(data_map_.chunks[chunk_num].hash)));
  }
  catch (std::exception& e) {
    LOG(kInfo) << boost::current_exception_diagnostic_information(true);
    throw(e);
  }
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
  uint32_t n_1_chunk(GetPreviousChunkNumber(this_chunk_num));
  uint32_t n_2_chunk(GetPreviousChunkNumber(GetPreviousChunkNumber(this_chunk_num)));

  const ByteVector n_1_pre_hash(data_map_.chunks[n_1_chunk].pre_hash);
  const ByteVector n_2_pre_hash(data_map_.chunks[n_2_chunk].pre_hash);


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
  uint32_t num_chunks = static_cast<uint32_t>(data_map_.chunks.size());
  uint32_t n_1_chunk = (chunk_num + num_chunks - 1) % num_chunks;
  uint32_t n_2_chunk = (chunk_num + num_chunks - 2) % num_chunks;

  auto chunk_n_itr(chunks_.find(chunk_num));
  auto chunk_n_1_itr(chunks_.find(n_1_chunk));
  auto chunk_n_2_itr(chunks_.find(n_2_chunk));

  assert(chunk_n_itr != std::end(chunks_) && "this chunk chunkstatus not found");
  assert(chunk_n_1_itr != std::end(chunks_) && "chunk_n_1 chunkstatus not found");
  assert(chunk_n_2_itr != std::end(chunks_) && "chunk_n_2 chunkstatus not found");
  assert(chunk_n_1_itr->second != ChunkStatus::to_be_encrypted && "chunk_n_1 hash invalid");
  assert(chunk_n_2_itr->second != ChunkStatus::to_be_encrypted && "chunk_n_2 hash invalid");

  ByteVector pad(kPadSize);
  ByteVector key(crypto::AES256_KeySize);
  ByteVector iv(crypto::AES256_IVSize);
  GetPadIvKey(chunk_num, key, iv, pad);

  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(&key.data()[0], crypto::AES256_KeySize,
                                                          &iv.data()[0]);

  std::string chunk_content;
  chunk_content.reserve(length);
  CryptoPP::Gzip aes_filter(
      new CryptoPP::StreamTransformationFilter(
          encryptor, new XORFilter(new CryptoPP::StringSink(chunk_content), &pad.data()[0])),
      1);
  aes_filter.Put2(&data.data()[0], length, -1, true);

  ByteVector temp(std::begin(chunk_content), std::end(chunk_content));

  CalculatePreHash(chunk_num, &temp.data()[0], temp.size());

  try {
    std::lock_guard<std::mutex> guard(data_mutex_);
    buffer_.Store(std::string(std::begin(data_map_.chunks[chunk_num].hash),
                              std::end(data_map_.chunks[chunk_num].hash)),
                  NonEmptyString(chunk_content));
  }
  catch (std::exception& e) {
    LOG(kError) << e.what() << "Could not store "
                << Base64Substr(std::string(std::begin(data_map_.chunks[chunk_num].hash),
                                            std::begin(data_map_.chunks[chunk_num].hash)));
    LOG(kInfo) << boost::current_exception_diagnostic_information(true);
    throw(e);
  }
  chunk_n_itr->second = ChunkStatus::stored;
  {
    std::lock_guard<std::mutex> guard(data_mutex_);
    data_map_.chunks[chunk_num].size = length;  // keep pre-compressed length
    data_map_.chunks[chunk_num].storage_state = ChunkDetails::kPending;
  }
}

void SelfEncryptor::CalculatePreHash(uint32_t chunk_num, byte* data, uint32_t length) {
  SCOPED_PROFILE

  std::lock_guard<std::mutex> guard(data_mutex_);
  CryptoPP::SHA512().CalculateDigest(&data_map_.chunks[chunk_num].pre_hash.data()[0], data, length);
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
  if (file_size_ < 3U * kMaxChunkSize) {
    if (chunk < 3U)
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
  } else if (file_size_ <= 3 * kMinChunkSize) {
    return 3;
  } else {
    return file_size_ % kMaxChunkSize == 0 ? file_size_ / kMaxChunkSize
                                           : (file_size_ / kMaxChunkSize) + 1;
  }
}

std::pair<uint64_t, uint64_t> SelfEncryptor::GetStartEndPositons(uint32_t chunk_number) {
  auto start(0);
  if (chunk_number != 0)
    start = GetChunkSize(GetPreviousChunkNumber(chunk_number)) * (chunk_number - 1);
  return std::make_pair(start, start + GetChunkSize(chunk_number));
}

uint32_t SelfEncryptor::GetNextChunkNumber(uint32_t chunk_number) {
  return (GetNumChunks() + chunk_number + 1) % GetNumChunks();
}

uint32_t SelfEncryptor::GetPreviousChunkNumber(uint32_t chunk_number) {
  return (GetNumChunks() + chunk_number - 1) % GetNumChunks();
}

uint32_t SelfEncryptor::GetChunkNumber(uint64_t position) { return file_size_ / position; }

}  // namespace encrypt

}  // namespace maidsafe
