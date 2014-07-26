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

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/profiler.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/config.h"
#include "maidsafe/common/on_scope_exit.h"

#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/xor.h"
#include "maidsafe/encrypt/cache.h"
#include "maidsafe/encrypt/data_map.pb.h"
#include "maidsafe/encrypt/sequencer.h"

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
                             std::function<NonEmptyString(const std::string&)> get_from_store,
                             int /* num_procs */)
    : data_map_(data_map),
      kOriginalDataMap_(data_map),
      sequencer_(new Sequencer),
      read_cache_(new Cache(kQueueSize)),
      buffer_(buffer),
      main_encrypt_queue_(),
      get_from_store_(get_from_store),
      chunks_written_to_(),
      require_calculate_hash_(),
      file_size_(0),
      truncated_file_size_(0),
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
  if (truncated_file_size_ > file_size_)
    AppendNulls(truncated_file_size_);
  Flush();
}

bool SelfEncryptor::Write(const char* data, uint32_t length, uint64_t position) {
  SCOPED_PROFILE
  if (length == 0)
    return true;
  ByteVector to_be_written(data, data + length);  // copy - inefficient
  read_cache_->Put(to_be_written, position);

  // if ((position) < kQueueSize) {  // we can sone of this main_encrypt_queue_
  //   auto this_length(std::min(position + length, static_cast<uint64_t>(kQueueSize)));
  //   if (main_encrypt_queue_.size() < this_length)
  //     main_encrypt_queue_.resize(position + this_length);
  //   std::copy(std::begin(to_be_written), std::begin(to_be_written) + this_length,
  //             std::begin(main_encrypt_queue_) + position);
  //   if (this_length == length)
  //     return true;
  //   else {
  //     to_be_written.erase(std::begin(to_be_written), std::begin(to_be_written) + this_length);
  //     position += this_length;
  //   }
  // }
  PrepareWindow(length, position);
  sequencer_->Add(to_be_written, position);
  file_size_ = std::max(file_size_, length + position);
  return true;  //TODO(dirvine) did we actually write ??
}

void SelfEncryptor::PrepareWindow(uint32_t length, uint64_t position) {
  auto first_chunk(position / kMaxChunkSize);
  auto last_chunk(first_chunk + (length / kMaxChunkSize));
  if (position % kMaxChunkSize != 0)
    ++last_chunk;
  for (; first_chunk <= last_chunk; ++first_chunk) {
    if (!sequencer_->HasChunk(first_chunk) && data_map_.chunks.size() >= first_chunk)
      sequencer_->Add(DecryptChunk(first_chunk), first_chunk * kMaxChunkSize);
    chunks_written_to_.insert(first_chunk);
    require_calculate_hash_.insert(first_chunk);
  }
  require_calculate_hash_.insert(++last_chunk);
  require_calculate_hash_.insert(++last_chunk);
}

void SelfEncryptor::PopulateMainQueue() {
  SCOPED_PROFILE
  // dump at least the first three chunks in sequencer
  uint64_t pos(0);
  if (!data_map_.chunks.empty()) {
    assert(data_map_.chunks.size() >= 3);
    for (auto i(0); i != 3; ++i) {
      ByteVector temp(DecryptChunk(i));
      sequencer_->Add(DecryptChunk(i), pos);
      pos += data_map_.chunks.at(i).size;
    }
  } else {
      sequencer_->Add(data_map_.content, pos);
  }
}

ByteVector SelfEncryptor::DecryptChunk(uint32_t chunk_num) {
  SCOPED_PROFILE
  if (data_map_.chunks.size() <= chunk_num) {
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
  } catch (std::exception& e) {
    LOG(kInfo) << boost::current_exception_diagnostic_information(true);
    throw(e);
  }
  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(&key.data()[0], crypto::AES256_KeySize, &iv.data()[0]);
  CryptoPP::StringSource filter(
      content.string(), true,
      new XORFilter(new CryptoPP::StreamTransformationFilter(
                        decryptor, new CryptoPP::Gunzip(new CryptoPP::MessageQueue)),
                    &pad.data()[0]));
  filter.Get(&data.data()[0], length);
  return data;
}

void SelfEncryptor::GetPadIvKey(uint32_t this_chunk_num, ByteVector& key, ByteVector& iv, ByteVector& pad) {
  SCOPED_PROFILE
  uint32_t num_chunks = static_cast<uint32_t>(data_map_.chunks.size());
  uint32_t n_1_chunk = (this_chunk_num + num_chunks - 1) % num_chunks;
  uint32_t n_2_chunk = (this_chunk_num + num_chunks - 2) % num_chunks;

  const ByteVector n_1_pre_hash = data_map_.chunks[n_1_chunk].pre_hash;
  const ByteVector n_2_pre_hash = data_map_.chunks[n_2_chunk].pre_hash;


  std::copy_n(std::begin(n_2_pre_hash), crypto::AES256_KeySize, std::begin(key));
  memcpy(iv, n_2_pre_hash + crypto::AES256_KeySize, crypto::AES256_IVSize);
  memcpy(pad, n_1_pre_hash, crypto::SHA512::DIGESTSIZE);
  memcpy(pad + crypto::SHA512::DIGESTSIZE, &data_map_.chunks[this_chunk_num].pre_hash[0],
         crypto::SHA512::DIGESTSIZE);
  uint32_t hash_offset(crypto::AES256_KeySize + crypto::AES256_IVSize);
  memcpy(pad + (2 * crypto::SHA512::DIGESTSIZE), n_2_pre_hash + hash_offset,
         crypto::SHA512::DIGESTSIZE - hash_offset);
}


void SelfEncryptor::EncryptChunk(uint32_t chunk_num, byte* data, uint32_t length) {
  SCOPED_PROFILE
  assert(data_map_.chunks.size() > chunk_num);
  byte* pad(new byte[kPadSize]);
  byte* key(new byte[crypto::AES256_KeySize]);
  byte* iv(new byte[crypto::AES256_IVSize]);
  byte* post_hash(new byte[crypto::SHA512::DIGESTSIZE]);
  on_scope_exit([=] {
    delete[] key;
    delete[] iv;
    delete[] pad;
    delete[] post_hash;
  });

  GetPadIvKey(chunk_num, key, iv, pad);
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(key, crypto::AES256_KeySize, iv);

  std::string chunk_content;
  chunk_content.reserve(length);
  CryptoPP::Gzip aes_filter(
      new CryptoPP::StreamTransformationFilter(
          encryptor, new XORFilter(new CryptoPP::StringSink(chunk_content), pad)),
      1);
  aes_filter.Put2(data, length, -1, true);

  CryptoPP::SHA512().CalculateDigest(post_hash, reinterpret_cast<const byte*>(chunk_content.data()),
                                     chunk_content.size());
  ByteVector tmp(post_hash, post_hash + crypto::SHA512::DIGESTSIZE);
  data_map_.chunks[chunk_num].hash = tmp;

  data_map_.chunks[chunk_num].storage_state = ChunkDetails::kPending;
  try {
    buffer_.Store(std::string(std::begin(data_map_.chunks[chunk_num].hash),
                              std::begin(data_map_.chunks[chunk_num].hash)),
                  NonEmptyString(chunk_content));
  } catch (std::exception& e) {
    LOG(kError) << e.what() << "Could not store "
                << Base64Substr(std::string(std::begin(data_map_.chunks[chunk_num].hash),
                                            std::begin(data_map_.chunks[chunk_num].hash)));
    LOG(kInfo) << boost::current_exception_diagnostic_information(true);
    throw(e);
  }
  auto itr = chunks_written_to_.find(chunk_num);
  if (itr != std::end(chunks_written_to_))
    chunks_written_to_.erase(itr);
  else
    BOOST_THROW_EXCEPTION(EncryptErrors::failed_to_write);

  data_map_.chunks[chunk_num].size = length;  // keep pre-compressed length
}

void SelfEncryptor::CalculatePreHash(uint32_t chunk_num, byte* data, uint32_t length) {
  SCOPED_PROFILE

  std::lock_guard<std::mutex> guard(data_mutex_);
  CryptoPP::SHA512().CalculateDigest(&data_map_.chunks[chunk_num].pre_hash.data()[0], data, length);
}

bool SelfEncryptor::Flush() {
  SCOPED_PROFILE
  TO BE DONE if (main_encrypt_queue_.size() < 3 * kMinChunkSize) {
    data_map_.content.clear();
    std::copy(std::begin(main_encrypt_queue_), std::begin(main_encrypt_queue_) + file_size_,
              std::begin(data_map_.content));
    data_map_.chunks.clear();
    return true;
  }
  else {
    data_map_.content.clear();
  }
  From here just rewrite the chunks written to !(includes new data) return true;
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
  uint32_t copied(0);
  if ((length + position) <= kQueueSize && main_encrypt_queue_.size() <= (length + position)) {
    copied = std::min(length + position, main_encrypt_queue_.size());
    memcpy(data, &main_encrypt_queue_.data()[position], copied);
    if (copied == length)
      return true;
  }
  Try sequencer get chunk / decrypt add to read_cache and reread read cache

      return true;
}



bool SelfEncryptor::Truncate(uint64_t position) {
  SCOPED_PROFILE
  if (position > file_size_)
    return TruncateUp(position);
  else if (position < file_size_)
    return TruncateDown(position);
  return true;
}

bool SelfEncryptor::TruncateDown(uint64_t position) {
  SCOPED_PROFILE
  // truncate queue, sequencer, and chunks 0 & 1.

  if (position < main_encrypt_queue_.size()) {
    main_encrypt_queue_.resize(position);
    sequencer_->Clear();
  }
  sequencer_->Truncate(position);
  remove all chunks_written_to above this point
      // TODO(Fraser#5#): 2011-10-18 - Confirm these memset's are really required
      // if (position < kMaxChunkSize) {
      //   uint32_t overwite_size(kMaxChunkSize - static_cast<uint32_t>(position));
      //   uint32_t overwrite_position(static_cast<uint32_t>(position));
      //   memset(chunk0_raw_ + overwrite_position, 0, overwite_size);
      //   memset(chunk1_raw_, 0, kMaxChunkSize);
      //   if (data_map_.chunks.size() > 1) {
      //     data_map_.chunks[0].pre_hash_state = ChunkDetails::kOutdated;
      //     data_map_.chunks[1].pre_hash_state = ChunkDetails::kOutdated;
      //   }
      // } else if (position < 2 * kMaxChunkSize) {
      //   uint32_t overwite_size((2 * kMaxChunkSize) - static_cast<uint32_t>(position));
      //   uint32_t overwrite_position(static_cast<uint32_t>(position) - kMaxChunkSize);
      //   memset(chunk1_raw_ + overwrite_position, 0, overwite_size);
      //   if (data_map_.chunks.size() > 1)
      //     data_map_.chunks[1].pre_hash_state = ChunkDetails::kOutdated;
      // }
      //
      file_size_ = position;
  CalculateSizes(true);
  return true;
}

bool SelfEncryptor::TruncateUp(uint64_t position) {
  SCOPED_PROFILE
  //   if (file_size_ < kDefaultByteVector Size_) {
  //     uint64_t target_position(std::min(position, static_cast<uint64_t>(kDefaultByteVector
  //     Size_)));
  //     if (!AppendNulls(target_position)) {
  //       LOG(kError) << "Failed to append nulls to beyond end of Chunk 1";
  //       return false;
  //     }
  //     if (position <= kDefaultByteVector Size_)
  //       return true;
  //   }
  //   truncated_file_size_ = position;
  //   return true;
  // }
  //
  // bool SelfEncryptor::AppendNulls(uint64_t position) {
  //   SCOPED_PROFILE
  //   std::unique_ptr<char[]> tail_data(new char[kDefaultByteVector Size_]);
  //   memset(tail_data.get(), 0, kDefaultByteVector Size_);
  //   uint64_t current_position(file_size_);
  //   uint64_t length(position - current_position);
  //   while (length > kDefaultByteVector Size_) {
  //     if (!Write(tail_data.get(), kDefaultByteVector Size_, current_position))
  //       return false;
  //     current_position += kDefaultByteVector Size_;
  //     length -= kDefaultByteVector Size_;
  //   }
  //   return Write(tail_data.get(), static_cast<uint32_t>(length), current_position);
}

void SelfEncryptor::DeleteChunk(uint32_t chunk_num) {
  SCOPED_PROFILE
  std::lock_guard<std::mutex> data_guard(data_mutex_);
  if (data_map_.chunks[chunk_num].hash.empty())
    return;

  try {
    buffer_.Delete(data_map_.chunks[chunk_num].hash);
  } catch (std::exception& e) {
    LOG(kInfo) << boost::current_exception_diagnostic_information(true);
    throw(e);
  }
}

}  // namespace encrypt

}  // namespace maidsafe
