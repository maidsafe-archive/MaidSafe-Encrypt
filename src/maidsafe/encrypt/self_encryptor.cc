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

#ifdef MAIDSAFE_OMP_ENABLED
#include <omp.h>
#endif

#include <algorithm>
#include <limits>
#include <set>
#include <tuple>
#include <utility>

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

#include "maidsafe/common/log.h"
#include "maidsafe/common/profiler.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/sequencer.h"

namespace maidsafe {

namespace encrypt {

namespace {

const size_t kPadSize((3 * crypto::SHA512::DIGESTSIZE) - crypto::AES256_KeySize -
                      crypto::AES256_IVSize);

class XORFilter : public CryptoPP::Bufferless<CryptoPP::Filter> {
 public:
  XORFilter(CryptoPP::BufferedTransformation* attachment, byte* pad,
            size_t pad_size = kPadSize)
      : pad_(pad), count_(0), kPadSize_(pad_size) {
    CryptoPP::Filter::Detach(attachment);
  }
  size_t Put2(const byte* in_string, size_t length, int message_end, bool blocking) override {
    if (length == 0) {
      return AttachedTransformation()->Put2(in_string, length, message_end, blocking);
    }
    std::unique_ptr<byte[]> buffer(new byte[length]);

    size_t i(0);
#ifdef MAIDSAFE_OMP_ENABLED
// #  pragma omp parallel for shared(buffer, in_string) private(i)
#endif
    for (; i != length; ++i) {
      buffer[i] = in_string[i] ^ pad_[count_ % kPadSize_];
      ++count_;
    }

    return AttachedTransformation()->Put2(buffer.get(), length, message_end, blocking);
  }
  bool IsolatedFlush(bool, bool) override { return false; }

 private:
  XORFilter& operator=(const XORFilter&);
  XORFilter(const XORFilter&);

  byte* pad_;
  size_t count_;
  const size_t kPadSize_;
};

/*
void DebugPrint(bool encrypting,
                uint32_t chunk_num,
                ByteArray pad,
                ByteArray key,
                ByteArray iv,
                const byte* plain_data,
                uint32_t plain_data_length,
                const std::string &encrypted_data) {
  std::string pad_str(Base64Substr(std::string(
      reinterpret_cast<char*>(pad.get()), detail::kPadSize)));
  std::string key_str(Base64Substr(std::string(
      reinterpret_cast<char*>(key.get()), crypto::AES256_KeySize)));
  std::string iv_str(Base64Substr(std::string(
      reinterpret_cast<char*>(iv.get()), crypto::AES256_IVSize)));
  std::string plain(Base64Substr(crypto::Hash<crypto::SHA512>(std::string(
      reinterpret_cast<const char*>(plain_data), plain_data_length))));
  std::string encrypted(Base64Substr(crypto::Hash<crypto::SHA512>(
      encrypted_data)));
  LOG(kInfo) << (encrypting ? "\nEncrypt chunk " : "\nDecrypt chunk ")
             << chunk_num << "\nPad: " << pad_str << "   Key: " << key_str
             << "   IV: " << iv_str << "   Plain: " << plain << "   Encrypted: "
             << encrypted;
}
*/

}  // unnamed namespace

crypto::CipherText EncryptDataMap(const Identity& parent_id, const Identity& this_id,
                                  const DataMap& data_map) {
  assert(parent_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(this_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));

  std::string serialised_data_map, encrypted_data_map;
  SerialiseDataMap(data_map, serialised_data_map);

  ByteArray array_data_map(GetNewByteArray(static_cast<uint32_t>(serialised_data_map.size())));
  uint32_t copied(MemCopy(array_data_map, 0, serialised_data_map.c_str(), Size(array_data_map)));
  assert(Size(array_data_map) == copied);

  size_t inputs_size(parent_id.string().size() + this_id.string().size());
  ByteArray enc_hash(GetNewByteArray(crypto::SHA512::DIGESTSIZE)),
      xor_hash(GetNewByteArray(crypto::SHA512::DIGESTSIZE));
  CryptoPP::SHA512().CalculateDigest(
      enc_hash.get(), reinterpret_cast<const byte*>((parent_id.string() + this_id.string()).data()),
      inputs_size);
  CryptoPP::SHA512().CalculateDigest(
      xor_hash.get(), reinterpret_cast<const byte*>((this_id.string() + parent_id.string()).data()),
      inputs_size);

  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(enc_hash.get(), crypto::AES256_KeySize,
                                                          enc_hash.get() + crypto::AES256_KeySize);

  encrypted_data_map.reserve(copied);
  CryptoPP::Gzip aes_filter(
      new CryptoPP::StreamTransformationFilter(
          encryptor, new XORFilter(new CryptoPP::StringSink(encrypted_data_map), xor_hash.get(),
                                   crypto::SHA512::DIGESTSIZE)),
      6);
  aes_filter.Put2(array_data_map.get(), copied, -1, true);

  assert(!encrypted_data_map.empty());

  return crypto::CipherText(encrypted_data_map);
}

DataMap DecryptDataMap(const Identity& parent_id, const Identity& this_id,
                       const std::string& encrypted_data_map) {
  assert(parent_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(this_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(!encrypted_data_map.empty());

  std::string serialised_data_map;
  size_t inputs_size(parent_id.string().size() + this_id.string().size());
  ByteArray enc_hash(GetNewByteArray(crypto::SHA512::DIGESTSIZE)),
      xor_hash(GetNewByteArray(crypto::SHA512::DIGESTSIZE));
  CryptoPP::SHA512().CalculateDigest(
      enc_hash.get(), reinterpret_cast<const byte*>((parent_id.string() + this_id.string()).data()),
      inputs_size);
  CryptoPP::SHA512().CalculateDigest(
      xor_hash.get(), reinterpret_cast<const byte*>((this_id.string() + parent_id.string()).data()),
      inputs_size);

  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(enc_hash.get(), crypto::AES256_KeySize,
                                                          enc_hash.get() + crypto::AES256_KeySize);

  CryptoPP::StringSource filter(
      encrypted_data_map, true,
      new XORFilter(
          new CryptoPP::StreamTransformationFilter(
              decryptor, new CryptoPP::Gunzip(new CryptoPP::StringSink(serialised_data_map))),
          xor_hash.get(), crypto::SHA512::DIGESTSIZE));

  DataMap data_map;
  ParseDataMap(serialised_data_map, data_map);
  return data_map;
}

SelfEncryptor::SelfEncryptor(DataMap& data_map, data_store::DataBuffer<std::string>& buffer,
                             std::function<NonEmptyString(const std::string&)> get_from_store,
                             int num_procs)
    : data_map_(data_map),
      kOriginalDataMap_(data_map),
      sequencer_(new Sequencer),
      kDefaultByteArraySize_(num_procs == 0 ? kDefaultChunkSize * Concurrency()
                                            : kDefaultChunkSize * num_procs),
      file_size_(0),
      last_chunk_position_(0),
      truncated_file_size_(0),
      normal_chunk_size_(0),
      main_encrypt_queue_(),
      queue_start_position_(2 * kDefaultChunkSize),
      kQueueCapacity_(kDefaultByteArraySize_ + kDefaultChunkSize),
      retrievable_from_queue_(0),
      chunk0_raw_(),
      chunk1_raw_(),
      buffer_(buffer),
      get_from_store_(get_from_store),
      current_position_(0),
      prepared_for_writing_(false),
      flushed_(true),
      read_cache_(),
      cache_start_position_(0),
      prepared_for_reading_(),
      read_buffer_(),
      buffer_activated_(false),
      buffer_length_(0),
      last_read_position_(0),
      kMaxBufferSize_(20 * kDefaultByteArraySize_),
      data_mutex_() {
  if (!get_from_store) {
    LOG(kError) << "Need to have a non-null get_from_store functor.";
    ThrowError(CommonErrors::invalid_parameter);
  }
  if (data_map.chunks.empty()) {
    file_size_ = data_map.content.size();
    last_chunk_position_ = std::numeric_limits<uint64_t>::max();
    normal_chunk_size_ = 0;
  } else {
    auto penultimate(--data_map.chunks.end());
    for (auto it(data_map.chunks.begin()); it != penultimate; ++it)
      file_size_ += (*it).size;
    last_chunk_position_ = file_size_;
    file_size_ += (*data_map.chunks.rbegin()).size;
    normal_chunk_size_ = (*data_map.chunks.begin()).size;
  }
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

  if (PrepareToWrite(length, position) != kSuccess) {
    LOG(kError) << "Failed to write " << length << " bytes at position " << position;
    return false;
  }
  PutToReadCache(data, length, position);
  PutToReadBuffer(data, length, position);

  uint32_t write_length(length);
  uint64_t write_position(position);
  uint32_t written = PutToInitialChunks(data, &write_length, &write_position);
  uint32_t data_offset(0), queue_offset(0);
  bool data_in_queue =
      GetDataOffsetForEnqueuing(write_length, write_position, &data_offset, &queue_offset);
  if (data_in_queue) {
    uint32_t seq_length(write_length);
    if (data_offset != 0 && GetLengthForSequencer(write_position, &seq_length)) {
      if (sequencer_->Add(data + written, seq_length, write_position) != kSuccess) {
        LOG(kError) << "Failed to write " << length << " bytes at position " << position;
        return false;
      }
    }
    assert(data_map_.chunks.size() >= 2);
    bool modified(false);
    CalculatePreHash(0, chunk0_raw_.get(), normal_chunk_size_, &modified);
    if (modified)
      data_map_.chunks[0].size = 0;
    CalculatePreHash(1, chunk1_raw_.get(), normal_chunk_size_, &modified);
    if (modified)
      data_map_.chunks[1].size = 0;
    if (PutToEncryptQueue(data + written, write_length, data_offset, queue_offset) != kSuccess) {
      LOG(kError) << "Failed to write " << length << " bytes at position " << position;
      return false;
    }
  } else if (GetLengthForSequencer(write_position, &write_length)) {
    if (sequencer_->Add(data + written, write_length, write_position) != kSuccess) {
      LOG(kError) << "Failed to write " << length << " bytes at position " << position;
      return false;
    }
  }

  std::pair<uint64_t, ByteArray> next_seq_block(sequencer_->PeekBeyond(queue_start_position_));
  while (next_seq_block.first < queue_start_position_ + kQueueCapacity_) {
    ByteArray extra(sequencer_->Get(next_seq_block.first));
    assert(extra);
    uint32_t extra_offset(0);
    if (next_seq_block.first < current_position_) {
      extra_offset = static_cast<uint32_t>(current_position_ - next_seq_block.first);
    }
    if (extra_offset < Size(extra)) {
      uint32_t queue_offset(static_cast<uint32_t>(
          std::max(current_position_, next_seq_block.first) - queue_start_position_));
      if (kSuccess != PutToEncryptQueue(reinterpret_cast<char*>(extra.get()), Size(extra),
                                        extra_offset, queue_offset)) {
        LOG(kError) << "Failed to write " << length << " bytes at position " << position;
        return false;
      }
    }
    next_seq_block = sequencer_->PeekBeyond(current_position_);
  }

  return true;
}

int SelfEncryptor::PrepareToWrite(uint32_t length, uint64_t position) {
  SCOPED_PROFILE
  if (position + length > file_size_) {
    file_size_ = position + length;
    CalculateSizes(false);
  }

  flushed_ = false;

  if (prepared_for_writing_)
    return kSuccess;

  if (!main_encrypt_queue_) {
    main_encrypt_queue_ = GetNewByteArray(kQueueCapacity_);
    if (position > queue_start_position_ && last_chunk_position_ > 2 * kDefaultChunkSize) {
      queue_start_position_ =
          std::min(last_chunk_position_, (position / kDefaultChunkSize) * kDefaultChunkSize);
      assert(queue_start_position_ % kDefaultChunkSize == 0);
      current_position_ = queue_start_position_;
    }
  }

  if (!chunk0_raw_)
    chunk0_raw_ = GetNewByteArray(kDefaultChunkSize);

  if (!chunk1_raw_)
    chunk1_raw_ = GetNewByteArray(kDefaultChunkSize);

  if (!data_map_.chunks.empty()) {
    assert(data_map_.chunks.empty() || data_map_.chunks.size() >= 3);
    ByteArray temp(GetNewByteArray(kDefaultChunkSize + 1));
    uint32_t chunks_to_decrypt(std::min((kQueueCapacity_ / kDefaultChunkSize) + 2,
                                        static_cast<uint32_t>(data_map_.chunks.size())));
    bool consumed_whole_chunk(true);
    uint64_t pos(0);
    uint32_t copied_to_queue(0);
    for (uint32_t i(0); i != chunks_to_decrypt; ++i) {
      int result(DecryptChunk(i, temp.get()));
      if (result != kSuccess) {
        LOG(kError) << "Failed to prepare for writing.";
        return result;
      }
      uint32_t len(data_map_.chunks[i].size);
      uint32_t written = PutToInitialChunks(reinterpret_cast<char*>(temp.get()), &len, &pos);
      consumed_whole_chunk = (len == 0);

      if (!consumed_whole_chunk) {
        uint32_t copied = MemCopy(main_encrypt_queue_, copied_to_queue, temp.get() + written, len);
        assert(len == copied);
        copied_to_queue += copied;
      }
    }
    data_map_.chunks[0].size = 0;
    data_map_.chunks[0].pre_hash_state = ChunkDetails::kOk;
    data_map_.chunks[1].size = 0;
    data_map_.chunks[1].pre_hash_state = ChunkDetails::kOk;
    if (chunks_to_decrypt == 3) {
      current_position_ = queue_start_position_ + copied_to_queue;
      retrievable_from_queue_ = copied_to_queue;
      data_map_.chunks[2].pre_hash_state = ChunkDetails::kOutdated;
    }
  } else {
    uint32_t len(static_cast<uint32_t>(data_map_.content.size()));
    uint64_t pos(0);
    PutToInitialChunks(data_map_.content.data(), &len, &pos);
    if (data_map_.chunks[0].pre_hash_state == ChunkDetails::kOutdated)
      data_map_.chunks[0].pre_hash_state = ChunkDetails::kOk;
    if (data_map_.chunks[1].pre_hash_state == ChunkDetails::kOutdated)
      data_map_.chunks[1].pre_hash_state = ChunkDetails::kOk;
    data_map_.content.clear();
  }

  prepared_for_writing_ = true;
  return kSuccess;
}

void SelfEncryptor::PutToReadCache(const char* data, uint32_t length, uint64_t position) {
  SCOPED_PROFILE
  if (!prepared_for_reading_)
    return;
  if (position < cache_start_position_ + kDefaultByteArraySize_ &&
      position + length >= cache_start_position_) {
    uint32_t data_offset(0), cache_offset(0);
    uint32_t copy_size(length);
    if (position < cache_start_position_) {
      data_offset = static_cast<uint32_t>(cache_start_position_ - position);
      copy_size -= data_offset;
    } else {
      cache_offset = static_cast<uint32_t>(position - cache_start_position_);
    }
    copy_size = std::min(copy_size, kDefaultByteArraySize_ - cache_offset);
    memcpy(read_cache_.get() + cache_offset, data + data_offset, copy_size);
  }
}

void SelfEncryptor::PutToReadBuffer(const char* data, uint32_t length, uint64_t position) {
  SCOPED_PROFILE
  if (!buffer_activated_)
    return;
  if (position < buffer_length_) {
    uint64_t copy_size(buffer_length_ - position);
    if (copy_size > length)
      copy_size = length;
    memcpy(read_buffer_.get() + position, data, static_cast<uint32_t>(copy_size));
  }
}

void SelfEncryptor::CalculateSizes(bool force) {
  SCOPED_PROFILE
  if (normal_chunk_size_ != kDefaultChunkSize || force) {
    if (file_size_ < 3 * kMinChunkSize) {
      normal_chunk_size_ = 0;
      last_chunk_position_ = std::numeric_limits<uint64_t>::max();
      return;
    } else if (file_size_ < 3 * kDefaultChunkSize) {
      normal_chunk_size_ = static_cast<uint32_t>(file_size_) / 3;
      last_chunk_position_ = 2 * normal_chunk_size_;
      return;
    }
    normal_chunk_size_ = kDefaultChunkSize;
  }

  assert(kDefaultChunkSize > 0);
  uint64_t chunk_count_excluding_last = file_size_ / kDefaultChunkSize;

  if (file_size_ % kDefaultChunkSize < kMinChunkSize)
    --chunk_count_excluding_last;
  last_chunk_position_ = chunk_count_excluding_last * kDefaultChunkSize;
}

uint32_t SelfEncryptor::PutToInitialChunks(const char* data, uint32_t* length, uint64_t* position) {
  SCOPED_PROFILE
  if (data_map_.chunks.size() < 2)
    data_map_.chunks.resize(2);
  uint32_t copy_length0(0);
  // Handle Chunk 0
  if (*position < kDefaultChunkSize) {
    copy_length0 = std::min(*length, kDefaultChunkSize - static_cast<uint32_t>(*position));
    uint32_t copied = MemCopy(chunk0_raw_, static_cast<uint32_t>(*position), data, copy_length0);
    assert(copy_length0 == copied);
    static_cast<void>(copied);
    // Don't decrease current_position_ (could be a rewrite - this shouldn't
    // change current_position_).
    if (current_position_ < *position + copy_length0)
      current_position_ = *position + copy_length0;
    *length -= copy_length0;
    *position += copy_length0;
    if (copy_length0 != 0)
      data_map_.chunks[0].pre_hash_state = ChunkDetails::kOutdated;
  }

  // Handle Chunk 1
  uint32_t copy_length1(0);
  if ((*position >= kDefaultChunkSize) && (*position < 2 * kDefaultChunkSize)) {
    copy_length1 = std::min(*length, (2 * kDefaultChunkSize) - static_cast<uint32_t>(*position));
    uint32_t copied = MemCopy(chunk1_raw_, static_cast<uint32_t>(*position - kDefaultChunkSize),
                              data + copy_length0, copy_length1);
    assert(copy_length1 == copied);
    static_cast<void>(copied);
    // Don't decrease current_position_ (could be a rewrite - this shouldn't
    // change current_position_).
    if (current_position_ < *position + copy_length1)
      current_position_ = *position + copy_length1;
    *length -= copy_length1;
    *position += copy_length1;
    if (copy_length1 != 0)
      data_map_.chunks[1].pre_hash_state = ChunkDetails::kOutdated;
  }

  return copy_length0 + copy_length1;
}

bool SelfEncryptor::GetDataOffsetForEnqueuing(uint32_t length, uint64_t position,
                                              uint32_t* data_offset, uint32_t* queue_offset) {
  SCOPED_PROFILE
  // Cover most common case first
  if (position == current_position_) {
    *data_offset = 0;
    *queue_offset = static_cast<uint32_t>(current_position_ - queue_start_position_);
    return current_position_ >= queue_start_position_;
  }

  if (length == 0)
    return false;

  if (position < queue_start_position_) {
    // We don't care if this overflows as in this case we return false
    *data_offset = static_cast<uint32_t>(queue_start_position_ - position);
    *queue_offset = 0;
    return (position + length > queue_start_position_);
  } else if (position < queue_start_position_ + kQueueCapacity_) {
    *data_offset = 0;
    *queue_offset = static_cast<uint32_t>(position - queue_start_position_);
    return true;
  }
  return false;
}

int SelfEncryptor::PutToEncryptQueue(const char* data, uint32_t length, uint32_t data_offset,
                                     uint32_t queue_offset) {
  SCOPED_PROFILE
  length -= data_offset;
  uint32_t copy_length = std::min(length, kQueueCapacity_ - queue_offset);
  uint32_t copied(0);
  while (copy_length != 0) {
    copied = MemCopy(main_encrypt_queue_, queue_offset, data + data_offset, copy_length);
    assert(copy_length == copied);
    current_position_ = std::max(queue_start_position_ + copied + queue_offset, current_position_);
    retrievable_from_queue_ = static_cast<uint32_t>(current_position_ - queue_start_position_);
    if (retrievable_from_queue_ == kQueueCapacity_) {
      int result(ProcessMainQueue());
      if (result != kSuccess)
        return result;
      queue_offset = retrievable_from_queue_;
    } else {
      queue_offset += copy_length;
    }
    data_offset += copy_length;
    length -= copy_length;
    copy_length = std::min(length, kDefaultByteArraySize_);
  }
  return kSuccess;
}

bool SelfEncryptor::GetLengthForSequencer(uint64_t position, uint32_t* length) {
  SCOPED_PROFILE
  if (*length == 0)
    return false;
  assert(position >= 2 * kDefaultChunkSize);
  if (position + *length < queue_start_position_) {
    return true;
  } else if (position < queue_start_position_) {
    *length = static_cast<uint32_t>(
        std::min(static_cast<uint64_t>(*length), queue_start_position_ - position));
    return true;
  }
  return (position > queue_start_position_ + retrievable_from_queue_);
}

int SelfEncryptor::DecryptChunk(uint32_t chunk_num, byte* data) {
  SCOPED_PROFILE
  if (data_map_.chunks.size() <= chunk_num) {
    LOG(kWarning) << "Can't decrypt chunk " << chunk_num << " of " << data_map_.chunks.size();
    return kInvalidChunkIndex;
  }

  uint32_t length = data_map_.chunks[chunk_num].size;
  if (length == 0) {  // Chunk hasn't been encrypted yet
    memset(data, 0, normal_chunk_size_);
    return kSuccess;
  }

  ByteArray pad(GetNewByteArray(kPadSize));
  ByteArray key(GetNewByteArray(crypto::AES256_KeySize));
  ByteArray iv(GetNewByteArray(crypto::AES256_IVSize));
  GetPadIvKey(chunk_num, key, iv, pad, false);
  NonEmptyString content;
  try {
    content = buffer_.Get(data_map_.chunks[chunk_num].hash);
  }
  catch (...) {
    LOG(kInfo) << "Failed to get data for " << HexSubstr(data_map_.chunks[chunk_num].hash)
                << " from buffer, trying functor.";
    try {
      content = get_from_store_(data_map_.chunks[chunk_num].hash);
    }
    catch(const std::exception& e) {
      LOG(kError) << "Failed to get data for " << HexSubstr(data_map_.chunks[chunk_num].hash)
                  << " - " << e.what();
      return kMissingChunk;
    }
  }

  if (content.string().empty()) {
    LOG(kError) << "Could not find chunk number " << chunk_num << ", hash "
                << Base64Substr(data_map_.chunks[chunk_num].hash);
    return kMissingChunk;
  }

  try {
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(key.get(), crypto::AES256_KeySize,
                                                            iv.get());
    CryptoPP::StringSource filter(
        content.string(), true, new XORFilter(
            new CryptoPP::StreamTransformationFilter(
                decryptor,
                new CryptoPP::Gunzip(new CryptoPP::MessageQueue)),
            pad.get()));
    filter.Get(data, length);
  }
  catch (const std::exception& e) {
    LOG(kError) << e.what();
    return kDecryptionException;
  }
//  DebugPrint(false, chunk_num, pad, key, iv, data, length, content);

  return kSuccess;
}

void SelfEncryptor::GetPadIvKey(uint32_t this_chunk_num, ByteArray key, ByteArray iv, ByteArray pad,
                                bool writing) {
  SCOPED_PROFILE
  uint32_t num_chunks = static_cast<uint32_t>(data_map_.chunks.size());
  uint32_t n_1_chunk = (this_chunk_num + num_chunks - 1) % num_chunks;
  uint32_t n_2_chunk = (this_chunk_num + num_chunks - 2) % num_chunks;

  const byte* n_1_pre_hash = data_map_.chunks[this_chunk_num].old_n1_pre_hash.get();
  const byte* n_2_pre_hash = data_map_.chunks[this_chunk_num].old_n2_pre_hash.get();
  if (writing) {
    if (!n_1_pre_hash) {
      assert(!n_2_pre_hash);
      data_map_.chunks[this_chunk_num].old_n1_pre_hash.reset(new byte[crypto::SHA512::DIGESTSIZE]);
      data_map_.chunks[this_chunk_num].old_n2_pre_hash.reset(new byte[crypto::SHA512::DIGESTSIZE]);
    }
    n_1_pre_hash = &data_map_.chunks[n_1_chunk].pre_hash[0];
    n_2_pre_hash = &data_map_.chunks[n_2_chunk].pre_hash[0];
    memcpy(data_map_.chunks[this_chunk_num].old_n1_pre_hash.get(), n_1_pre_hash,
           crypto::SHA512::DIGESTSIZE);
    memcpy(data_map_.chunks[this_chunk_num].old_n2_pre_hash.get(), n_2_pre_hash,
           crypto::SHA512::DIGESTSIZE);
  } else {
    if (!n_1_pre_hash) {
      assert(!n_2_pre_hash);
      n_1_pre_hash = &data_map_.chunks[n_1_chunk].pre_hash[0];
      n_2_pre_hash = &data_map_.chunks[n_2_chunk].pre_hash[0];
    }
  }

  uint32_t copied = MemCopy(key, 0, n_2_pre_hash, crypto::AES256_KeySize);
  assert(crypto::AES256_KeySize == copied);
  copied = MemCopy(iv, 0, n_2_pre_hash + crypto::AES256_KeySize, crypto::AES256_IVSize);
  assert(crypto::AES256_IVSize == copied);
  copied = MemCopy(pad, 0, n_1_pre_hash, crypto::SHA512::DIGESTSIZE);
  assert(static_cast<uint32_t>(crypto::SHA512::DIGESTSIZE) == copied);
  copied = MemCopy(pad, crypto::SHA512::DIGESTSIZE, &data_map_.chunks[this_chunk_num].pre_hash[0],
                   crypto::SHA512::DIGESTSIZE);
  assert(static_cast<uint32_t>(crypto::SHA512::DIGESTSIZE) == copied);
  uint32_t hash_offset(crypto::AES256_KeySize + crypto::AES256_IVSize);
  copied = MemCopy(pad, (2 * crypto::SHA512::DIGESTSIZE), n_2_pre_hash + hash_offset,
                   crypto::SHA512::DIGESTSIZE - hash_offset);
  assert(crypto::SHA512::DIGESTSIZE - hash_offset == copied);
  static_cast<void>(copied);
}

int SelfEncryptor::ProcessMainQueue() {
  SCOPED_PROFILE
  if (retrievable_from_queue_ < kDefaultChunkSize)
    return kSuccess;

  uint32_t chunks_to_process(retrievable_from_queue_ / kDefaultChunkSize);
  if ((retrievable_from_queue_ % kDefaultChunkSize) < kMinChunkSize)
    --chunks_to_process;

  if (chunks_to_process == 0)
    return kSuccess;

  assert((last_chunk_position_ - queue_start_position_) % kDefaultChunkSize == 0);

  uint32_t first_queue_chunk_index =
      static_cast<uint32_t>(queue_start_position_ / kDefaultChunkSize);
  data_map_.chunks.resize(std::max(static_cast<uint32_t>(data_map_.chunks.size()),
                                    first_queue_chunk_index + chunks_to_process));
#ifdef MAIDSAFE_OMP_ENABLED
#pragma omp parallel for
#endif
  for (int64_t i = 0; i < chunks_to_process; ++i) {
    bool modified(false);
    uint32_t chunk_index(first_queue_chunk_index + static_cast<uint32_t>(i));
    data_map_.chunks[chunk_index].pre_hash_state = ChunkDetails::kOutdated;
    CalculatePreHash(chunk_index,
                     main_encrypt_queue_.get() + (static_cast<uint32_t>(i) * kDefaultChunkSize),
                     kDefaultChunkSize, &modified);
    if (modified)
      DeleteChunk(chunk_index);
  }

  int64_t first_chunk_index(0);
  if (data_map_.chunks[first_queue_chunk_index - 1].pre_hash_state == ChunkDetails::kEmpty ||
      data_map_.chunks[first_queue_chunk_index - 2].pre_hash_state == ChunkDetails::kEmpty) {
    sequencer_->Add(reinterpret_cast<char*>(main_encrypt_queue_.get()), kDefaultChunkSize,
                    queue_start_position_);
    sequencer_->Add(reinterpret_cast<char*>(main_encrypt_queue_.get() + kDefaultChunkSize),
                    kDefaultChunkSize, queue_start_position_ + kDefaultChunkSize);
    first_chunk_index = 2;
  }

  int result(kSuccess);
#ifdef MAIDSAFE_OMP_ENABLED
#pragma omp parallel for
#endif
  for (int64_t i = first_chunk_index; i < chunks_to_process; ++i) {
    int res(EncryptChunk(first_queue_chunk_index + static_cast<uint32_t>(i),
                         main_encrypt_queue_.get() + (i * kDefaultChunkSize), kDefaultChunkSize));
    if (res != kSuccess) {
      std::lock_guard<std::mutex> guard(data_mutex_);
      LOG(kError) << "Failed processing main queue at chunk " << first_queue_chunk_index + i;
      result = res;
    }
  }

  if (result == kSuccess && chunks_to_process > 0) {
    uint32_t start_point(chunks_to_process * kDefaultChunkSize);
    uint32_t move_size(retrievable_from_queue_ - start_point);
    if (start_point < move_size)
      return result;
    uint32_t copied =
        MemCopy(main_encrypt_queue_, 0, main_encrypt_queue_.get() + start_point, move_size);
    assert(move_size == copied);
    static_cast<void>(copied);
    queue_start_position_ += (chunks_to_process * kDefaultChunkSize);
    retrievable_from_queue_ -= (chunks_to_process * kDefaultChunkSize);
    memset(main_encrypt_queue_.get() + retrievable_from_queue_, 0,
           kQueueCapacity_ - retrievable_from_queue_);
  }
  return result;
}

int SelfEncryptor::EncryptChunk(uint32_t chunk_num, byte* data, uint32_t length) {
  SCOPED_PROFILE
  assert(data_map_.chunks.size() > chunk_num);
  data_map_.chunks[chunk_num].hash.resize(crypto::SHA512::DIGESTSIZE);

  ByteArray pad(GetNewByteArray(kPadSize));
  ByteArray key(GetNewByteArray(crypto::AES256_KeySize));
  ByteArray iv(GetNewByteArray(crypto::AES256_IVSize));
  GetPadIvKey(chunk_num, key, iv, pad, true);
  int result(kSuccess);
  try {
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(key.get(), crypto::AES256_KeySize,
                                                            iv.get());

    std::string chunk_content;
    chunk_content.reserve(length);
    CryptoPP::Gzip aes_filter(
        new CryptoPP::StreamTransformationFilter(
            encryptor, new XORFilter(new CryptoPP::StringSink(chunk_content), pad.get())),
        6);
    aes_filter.Put2(data, length, -1, true);

    ByteArray post_hash(GetNewByteArray(crypto::SHA512::DIGESTSIZE));
    CryptoPP::SHA512().CalculateDigest(
        post_hash.get(), reinterpret_cast<const byte*>(chunk_content.data()), chunk_content.size());
    data_map_.chunks[chunk_num]
        .hash.assign(reinterpret_cast<char*>(post_hash.get()), crypto::SHA512::DIGESTSIZE);

    data_map_.chunks[chunk_num].storage_state = ChunkDetails::kPending;
    try {
      buffer_.Store(data_map_.chunks[chunk_num].hash, NonEmptyString(chunk_content));
    }
    catch (...) {
      LOG(kError) << "Could not store " << Base64Substr(data_map_.chunks[chunk_num].hash);
      data_map_.chunks[chunk_num].storage_state = ChunkDetails::kUnstored;
      result = kFailedToStoreChunk;
    }
//    DebugPrint(true, chunk_num, pad, key, iv, data, length, chunk_content);
  }
  catch (const std::exception& e) {
    LOG(kError) << e.what();
    result = kEncryptionException;
  }

  data_map_.chunks[chunk_num].size = length;  // keep pre-compressed length
  return result;
}

void SelfEncryptor::CalculatePreHash(uint32_t chunk_num, const byte* data, uint32_t length,
                                     bool* modified) {
  SCOPED_PROFILE
  if (data_map_.chunks[chunk_num].pre_hash_state == ChunkDetails::kOk) {
    *modified = false;
    return;
  }

  if (data_map_.chunks[chunk_num].pre_hash_state == ChunkDetails::kOutdated) {
    ByteArray temp(GetNewByteArray(crypto::SHA512::DIGESTSIZE));
    CryptoPP::SHA512().CalculateDigest(temp.get(), data, length);
    *modified = false;
    {
      std::lock_guard<std::mutex> guard(data_mutex_);
      for (int i(0); i != crypto::SHA512::DIGESTSIZE; ++i) {
        *modified = (*(temp.get() + i) != data_map_.chunks[chunk_num].pre_hash[i]);
        if (*modified)
          break;
      }
    }

    if (!(*modified)) {
      data_map_.chunks[chunk_num].pre_hash_state = ChunkDetails::kOk;
      return;
    }
    memcpy(data_map_.chunks[chunk_num].pre_hash, temp.get(), crypto::SHA512::DIGESTSIZE);
  } else {
    *modified = true;
    CryptoPP::SHA512().CalculateDigest(&data_map_.chunks[chunk_num].pre_hash[0], data, length);
  }

  data_map_.chunks[chunk_num].pre_hash_state = ChunkDetails::kOk;
}

bool SelfEncryptor::Flush() {
  SCOPED_PROFILE
  if (flushed_ || !prepared_for_writing_)
    return true;

  if (file_size_ < 3 * kMinChunkSize) {
    data_map_.content.assign(reinterpret_cast<char*>(chunk0_raw_.get()),
                              static_cast<size_t>(file_size_));
    data_map_.chunks.clear();
    flushed_ = true;
    return true;
  } else {
    data_map_.content.clear();
  }

  CalculateSizes(true);

  // Get pre-encryption hashes for chunks 0 & 1
  if (data_map_.chunks.size() < 2)
    data_map_.chunks.resize(2);
  bool chunk0_modified(false);
  CalculatePreHash(0, chunk0_raw_.get(), normal_chunk_size_, &chunk0_modified);
  // If chunk 0 was previously modified, it may already have had its pre-enc
  // hash updated to allow chunk 2 to be stored.  In this case, the modification
  // is indicated by a size of 0 in the data map.
  if (data_map_.chunks[0].size == 0)
    chunk0_modified = true;
  bool pre_pre_chunk_pre_hash_modified(chunk0_modified);
  byte* chunk1_start(chunk1_raw_.get());
  ByteArray temp;
  if (normal_chunk_size_ != kDefaultChunkSize) {
    if (normal_chunk_size_ * 2 <= kDefaultChunkSize) {
      // All of chunk 0 and chunk 1 data in chunk0_raw_
      chunk1_start = chunk0_raw_.get() + normal_chunk_size_;
    } else {
      // Some at end of chunk0_raw_ and rest in start of chunk1_raw_
      temp = GetNewByteArray(normal_chunk_size_);
      uint32_t size_chunk0(kDefaultChunkSize - normal_chunk_size_);
      uint32_t size_chunk1(normal_chunk_size_ - size_chunk0);
      uint32_t copied = MemCopy(temp, 0, chunk0_raw_.get() + normal_chunk_size_, size_chunk0);
      assert(size_chunk0 == copied);
      copied = MemCopy(temp, size_chunk0, chunk1_raw_.get(), size_chunk1);
      assert(size_chunk1 == copied);
      static_cast<void>(copied);
      chunk1_start = temp.get();
    }
  }
  bool chunk1_modified(false);
  CalculatePreHash(1, chunk1_start, normal_chunk_size_, &chunk1_modified);
  // If chunk 1 was previously modified, it may already have had its pre-enc
  // hash updated to allow chunks 2 & 3 to be stored.  In this case, the
  // modification is indicated by a size of 0 in the data map.
  if (data_map_.chunks[1].size == 0)
    chunk1_modified = true;
  bool pre_chunk_pre_hash_modified(chunk1_modified);

  // Empty queue (after this call it will contain 0 or 1 chunks).
  int result(ProcessMainQueue());
  if (result != kSuccess) {
    LOG(kError) << "Failed in Flush.";
    return false;
  }

  const uint32_t kOldChunkCount(static_cast<uint32_t>(data_map_.chunks.size()));
  const uint32_t kNewChunkCount(static_cast<uint32_t>(last_chunk_position_ / normal_chunk_size_) +
                                1);
  data_map_.chunks.resize(std::max(kOldChunkCount, kNewChunkCount));

  uint64_t flush_position(2 * normal_chunk_size_);
  uint32_t chunk_index(2);
  bool this_chunk_modified(false);
  bool this_chunk_has_data_in_sequencer(false);
  bool this_chunk_has_data_in_queue(false);
  uint32_t retrieved_from_queue(0);
  bool this_chunk_has_data_in_c0_or_c1(false);

  std::pair<uint64_t, ByteArray> sequence_block(sequencer_->GetFirst());
  uint64_t sequence_block_position(sequence_block.first);
  ByteArray sequence_block_data(sequence_block.second);
  uint32_t sequence_block_size(Size(sequence_block.second));
  uint32_t sequence_block_copied(0);

  ByteArray chunk_array(GetNewByteArray(kDefaultChunkSize + kMinChunkSize));
  uint32_t this_chunk_size(normal_chunk_size_);
  while (flush_position <= last_chunk_position_) {
    if (chunk_index == kNewChunkCount - 1) {  // on last chunk
      this_chunk_size = static_cast<uint32_t>(file_size_ - last_chunk_position_);
    }

    memset(chunk_array.get(), 0, Size(chunk_array));
    if (sequence_block_position < flush_position + this_chunk_size) {
      this_chunk_has_data_in_sequencer = true;
      this_chunk_modified = true;
    }

    if (flush_position <= queue_start_position_ + retrievable_from_queue_ &&
        flush_position + this_chunk_size > queue_start_position_ &&
        retrievable_from_queue_ - retrieved_from_queue != 0) {
      this_chunk_has_data_in_queue = true;
      this_chunk_modified = true;
    }

    if (flush_position < 2 * kDefaultChunkSize) {
      this_chunk_has_data_in_c0_or_c1 = true;
      this_chunk_modified = true;
    }

    if (data_map_.chunks[chunk_index].size == 0)
      this_chunk_modified = true;

    // Read in any data from previously-encrypted chunk
    if (chunk_index < kOldChunkCount &&
        (pre_pre_chunk_pre_hash_modified || pre_chunk_pre_hash_modified || this_chunk_modified)) {
      DecryptChunk(chunk_index, chunk_array.get());
    }

    // Overwrite with any data in chunk0_raw_ and/or chunk1_raw_
    uint32_t copied(0);
    if (this_chunk_has_data_in_c0_or_c1) {
      uint32_t offset(static_cast<uint32_t>(flush_position));
      uint32_t size_in_chunk0(0), c1_offset(0);
      if (offset < kDefaultChunkSize) {  // in chunk 0
        size_in_chunk0 = std::min(kDefaultChunkSize - offset, this_chunk_size);
        copied = MemCopy(chunk_array, 0, chunk0_raw_.get() + offset, size_in_chunk0);
        assert(size_in_chunk0 == copied);
      } else if (offset < 2 * kDefaultChunkSize) {
        c1_offset = offset - kDefaultChunkSize;
      }
      uint32_t size_in_chunk1(
          std::min(this_chunk_size - size_in_chunk0, kDefaultChunkSize - c1_offset));
      if (size_in_chunk1 != 0) {  // in chunk 1
        copied +=
            MemCopy(chunk_array, size_in_chunk0, chunk1_raw_.get() + c1_offset, size_in_chunk1);
        assert(size_in_chunk0 + size_in_chunk1 == copied);
      }
    }

    // Overwrite with any data in queue
    if (this_chunk_has_data_in_queue) {
      uint32_t copy_size(std::min(retrievable_from_queue_ - retrieved_from_queue, this_chunk_size));
      copied =
          MemCopy(chunk_array, copied, main_encrypt_queue_.get() + retrieved_from_queue, copy_size);
      retrieved_from_queue += copy_size;
      assert(copy_size == copied);
    }

    // Overwrite with any data from sequencer
    if (this_chunk_has_data_in_sequencer) {
      while (sequence_block_position + sequence_block_copied < flush_position + this_chunk_size) {
        uint32_t copy_size(
            std::min(sequence_block_size - sequence_block_copied,
                     static_cast<uint32_t>(flush_position + this_chunk_size -
                                           (sequence_block_position + sequence_block_copied))));
        uint32_t copy_offset(0);
        if (sequence_block_position > flush_position)
          copy_offset = std::min(this_chunk_size - copy_size,
                                 static_cast<uint32_t>(sequence_block_position - flush_position));
        copied = MemCopy(chunk_array, copy_offset,
                         sequence_block_data.get() + sequence_block_copied, copy_size);
        assert(copy_size == copied);
        if (sequence_block_copied + copy_size == sequence_block_size) {
          sequence_block = sequencer_->GetFirst();
          sequence_block_position = sequence_block.first;
          sequence_block_data = sequence_block.second;
          sequence_block_size = Size(sequence_block.second);
          sequence_block_copied = 0;
        } else {
          sequence_block_copied += copy_size;
        }
      }
    }

    if (this_chunk_modified) {
      data_map_.chunks[chunk_index].pre_hash_state = ChunkDetails::kOutdated;
      CalculatePreHash(chunk_index, chunk_array.get(), this_chunk_size, &this_chunk_modified);
    }

    if (pre_pre_chunk_pre_hash_modified || pre_chunk_pre_hash_modified || this_chunk_modified) {
      DeleteChunk(chunk_index);
      result = EncryptChunk(chunk_index, chunk_array.get(), this_chunk_size);
      if (result != kSuccess) {
        LOG(kError) << "Failed in Flush.";
        return false;
      }
    }

    flush_position += this_chunk_size;
    ++chunk_index;
    pre_pre_chunk_pre_hash_modified = pre_chunk_pre_hash_modified;
    pre_chunk_pre_hash_modified = this_chunk_modified;
    this_chunk_modified = false;
    this_chunk_has_data_in_sequencer = false;
    this_chunk_has_data_in_queue = false;
    this_chunk_has_data_in_c0_or_c1 = false;
  }

  assert(flush_position == file_size_);

  // truncate the DataMap if required
  if (kNewChunkCount < kOldChunkCount) {
    while (chunk_index < kOldChunkCount)
      DeleteChunk(chunk_index++);
    data_map_.chunks.resize(kNewChunkCount);
  }

  if (pre_pre_chunk_pre_hash_modified || pre_chunk_pre_hash_modified || chunk0_modified ||
      data_map_.chunks[0].pre_hash_state != ChunkDetails::kOk) {
    DeleteChunk(0);
    result = EncryptChunk(0, chunk0_raw_.get(), normal_chunk_size_);
    if (result != kSuccess) {
      LOG(kError) << "Failed in Flush.";
      return false;
    }
  }

  pre_pre_chunk_pre_hash_modified = pre_chunk_pre_hash_modified;
  pre_chunk_pre_hash_modified = chunk0_modified;

  if (pre_pre_chunk_pre_hash_modified || pre_chunk_pre_hash_modified || chunk1_modified ||
      data_map_.chunks[1].pre_hash_state != ChunkDetails::kOk) {
    DeleteChunk(1);
    result = EncryptChunk(1, chunk1_start, normal_chunk_size_);
    if (result != kSuccess) {
      LOG(kError) << "Failed in Flush.";
      return false;
    }
  }

  flushed_ = true;
  return true;
}

bool SelfEncryptor::Read(char* data, uint32_t length, uint64_t position) {
  SCOPED_PROFILE
  if (length == 0)
    return true;

  if (ReadFromBuffer(data, length, position))
    return true;

  PrepareToRead();

  if (length < kDefaultByteArraySize_) {
    if (position < cache_start_position_ ||
        position + length > cache_start_position_ + kDefaultByteArraySize_) {
      // populate read_cache_.
      if (Transmogrify(read_cache_.get(), kDefaultByteArraySize_, position) != kSuccess) {
        LOG(kError) << "Failed to read " << length << " bytes at position " << position;
        return false;
      }
      cache_start_position_ = position;
    }
    memcpy(data, read_cache_.get() + static_cast<uint32_t>(position - cache_start_position_),
           length);
  } else {
    // length requested larger than cache size, just go ahead and read
    if (Transmogrify(data, length, position) != kSuccess) {
      LOG(kError) << "Failed to read " << length << " bytes at position " << position;
      return false;
    }
  }
  return true;
}

bool SelfEncryptor::ReadFromBuffer(char* data, uint32_t length, uint64_t position) {
  SCOPED_PROFILE
  if (!buffer_activated_) {
    uint64_t diff((position > last_read_position_) ? (position - last_read_position_)
                                                   : (last_read_position_ - position));
    last_read_position_ = position;
    if (diff > kDefaultByteArraySize_)
      ++buffer_length_;
    // trigger buffering once detected too many jumpping reading
    if (buffer_length_ > 5) {
      if (size() > kMaxBufferSize_)
        buffer_length_ = kMaxBufferSize_;
      else
        buffer_length_ = static_cast<uint32_t>(size());
      try {
        read_buffer_.reset(new char[buffer_length_]);
      }
      catch (const std::exception& e) {
        LOG(kError) << "Failed to read " << buffer_length_ << " bytes: " << e.what();
        read_buffer_.reset();
        return false;
      }
      // always buffering from 0
      if (Transmogrify(read_buffer_.get(), buffer_length_, 0) != kSuccess) {
        LOG(kError) << "Failed to read " << buffer_length_ << " bytes";
        return false;
      }
      buffer_activated_ = true;
    }
  }
  if (buffer_activated_) {
    if ((position + length) < buffer_length_) {
      memcpy(data, read_buffer_.get() + position, length);
      return true;
    }
  }
  return false;
}

void SelfEncryptor::PrepareToRead() {
  SCOPED_PROFILE
  if (prepared_for_reading_)
    return;

  read_cache_.reset(new char[kDefaultByteArraySize_]);
  cache_start_position_ = std::numeric_limits<uint64_t>::max();
  prepared_for_reading_ = true;
}

int SelfEncryptor::Transmogrify(char* data, uint32_t length, uint64_t position) {
  SCOPED_PROFILE
  memset(data, 0, length);

  // For tiny files, all data is in data_map_.content or chunk0_raw_.
  if (file_size_ < 3 * kMinChunkSize) {
    if (position >= 3 * kMinChunkSize) {
      LOG(kError) << "Failed to transmogrify " << length << " bytes at position " << position
                  << " with file size of " << file_size_ << " bytes.";
      return kInvalidPosition;
    }
    if (prepared_for_writing_) {
      uint32_t copy_size = std::min(length, (3 * kMinChunkSize) - static_cast<uint32_t>(position));
      memcpy(data, chunk0_raw_.get() + position, copy_size);
    } else {
      uint32_t copy_size(0);
      if (data_map_.content.size() > position) {
        copy_size = std::min(length, static_cast<uint32_t>(data_map_.content.size() - position));
      }
      memcpy(data, data_map_.content.data() + position, copy_size);
    }
    return kSuccess;
  }

  int result(ReadDataMapChunks(data, length, position));
  if (result != kSuccess) {
    LOG(kError) << "Failed to read DM chunks during transmogrification of " << length
                << " bytes at position " << position;
    return result;
  }

  if (!prepared_for_writing_)
    return kSuccess;
  ReadInProcessData(data, length, position);
  return kSuccess;
}

int SelfEncryptor::ReadDataMapChunks(char* data, uint32_t length, uint64_t position) {
  SCOPED_PROFILE
  if (data_map_.chunks.empty() || position >= file_size_)
    return kSuccess;

  int result(kSuccess);
  uint32_t num_chunks = static_cast<uint32_t>(data_map_.chunks.size());
  if (normal_chunk_size_ != kDefaultChunkSize) {
    assert(file_size_ < 3 * kDefaultChunkSize + kMinChunkSize - 1);
    ByteArray temp(GetNewByteArray(static_cast<uint32_t>(file_size_)));
#ifdef MAIDSAFE_OMP_ENABLED
#pragma omp parallel for
#endif
    for (int64_t i = 0; i < num_chunks; ++i) {
      uint32_t this_chunk_size(data_map_.chunks[static_cast<uint32_t>(i)].size);
      if (this_chunk_size != 0) {
        uint64_t offset = (static_cast<uint32_t>(i) * normal_chunk_size_);
        int res = DecryptChunk(static_cast<uint32_t>(i), temp.get() + offset);
        if (res != kSuccess) {
          std::lock_guard<std::mutex> guard(data_mutex_);
          LOG(kError) << "Failed to decrypt chunk " << i;
          result = res;
        }
      }
    }
    if (result != kSuccess)
      return result;

    memcpy(data, temp.get() + position,
           std::min(length, static_cast<uint32_t>(file_size_ - position)));
    return kSuccess;
  }

  uint32_t first_chunk_index =
      std::min(num_chunks - 1, static_cast<uint32_t>(position / kDefaultChunkSize));
  uint32_t first_chunk_offset(position % kDefaultChunkSize);
  uint32_t first_chunk_size(0);
  if (data_map_.chunks[first_chunk_index].size > first_chunk_offset)
    first_chunk_size = data_map_.chunks[first_chunk_index].size - first_chunk_offset;

  uint32_t last_chunk_index =
      std::min(num_chunks - 1, static_cast<uint32_t>((position + length - 1) / kDefaultChunkSize));
  uint32_t last_chunk_size(
      std::min(static_cast<uint32_t>(position + length - (last_chunk_index * kDefaultChunkSize)),
               data_map_.chunks[last_chunk_index].size));

#ifdef MAIDSAFE_OMP_ENABLED
#pragma omp parallel for
#endif
#ifdef __GNUC__
  for (uint32_t i = first_chunk_index; i <= last_chunk_index; ++i) {
#else
  for (int64_t i = first_chunk_index; i <= last_chunk_index; ++i) {
#endif
    uint32_t this_chunk_size(data_map_.chunks[static_cast<uint32_t>(i)].size);
    if (this_chunk_size != 0) {
      if (i == first_chunk_index) {
        ByteArray temp(GetNewByteArray(this_chunk_size));
        int res = DecryptChunk(static_cast<uint32_t>(i), temp.get());
        if (res != kSuccess) {
          LOG(kError) << "Failed to decrypt chunk " << i;
          result = res;
        }
        memcpy(data, temp.get() + first_chunk_offset, first_chunk_size);
      } else if (i == last_chunk_index) {
        ByteArray temp(GetNewByteArray(this_chunk_size));
        int res = DecryptChunk(static_cast<uint32_t>(i), temp.get());
        if (res != kSuccess) {
          LOG(kError) << "Failed to decrypt chunk " << i;
          result = res;
        }
        uint32_t offset = kDefaultChunkSize - first_chunk_offset +
                          (last_chunk_index - first_chunk_index - 1) * kDefaultChunkSize;
        memcpy(data + offset, temp.get(), last_chunk_size);
      } else {
        uint32_t offset = kDefaultChunkSize - first_chunk_offset +
                          static_cast<uint32_t>(i - first_chunk_index - 1) * kDefaultChunkSize;
        int res = DecryptChunk(static_cast<uint32_t>(i), reinterpret_cast<byte*>(&data[offset]));
        if (res != kSuccess) {
          std::lock_guard<std::mutex> guard(data_mutex_);
          LOG(kError) << "Failed to decrypt chunk " << i;
          result = res;
        }
      }
    }
  }
  return result;
}

void SelfEncryptor::ReadInProcessData(char * data, uint32_t length, uint64_t position) {
  SCOPED_PROFILE
  uint32_t copy_size(0), bytes_read(0);
  uint64_t read_position(position);
  // Get data from chunk 0 if required.
  if (read_position < kDefaultChunkSize) {
    copy_size = std::min(length, kDefaultChunkSize - static_cast<uint32_t>(read_position));
    memcpy(data, chunk0_raw_.get() + read_position, copy_size);
    bytes_read += copy_size;
    read_position += copy_size;
    if (bytes_read == length)
      return;
  }
  // Get data from chunk 1 if required.
  if (read_position < 2 * kDefaultChunkSize) {
    copy_size = std::min(length - bytes_read,
                         (2 * kDefaultChunkSize) - static_cast<uint32_t>(read_position));
    memcpy(data + bytes_read, chunk1_raw_.get() + read_position - kDefaultChunkSize, copy_size);
    bytes_read += copy_size;
    read_position += copy_size;
    if (bytes_read == length)
      return;
  }

  // Get data from queue if required.
  uint32_t data_offset(0), queue_offset(0), copy_length(0);
  if (retrievable_from_queue_ != 0) {
    if ((position < queue_start_position_ + retrievable_from_queue_) &&
        (position + length > queue_start_position_)) {
      if (position < queue_start_position_)
        data_offset = static_cast<uint32_t>(queue_start_position_ - position);
      else
        queue_offset = static_cast<uint32_t>(position - queue_start_position_);
      copy_length = std::min(length - data_offset, retrievable_from_queue_ - queue_offset);
      memcpy(data + data_offset, main_encrypt_queue_.get() + queue_offset, copy_length);
    }
  }

  // Get data from sequencer if required.
  std::pair<uint64_t, ByteArray> sequence_block(sequencer_->Peek(length, position));
  uint64_t sequence_block_position(sequence_block.first);
  ByteArray sequence_block_data(sequence_block.second);
  uint32_t sequence_block_size(Size(sequence_block.second));
  uint64_t seq_position(position);
  uint32_t sequence_block_offset(0);

  while (position < sequence_block_position + sequence_block_size &&
         position + length >= sequence_block_position) {
    if (position < sequence_block_position) {
      data_offset = static_cast<uint32_t>(sequence_block_position - position);
      sequence_block_offset = 0;
    } else {
      data_offset = 0;
      sequence_block_offset = static_cast<uint32_t>(position - sequence_block_position);
    }
    copy_length = std::min(length - data_offset,
                           static_cast<uint32_t>(sequence_block_position + sequence_block_size -
                                                 position - data_offset));

    memcpy(data + data_offset, sequence_block_data.get() + sequence_block_offset, copy_length);

    seq_position = sequence_block_position + sequence_block_size;
    sequence_block = sequencer_->PeekBeyond(seq_position);
    sequence_block_position = sequence_block.first;
    sequence_block_data = sequence_block.second;
    sequence_block_size = Size(sequence_block.second);
  }
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
  PrepareToWrite(0, 0);

  if (position < queue_start_position_) {
    queue_start_position_ = 2 * kDefaultChunkSize;
    current_position_ = queue_start_position_;
    retrievable_from_queue_ = 0;
  } else if (position < queue_start_position_ + retrievable_from_queue_) {
    current_position_ = position;
    retrievable_from_queue_ = static_cast<uint32_t>(current_position_ - queue_start_position_);
  }

  sequencer_->Truncate(position);

  // TODO(Fraser#5#): 2011-10-18 - Confirm these memset's are really required
  if (position < kDefaultChunkSize) {
    uint32_t overwite_size(kDefaultChunkSize - static_cast<uint32_t>(position));
    uint32_t overwrite_position(static_cast<uint32_t>(position));
    memset(chunk0_raw_.get() + overwrite_position, 0, overwite_size);
    memset(chunk1_raw_.get(), 0, kDefaultChunkSize);
    if (data_map_.chunks.size() > 1) {
      data_map_.chunks[0].pre_hash_state = ChunkDetails::kOutdated;
      data_map_.chunks[1].pre_hash_state = ChunkDetails::kOutdated;
    }
  } else if (position < 2 * kDefaultChunkSize) {
    uint32_t overwite_size((2 * kDefaultChunkSize) - static_cast<uint32_t>(position));
    uint32_t overwrite_position(static_cast<uint32_t>(position) - kDefaultChunkSize);
    memset(chunk1_raw_.get() + overwrite_position, 0, overwite_size);
    if (data_map_.chunks.size() > 1)
      data_map_.chunks[1].pre_hash_state = ChunkDetails::kOutdated;
  }

  file_size_ = position;
  CalculateSizes(true);
  return true;
}

bool SelfEncryptor::TruncateUp(uint64_t position) {
  SCOPED_PROFILE
  if (file_size_ < kDefaultByteArraySize_) {
    uint64_t target_position(std::min(position, static_cast<uint64_t>(kDefaultByteArraySize_)));
    if (!AppendNulls(target_position)) {
      LOG(kError) << "Failed to append nulls to beyond end of Chunk 1";
      return false;
    }
    if (position <= kDefaultByteArraySize_)
      return true;
  }
  truncated_file_size_ = position;
  return true;
}

bool SelfEncryptor::AppendNulls(uint64_t position) {
  SCOPED_PROFILE
  std::unique_ptr<char[]> tail_data(new char[kDefaultByteArraySize_]);
  memset(tail_data.get(), 0, kDefaultByteArraySize_);
  uint64_t current_position(file_size_);
  uint64_t length(position - current_position);
  while (length > kDefaultByteArraySize_) {
    if (!Write(tail_data.get(), kDefaultByteArraySize_, current_position))
      return false;
    current_position += kDefaultByteArraySize_;
    length -= kDefaultByteArraySize_;
  }
  return Write(tail_data.get(), static_cast<uint32_t>(length), current_position);
}

void SelfEncryptor::DeleteChunk(uint32_t chunk_num) {
  SCOPED_PROFILE
  std::lock_guard<std::mutex> data_guard(data_mutex_);
  if (data_map_.chunks[chunk_num].hash.empty())
    return;

  /*if (chunk_num < original_data_map_->chunks.size() &&
      data_map_.chunks[chunk_num].hash == original_data_map_->chunks[chunk_num].hash) {
    return;
  }*/

  try {
    buffer_.Delete(data_map_.chunks[chunk_num].hash);
  }
  catch (...) {
  }
}

}  // namespace encrypt

}  // namespace maidsafe
