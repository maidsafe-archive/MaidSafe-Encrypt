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

#ifndef MAIDSAFE_ENCRYPT_SELF_ENCRYPTOR_H_
#define MAIDSAFE_ENCRYPT_SELF_ENCRYPTOR_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/data_buffer.h"

#include "maidsafe/encrypt/data_map.h"

namespace maidsafe {

namespace encrypt {

enum class EncryptionAlgorithm : uint32_t {
  kSelfEncryptionVersion0 = 0,
  kDataMapEncryptionVersion0
};

extern const EncryptionAlgorithm kSelfEncryptionVersion;
extern const EncryptionAlgorithm kDataMapEncryptionVersion;

class Sequencer;
class Cache; 

crypto::CipherText EncryptDataMap(const Identity& parent_id, const Identity& this_id,
                                  const DataMap& data_map);

DataMap DecryptDataMap(const Identity& parent_id, const Identity& this_id,
                       const std::string& encrypted_data_map);

class SelfEncryptor {
 public:
  SelfEncryptor(DataMap& data_map, DataBuffer<std::string>& buffer,
                std::function<NonEmptyString(const std::string&)> get_from_store,
                int num_procs = 0);
  ~SelfEncryptor();
  SelfEncryptor(const SelfEncryptor&) = delete;
  SelfEncryptor(SelfEncryptor&&) = delete;
  SelfEncryptor& operator=(SelfEncryptor) = delete;

  bool Write(const char* data, uint32_t length, uint64_t position);
  bool Read(char* data, uint32_t length, uint64_t position);
  // Can truncate up or down
  bool Truncate(uint64_t position);
  // Forces all buffered data to be encrypted.  Missing portions of the file are filled with '\0's
  bool Flush();

  uint64_t size() const {
    return (file_size_ < truncated_file_size_) ? truncated_file_size_ : file_size_;
  }
  const DataMap& data_map() const { return data_map_; }
  const DataMap& original_data_map() const { return kOriginalDataMap_; }

 private:
  // If prepared_for_writing_ is not already true, this either reads the first 2
  // chunks into their appropriate buffers or reads the content field of
  // data_map_ into chunk0_raw_.  This guarantees that if data_map_ had
  // exactly 3 chunks before (the only way chunks could be non-default-sized),
  // it will be empty after.  Chunks read in from data_map_ are deleted from
  // chunk_store_.  The main_encrypt_queue_ is set to start at "position" if it
  // is beyond the end of the first 2 chunks.
  void PrepareToWrite(uint32_t length, uint64_t position);
  // If file < * Chunks then its all in the read_cache_
  bool SmallFile();
  // is read cache full
  bool CacheFull();
  // Copies any relevant data to read_cache_.
  void PutToReadCache(const char* data, uint32_t length, uint64_t position);
  // Copies any relevant data to read_buffer_.
  void PutToReadBuffer(const char* data, uint32_t length, uint64_t position);
  // Copies data to chunk0_raw_ and/or chunk1_raw_.  Returns number of bytes
  // copied.  Updates length and position if data is copied.
  uint32_t PutToInitialChunks(const char* data, uint32_t* length, uint64_t* position);
  // If data for writing overlaps or joins on to the end of main_encrypt_queue_,
  // this returns true and sets the offsets to the required start positions of
  // the data and the main_encrypt_queue_.
  bool GetDataOffsetForEnqueuing(uint32_t length, uint64_t position, uint32_t* data_offset,
                                 uint32_t* queue_offset);
  // Copies data into main_encrypt_queue_.  Any elements of data that precede
  // the start of main_encrypt_queue_ are ignored.  If the main_encrypt_queue_
  // becomes full during the process, it is encrpyted and reset.  This repeats
  // until all of the remaining data is copied.  If any of the data falls into
  // chunk 0 or 1, it is copied to those buffer(s) instead.  In this case, these
  // chunk buffers are treated as part of the main_encrypt_queue_ as far as
  // updating position pointers is concerned.
  void PutToEncryptQueue(const char* data, uint32_t length, uint32_t data_offset,
                         uint32_t queue_offset);
  // Any data for writing beyond chunks 0 and 1 and which precedes
  // main_encrypt_queue_, is added to the sequencer.  So is any data which
  // follows but doesn't adjoin main_encrypt_queue_.  For such a case, this
  // returns true and adjusts length to the required amount of data to be
  // copied.
  bool GetLengthForSequencer(uint64_t position, uint32_t* length);
  // Retrieves the encrypted chunk from chunk_store_ and decrypts it to "data".
  void DecryptChunk(uint32_t chunk_num, byte* data);
  // Retrieves appropriate pre-hashes from data_map_ and constructs key, IV and
  // encryption pad.  If writing, and chunk has old_n1_pre_hash and
  // old_n2_pre_hash fields set, they are reset to NULL.
  void GetPadIvKey(uint32_t this_chunk_num, std::shared_ptr<byte> key, std::shared_ptr<byte> iv,
                   std::shared_ptr<byte> pad, bool writing);
  // Encrypts all but the last chunk in the queue, then moves the last chunk to
  // the front of the queue.
  void ProcessMainQueue();
  // Encrypts the chunk and stores in chunk_store_
  void EncryptChunk(uint32_t chunk_num, byte* data, uint32_t length);
  // If the calculated pre-hash is different to any existing pre-hash,
  // modified is set to true.  In this case, chunks n+1 and n+2 have their
  // old_n1_pre_hash and old_n2_pre_hash fields completed if not already done.
  void CalculatePreHash(uint32_t chunk_num, const byte* data, uint32_t length, bool* modified);
  void CalculateSizes(bool force);
  // Handles reading from populated data_map_ and all the various write buffers.
  int Transmogrify(char* data, uint32_t length, uint64_t position);
  void ReadDataMapChunks(char* data, uint32_t length, uint64_t position);
  void ReadInProcessData(char* data, uint32_t length, uint64_t position);
  bool TruncateUp(uint64_t position);
  bool AppendNulls(uint64_t position);
  bool TruncateDown(uint64_t position);
  void DeleteChunk(uint32_t chunk_num);

  DataMap& data_map_;
  DataMap kOriginalDataMap_;
  std::unique_ptr<Sequencer> sequencer_;
  const uint32_t kDefaultByteArraySize_;
  uint64_t file_size_, last_chunk_position_;
  uint64_t truncated_file_size_;
  uint32_t normal_chunk_size_;
  std::shared_ptr<byte> main_encrypt_queue_;
  uint64_t queue_start_position_;
  const uint32_t kQueueCapacity_;
  uint32_t retrievable_from_queue_;
  std::shared_ptr<byte> chunk0_raw_, chunk1_raw_;
  DataBuffer<std::string>& buffer_;
  std::function<NonEmptyString(const std::string&)> get_from_store_;
  uint64_t current_position_;
  std::unique_ptr<Cache> read_cache_;
  bool prepared_for_writing_, flushed_;
  uint64_t last_read_position_;
  mutable std::mutex data_mutex_;
};

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELF_ENCRYPTOR_H_
