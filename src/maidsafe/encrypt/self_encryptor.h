
/*******************************************************************************
*  Copyright 2011 MaidSafe.net limited                                         *
*                                                                              *
*  The following source code is property of MaidSafe.net limited and is not    *
*  meant for external use.  The use of this code is governed by the license    *
*  file LICENSE.TXT found in the root of this directory and also on            *
*  www.MaidSafe.net.                                                           *
*                                                                              *
*  You are not free to copy, amend or otherwise use this source code without   *
*  the explicit written permission of the board of directors of MaidSafe.net.  *
*******************************************************************************/

#ifndef MAIDSAFE_ENCRYPT_SELF_ENCRYPTOR_H_
#define MAIDSAFE_ENCRYPT_SELF_ENCRYPTOR_H_

#include <omp.h>

#include <tuple>
#include <cstdint>
#include <string>
#include "boost/scoped_ptr.hpp"
#include "boost/shared_array.hpp"

#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/version.h"

#if MAIDSAFE_ENCRYPT_VERSION != 906
#  error This API is not compatible with the installed library.\
    Please update the library.
#endif


namespace maidsafe {

class ChunkStore;
typedef std::shared_ptr<ChunkStore> ChunkStorePtr;

namespace encrypt {

class Sequencer;

class SelfEncryptor {
 public:
  SelfEncryptor(DataMapPtr data_map,
                std::shared_ptr<ChunkStore> chunk_store,
                int num_procs = 0);
  ~SelfEncryptor();
  bool Write(const char *data, uint32_t length, uint64_t position);
  bool Read(char *data, const uint32_t &length, const uint64_t &position);
  bool DeleteAllChunks();
  bool Truncate(uint64_t size);
  void Flush();
  DataMapPtr data_map() const { return data_map_; }

 private:
  typedef boost::shared_array<byte> ByteArray;
  SelfEncryptor &operator = (const SelfEncryptor&);
  SelfEncryptor(const SelfEncryptor&);
  // If prepared_for_writing_ is not already true, this either reads the first 2
  // chunks into their appropriate buffers or reads the content field of
  // data_map_ into chunk0_raw_.  This guarantees that if data_map_ had
  // exactly 3 chunks before (the only way chunks could be non-default-sized),
  // it will be empty after.  Chunks read in from data_map_ are deleted from
  // chunk_store_.
  void PrepareToWrite();
  // Copies any relevant data to read_cache_.
  void PutToReadCache(const char *data,
                      const uint32_t &length,
                      const uint64_t &position);
  // Copies data to chunk0_raw_ and/or chunk1_raw_.  Returns number of bytes
  // copied.  Updates length and position if data is copied.
  uint32_t PutToInitialChunks(const char *data,
                              uint32_t *length,
                              uint64_t *position);
  // If data for writing overlaps or joins on to the end of main_encrypt_queue_,
  // this returns true and sets the offsets to the required start positions of
  // the data and the main_encrypt_queue_.
  bool GetDataOffsetForEnqueuing(const uint32_t &length,
                                 const uint64_t &position,
                                 uint32_t *data_offset,
                                 uint32_t *queue_offset);
  // Copies data into main_encrypt_queue_.  Any elements of data that precede
  // the start of main_encrypt_queue_ are ignored.  If the main_encrypt_queue_
  // becomes full during the process, it is encrpyted and reset.  This repeats
  // until all of the remaining data is copied.  If any of the data falls into
  // chunk 0 or 1, it is copied to those buffer(s) instead.  In this case, these
  // chunk buffers are treated as part of the main_encrypt_queue_ as far as
  // updating position pointers is concerned.
  void PutToEncryptQueue(const char *data,
                         uint32_t length,
                         uint32_t data_offset,
                         uint32_t queue_offset);
  // Any data for writing beyond chunks 0 and 1 and which precedes
  // main_encrypt_queue_, is added to the sequencer.  So is any data which
  // follows but doesn't adjoin main_encrypt_queue_.  For such a case, this
  // returns true and adjusts length to the required amount of data to be
  // copied.
  bool GetLengthForSequencer(const uint64_t &position, uint32_t *length);
  void ReadChunk(uint32_t chunk_num, byte *data);
  void GetPadIvKey(uint32_t this_chunk_num,
                   ByteArray key,
                   ByteArray iv,
                   ByteArray pad);
  bool ProcessMainQueue();
  void EncryptChunk(uint32_t chunk_num, byte *data, uint32_t length);
  void CalculateSizes(bool force);

  // If prepared_for_reading_ is not already true, this initialises read_cache_.
  void PrepareToRead();
  // Handles reading from populated data_map_ and all the various write buffers.
  bool Transmogrify(char *data,
                    const uint32_t &length,
                    const uint64_t &position);
  bool ReadDataMapChunks(char *data,
                         const uint32_t &length,
                         const uint64_t &position);
  void ReadInProcessData(char *data, uint32_t length, uint64_t position);

  DataMapPtr data_map_;
  boost::scoped_ptr<Sequencer> sequencer_;
  const uint32_t kDefaultByteArraySize_;
  uint64_t file_size_, last_chunk_position_;
  uint32_t normal_chunk_size_;
  ByteArray main_encrypt_queue_;
  uint64_t queue_start_position_;
  const uint32_t kQueueCapacity_;
  uint32_t retrievable_from_queue_;
  ByteArray chunk0_raw_, chunk1_raw_;
  std::shared_ptr<ChunkStore> chunk_store_;
  uint64_t current_position_;
  bool prepared_for_writing_, chunk0_modified_, chunk1_modified_, read_ok_;
  boost::shared_array<char> read_cache_;
  uint64_t cache_start_position_;
  bool prepared_for_reading_;
};

}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELF_ENCRYPTOR_H_
