
/*******************************************************************************
 *  Copyright 2008-2011 maidsafe.net limited                                   *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  utils.h
 * @brief Helper functions for self-encryption engine.
 * @date  2008-09-09
 */

#ifndef MAIDSAFE_ENCRYPT_SELF_ENCRYPT_H_
#define MAIDSAFE_ENCRYPT_SELF_ENCRYPT_H_


#include <omp.h>

#include <tuple>
#include <cstdint>
#include <string>

#ifdef __MSVC__
#  pragma warning(push, 1)
#endif
#include "cryptopp/mqueue.h"
#include "cryptopp/sha.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "boost/shared_array.hpp"

#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/sequencer.h"
#include "maidsafe/encrypt/version.h"

#if MAIDSAFE_ENCRYPT_VERSION != 906
#  error This API is not compatible with the installed library.\
    Please update the library.
#endif


namespace maidsafe {

class ChunkStore;
typedef std::shared_ptr<ChunkStore> ChunkStorePtr;

namespace encrypt {

uint64_t TotalSize(DataMapPtr data_map);

/// XOR transformation class for pipe-lining
class XORFilter : public CryptoPP::Bufferless<CryptoPP::Filter> {
 public:
  XORFilter(CryptoPP::BufferedTransformation *attachment = NULL,
            byte *pad = NULL)
      : pad_(pad), count_(0) { CryptoPP::Filter::Detach(attachment); }
  size_t Put2(const byte* in_string,
              size_t length,
              int message_end,
              bool blocking);
  bool IsolatedFlush(bool, bool) { return false; }
 private:
  XORFilter &operator = (const XORFilter&);
  XORFilter(const XORFilter&);
  byte *pad_;
  size_t count_;
};

class SelfEncryptor {
 public:
  SelfEncryptor(DataMapPtr data_map,
                std::shared_ptr<ChunkStore> chunk_store,
                int num_procs = 0)
      : data_map_(data_map ? data_map : DataMapPtr(new DataMap)),
        sequencer_(),
        kDefaultByteArraySize_(num_procs == 0 ?
                               kDefaultChunkSize * omp_get_num_procs() :
                               kDefaultChunkSize * num_procs),
        main_encrypt_queue_(),
        queue_start_position_(2 * kDefaultChunkSize),
        kQueueCapacity_(kDefaultByteArraySize_ + kDefaultChunkSize),
        retrievable_from_queue_(0),
        chunk0_raw_(),
        chunk1_raw_(),
        chunk_store_(chunk_store),
        chunk_one_two_q_full_(false),
        c0_and_1_chunk_size_(kDefaultChunkSize),
        current_position_(0),
        prepared_for_writing_(!data_map),
        chunk0_modified_(true),
        chunk1_modified_(true),
        read_ok_(true),
        rewriting_(false),
        read_cache_(),
        cache_start_position_(0),
        prepared_for_reading_() {}
  ~SelfEncryptor();
  bool Write(const char *data = NULL,
             uint32_t length = 0,
             uint64_t position = 0);
  bool Read(char *data, uint32_t length = 0, uint64_t position = 0);
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
  void AddReleventSeqDataToQueue();
  void ReadChunk(uint32_t chunk_num, byte *data);
  void GetPadIvKey(uint32_t this_chunk_num,
                   ByteArray key,
                   ByteArray iv,
                   ByteArray pad);
//  bool AttemptProcessQueue();
//  bool QueueC0AndC1();
  bool ProcessMainQueue(const uint32_t &chunk_size,
                        const uint64_t &last_chunk_position);
  void EncryptChunk(uint32_t chunk_num, byte *data, uint32_t length);
  void CalculateSizes(uint64_t *file_size,
                      uint32_t *normal_chunk_size,
                      uint64_t *last_chunk_position);
  bool WriteExtraAndEnc0and1();

  // If prepared_for_reading_ is not already true, this initialises read_cache_.
  void PrepareToRead();
  bool Transmogrify(char *data,
                    const uint32_t &length,
                    const uint64_t &position);
  bool ReadDataMapChunks(char *data,
                         const uint32_t &length,
                         const uint64_t &position);
  void ReadInProcessData(char *data, uint32_t length, uint64_t position);

  DataMapPtr data_map_;
  Sequencer sequencer_;
  const uint32_t kDefaultByteArraySize_;
  ByteArray main_encrypt_queue_;
  uint64_t queue_start_position_;
  const uint32_t kQueueCapacity_;
  uint32_t retrievable_from_queue_;
  ByteArray chunk0_raw_;
  ByteArray chunk1_raw_;
  std::shared_ptr<ChunkStore> chunk_store_;
  bool chunk_one_two_q_full_;
  uint32_t c0_and_1_chunk_size_;
  uint64_t current_position_;
  bool prepared_for_writing_;
  bool chunk0_modified_, chunk1_modified_;
  bool read_ok_;
  bool rewriting_;
  boost::shared_array<char> read_cache_;
  uint64_t cache_start_position_;
  bool prepared_for_reading_;
};

}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELF_ENCRYPT_H_
