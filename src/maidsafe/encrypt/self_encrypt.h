
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
  SelfEncryptor(DataMapPtr data_map, std::shared_ptr<ChunkStore> chunk_store)
      : data_map_(data_map ? data_map : DataMapPtr(new DataMap)),
        sequencer_(),
        chunk_size_(1024 * 256),
        main_encrypt_queue_(),
        chunk0_raw_(new byte[chunk_size_]),
        chunk1_raw_(new byte[chunk_size_]),
        chunk_store_(chunk_store),
        chunk_one_two_q_full_(false),
        c0_and_1_chunk_size_(chunk_size_),
        current_position_(0),
        read_ok_(true),
        rewriting_(false),
        ignore_threads_(false),
        num_procs_(omp_get_num_procs()),
        cache_(false),
        data_cache_(new char[chunk_size_ * num_procs_]),
        cache_initial_posn_(0),
        trailing_data_(),
        trailing_data_start_(0),
        trailing_data_size_(0) {}
  ~SelfEncryptor();
  bool Write(const char *data = NULL,
             uint32_t length = 0,
             uint64_t position = 0);
  bool Read(char *data, uint32_t length = 0, uint64_t position = 0);
  bool DeleteAllChunks();
  bool Truncate(std::uint64_t size);
  DataMapPtr data_map() const { return data_map_; }

 private:
  typedef boost::shared_array<byte> ByteArray;
  SelfEncryptor &operator = (const SelfEncryptor&);
  SelfEncryptor(const SelfEncryptor&);
  void AddReleventSeqDataToQueue();
  void SequenceAllNonStandardChunksAndExtraContent();
  void ReadChunk(uint32_t chunk_num, byte *data);
  void GetPadIvKey(uint32_t this_chunk_num,
                   ByteArray key,
                   ByteArray iv,
                   ByteArray pad);
  bool AttemptProcessQueue();
  bool QueueC0AndC1();
  bool ProcessMainQueue();
  void EncryptAChunk(uint32_t chunk_num,
                     byte *data,
                     uint32_t length,
                     bool re_encrypt);
  void EmptySequencer();
  bool WriteExtraAndEnc0and1();
  bool Transmogrify(char *data,
                    uint32_t length = 0,
                    uint64_t position = 0,
                    bool writing = false);
  void ReadInProcessData(char *data, uint32_t length, uint64_t position);

  DataMapPtr data_map_;
  Sequencer sequencer_;
  uint32_t chunk_size_;
  CryptoPP::MessageQueue main_encrypt_queue_;
  ByteArray chunk0_raw_;
  ByteArray chunk1_raw_;
  std::shared_ptr<ChunkStore> chunk_store_;
  bool chunk_one_two_q_full_;
  uint32_t c0_and_1_chunk_size_;
  uint64_t current_position_;
  bool read_ok_;
  bool rewriting_;
  bool ignore_threads_;
  int num_procs_;
  bool cache_;
  boost::shared_array<char> data_cache_;
  uint64_t cache_initial_posn_;
  ByteArray trailing_data_;
  uint64_t trailing_data_start_;
  uint32_t trailing_data_size_;
};

}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELF_ENCRYPT_H_
