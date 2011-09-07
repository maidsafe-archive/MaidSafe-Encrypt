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

#ifndef MAIDSAFE_ENCRYPT_UTILS_H_
#define MAIDSAFE_ENCRYPT_UTILS_H_

  #include "maidsafe/encrypt/version.h"
    #if MAIDSAFE_ENCRYPT_VERSION != 905
    # error This API is not compatible with the installed library.\
     Please update the library.
    #endif


#include <cstdint>
#include <string>
#include <tuple>
#include <omp.h>

#ifdef __MSVC__
#  pragma warning(push, 1)
#  pragma warning(disable: 4702)
#endif
#include "cryptopp/cryptlib.h"
#include "cryptopp/files.h"
#include "cryptopp/channels.h"
#include "cryptopp/mqueue.h"
#include "cryptopp/sha.h"
#include "cryptopp/aes.h"
#include "cryptopp/gzip.h"
#include "common/crypto.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "boost/filesystem.hpp"
#include "boost/shared_array.hpp"
#include "boost/asio/io_service.hpp"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/sequencer.h"

namespace fs = boost::filesystem;

namespace maidsafe {

class ChunkStore;

namespace encrypt {


/// XOR transformation class for pipe-lining
class XORFilter : public CryptoPP::Bufferless<CryptoPP::Filter> {
 public:
  XORFilter(CryptoPP::BufferedTransformation *attachment = NULL,
            byte *pad = NULL) :
            pad_(pad), count_(0) {
              CryptoPP::Filter::Detach(attachment);
  };
  size_t Put2(const byte* inString,
              size_t length,
              int messageEnd,
              bool blocking);
  bool IsolatedFlush(bool, bool) { return false; }
 private:
  XORFilter &operator = (const XORFilter&);  // no assignment
  XORFilter(const XORFilter&);  // no copy
  byte *pad_;
  size_t count_;
};

class SE {  // Self Encryption
 public:
   SE(std::shared_ptr<DataMap> data_map,
      std::shared_ptr<ChunkStore> chunk_store) :
                        data_map_(data_map),  sequencer_(),
                        chunk_size_(1024*256),
                        min_chunk_size_(1024), length_(), hash_(),
                        main_encrypt_queue_(CryptoPP::MessageQueue()),
                        chunk0_raw_(new byte[chunk_size_]),
                        chunk1_raw_(new byte[chunk_size_]),
                        chunk_data_(),
                        chunk_store_(chunk_store),
                        chunk_one_two_q_full_(false),
                        c0_and_1_chunk_size_(chunk_size_),
                        current_position_(0), readok_(true),
                        repeated_chunks_(false), q_position_(0),
                        rewriting_(false),
                        ignore_threads_(false), num_procs_(omp_get_num_procs()),
                        read_c0andc1_(false),
                        end_of_chunks_position_(0),
                        cache_(false),
                        data_cache_(new char[chunk_size_ * num_procs_]),
                        cache_initial_posn_(0) {
                          if (!data_map_)
                            data_map_.reset(new DataMap);
                        }
  ~SE();
  bool Write(const char* data = NULL,
             std::uint32_t length = 0,
             std::uint64_t position = 0);
  bool Read(char* data, std::uint32_t length = 0, std::uint64_t position = 0);
//   bool Read(char * data, std::uint32_t length = 0, std::uint64_t position = 0) {
//     return Transmogrify(data, length, position,false);
//   }
  bool setDatamap(std::shared_ptr<DataMap> data_map);
  bool DeleteAllChunks();
  std::shared_ptr<DataMap> getDataMap() { return data_map_; }

 private:
   // METHODS
  SE &operator = (const SE&);  // no assignment
  SE(const SE&);  // no copy
  bool DeleteAChunkFromStore(size_t chunk_num);
  bool AttemptProcessQueue();
  bool Transmogrify(char* data,
                    std::uint32_t length = 0,
                    std::uint64_t position = 0,
                    bool writing = false);
  bool WriteExtraAndEnc0and1();
  void ReadChunk(std::uint16_t chunk_num, byte *data);
  void EncryptAChunk(std::uint16_t chunk_num, byte* data,
                     std::uint32_t length, bool re_encrypt);
  bool QueueC0AndC1();
  bool ResetEncrypt();
  bool EncryptaChunk(std::string &input, std::string *output);
  void getPad_Iv_Key(size_t this_chunk_num,
                     boost::shared_array<byte> key,
                     boost::shared_array<byte> iv,
                     boost::shared_array<byte> pad);
  bool ProcessMainQueue();
  void AddReleventSeqDataToQueue();
  void EmptySequencer();
  bool CheckPositionInSequncer(std::uint64_t position,
                               std::uint32_t length); // maybe not necessary
  void ReadInProcessData(char * data,
                         std::uint32_t  length,
                         std::uint64_t position);
  void SequenceAllNonStandardChunksAndExtraContent();
 private:
  // Setters and Getters, testing only
  void set_chunk_size(size_t chunk_size) { chunk_size_ = chunk_size; }
  std::uint32_t chunk_size() { return chunk_size_; }

 private:
   // MEMBERS
  std::shared_ptr<DataMap> data_map_;
  Sequencer sequencer_;
  size_t chunk_size_;
  size_t min_chunk_size_;
  size_t length_;
  CryptoPP::SHA512  hash_;
  CryptoPP::MessageQueue main_encrypt_queue_;
  boost::shared_array<byte> chunk0_raw_;
  boost::shared_array<byte> chunk1_raw_;
  ChunkDetails chunk_data_;
  std::shared_ptr<ChunkStore> chunk_store_;
  bool chunk_one_two_q_full_;
  std::uint32_t c0_and_1_chunk_size_;
  std::uint64_t current_position_;
  bool readok_;
  bool repeated_chunks_;
  size_t q_position_;
  bool rewriting_;
  bool ignore_threads_;
  std::int8_t num_procs_;
  bool read_c0andc1_;
  std::uint64_t end_of_chunks_position_;
  bool cache_;
  boost::shared_array<char> data_cache_;
  uint64_t cache_initial_posn_;
};

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_UTILS_H_
