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

#include <cstdint>
#include <string>

#include "cryptopp/cryptlib.h"
#include "cryptopp/files.h"
#include "cryptopp/channels.h"
#include "cryptopp/mqueue.h"
#include "cryptopp/sha.h"
#include "cryptopp/aes.h"
#include "common/crypto.h"
#include "boost/filesystem.hpp"
#include "boost/scoped_array.hpp"
#include "boost/concept_check.hpp"
#include "maidsafe/encrypt/data_map.h"

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

// Anchor class to allow detach and attach of transforms
// this will allow us to work with self encryption flags as is
class Anchor : public CryptoPP::Bufferless<CryptoPP::Filter> {
 public:
  Anchor(CryptoPP::BufferedTransformation* attachment = NULL) {
    CryptoPP::Filter::Detach(attachment);
  };
  size_t Put2(const byte * inString,
              size_t length,
              int messageEnd,
              bool blocking ) {
    return AttachedTransformation()->Put2(inString, length,
                                          messageEnd, blocking);
  }
};

class SE {  // Self Encryption of course
 public:
  SE(std::shared_ptr<ChunkStore> chunk_store) :
                        data_map_(), complete_(false), chunk_size_(1024*256),
                        min_chunk_size_(1024), length_(), hash_(),
                        main_encrypt_queue_(CryptoPP::MessageQueue()),
                        chunk0_queue_(CryptoPP::MessageQueue()),
                        chunk1_queue_(CryptoPP::MessageQueue()),
                        chunk_current_queue_(CryptoPP::MessageQueue()),
                        chunk_data_(),
                        chunk_store_(chunk_store),
                        chunk_one_two_q_full_(false), c0_and_1_chunk_size_(),
                        this_chunk_size_()
                        { }
  bool Write(const char* data = NULL, size_t length = 0);
  bool ReInitialise();
  bool FinaliseWrite();  // process what's left in queue and chunk 0 and 1
  bool Read(char * data, std::shared_ptr<DataMap2> data_map);
  bool PartialRead(char * data, size_t position, size_t length,
                   std::shared_ptr<DataMap2> data_map);
  DataMap2 getDataMap() { return data_map_; }
  bool EncryptChunkFromQueue(CryptoPP::MessageQueue & queue);
 private:
  SE &operator = (const SE&);  // no assignment
  SE(const SE&);  // no copy
  bool QueueC1AndC2();
  void HashMe(byte * digest, byte *data, size_t length);
  bool ResetEncrypt();
  bool EncryptaChunk(std::string &input, std::string *output);
 private:
  DataMap2 data_map_;
  bool complete_;  // in case of requirement to send a complete only
  size_t chunk_size_;
  size_t min_chunk_size_;
  size_t length_;
  CryptoPP::SHA512  hash_;
  CryptoPP::MessageQueue main_encrypt_queue_;
  CryptoPP::MessageQueue chunk0_queue_;
  CryptoPP::MessageQueue chunk1_queue_;
  CryptoPP::MessageQueue chunk_current_queue_;
  ChunkDetails2 chunk_data_;
  std::shared_ptr<ChunkStore> chunk_store_;
  bool chunk_one_two_q_full_;
  size_t c0_and_1_chunk_size_;
  size_t this_chunk_size_;
};

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_UTILS_H_
