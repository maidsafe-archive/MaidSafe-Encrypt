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
#include "boost/filesystem.hpp"

#include "maidsafe/encrypt/data_map.h"
#include <common/crypto.h>
#include <cryptopp/aes.h>
#include <boost/concept_check.hpp>


namespace fs = boost::filesystem;

namespace maidsafe {

class ChunkStore;

namespace encrypt {

/// XOR transformation class for pipe-lining
class XORFilter : public CryptoPP::Bufferless<CryptoPP::Filter> {
public:
  XORFilter(CryptoPP::BufferedTransformation *attachment = NULL,
            byte *pad = NULL) : pad_(pad)
            {
   CryptoPP::Filter::Detach(attachment);
  };
   size_t Put2(const byte* inString,
               size_t length,
               int messageEnd,
               bool blocking);
   bool IsolatedFlush(bool, bool) { return false; }
private:
  XORFilter &operator = (const XORFilter&); // no assignment
  XORFilter(const XORFilter&); // no copy
  byte *pad_;
};

class AESFilter : public CryptoPP::Bufferless<CryptoPP::Filter> {
public:
  AESFilter(CryptoPP::BufferedTransformation *attachment = NULL,
            byte *key = NULL , byte *iv = NULL, bool encrypt = true) :
                                              key_(key),
                                              iv_(iv),
                                              encrypt_(encrypt) {
   CryptoPP::Filter::Detach(attachment);
  };
   size_t Put2(const byte* inString,
               size_t length,
               int messageEnd,
               bool blocking);
   bool IsolatedFlush(bool, bool) { return false; }
private:
  AESFilter &operator = (const AESFilter&); // no assignment
  AESFilter(const AESFilter&); // no copy
  byte *key_;
  byte *iv_;
  bool encrypt_;
};


// Anchor class to allow detach and attach of transforms
// this will allow us to work with self encryption flags as is
class Anchor : public CryptoPP::Bufferless<CryptoPP::Filter>
{
public:
    Anchor(CryptoPP::BufferedTransformation* attachment = NULL)
        { CryptoPP::Filter::Detach(attachment); };
        
    size_t Put2(const byte * inString,
                size_t length,
                int messageEnd,
                bool blocking ) {
        return AttachedTransformation()->Put2(
            inString, length, messageEnd, blocking );
    }
};



class SE { // Self Encryption of course
public:
  SE(std::shared_ptr<ChunkStore> chunk_store) :
                        data_map_(), complete_(false), chunk_size_(1024*256),
                        min_chunk_size_(1024), length_(), hash_(),
                        main_encrypt_queue_(CryptoPP::MessageQueue()),
                        chunk1_queue_(CryptoPP::MessageQueue()),
                        chunk2_queue_(CryptoPP::MessageQueue()),
                        chunk_current_queue_(CryptoPP::MessageQueue()),
                        chunk_data_(),
                        chunk_store_(chunk_store),
                        chunk_one_two_q_full_(false)
                        {}
  bool Write(const char* data = NULL, size_t length = 0);
  bool ReInitialise();
  bool FinaliseWrite(); // process what's left in queue and chunk 0 and 1
  bool Read (char * data, std::shared_ptr<DataMap2> data_map);
  bool PartialRead(char * data, size_t position, size_t length,
                   std::shared_ptr<DataMap2> data_map);
  DataMap2 getDataMap() { return data_map_; }

private:
  SE &operator = (const SE&); // no assignment
  SE(const SE&); // no copy
  bool QueueC1AndC2();
  bool EncryptChunkFromQueue(CryptoPP::MessageQueue & queue);
  bool ResetEncrypt();
  bool EncryptChunkFromQueue(size_t chunk);
  bool EncryptaChunk(std::string &input, std::string *output);
private:  
  DataMap2 data_map_;
  bool complete_; // in case of requirement to send a complete only
  size_t chunk_size_;
  size_t min_chunk_size_;
  size_t length_;
  CryptoPP::SHA512  hash_;
  CryptoPP::MessageQueue main_encrypt_queue_;
  CryptoPP::MessageQueue chunk1_queue_;
  CryptoPP::MessageQueue chunk2_queue_;
  CryptoPP::MessageQueue chunk_current_queue_;
  ChunkDetails2 chunk_data_;
  std::shared_ptr<ChunkStore> chunk_store_;
  bool chunk_one_two_q_full_;
};

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_UTILS_H_
