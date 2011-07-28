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

struct SelfEncryptionParams;

namespace utils {

static int kCompressionRatio = 3; // optimised for speed

/// XOR transformation class for pipe-lining
class XORFilter : public CryptoPP::Bufferless<CryptoPP::Filter> {
public:
  XORFilter(CryptoPP::BufferedTransformation *attachment = NULL,
            byte *pad = NULL, size_t pad_length = 0):
            pad_(pad),
            pad_length_(pad_length) {
   CryptoPP::Filter::Detach(attachment);
  };
   size_t Put2(const byte* inString,
               size_t length,
               int messageEnd,
               bool blocking);
   bool IsolatedFlush(bool, bool) { return false; }
private:
  byte *pad_;
  size_t pad_length_;
};

class AESFilter : public CryptoPP::Bufferless<CryptoPP::Filter> {
public:
  AESFilter(CryptoPP::BufferedTransformation *attachment = NULL,
            byte *key = NULL, byte *iv = NULL, bool encrypt = true) :
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

/// Checks file extension against a list of known uncompressible file formats.
bool IsCompressedFile(const fs::path &file_path);

/// Estimates whether compression could result in space savings.
bool CheckCompressibility(const std::string &sample,
                          const uint32_t &self_encryption_type);

/// Verifies sanity of parameter values.
bool CheckParams(const SelfEncryptionParams &self_encryption_params);

/// Compresses a string.
std::string Compress(const std::string &input,
                     const uint32_t &self_encryption_type);

/// Uncompresses a string.
std::string Uncompress(const std::string &input,
                       const uint32_t &self_encryption_type);

/// Calculates the cryptographic hash of a string.
std::string Hash(const std::string &input,
                 const uint32_t &self_encryption_type);

/// Deterministically expands an input string to the required size.
bool ResizeObfuscationHash(const std::string &input,
                           const size_t &required_size,
                           std::string *resized_data);

std::string XOR(const std::string data, const std::string pad);

/// Applies self-encryption algorithm to the contents of a chunk
bool SelfEncryptChunk(std::shared_ptr<std::string> content,
                             const std::string &encryption_hash,
                             const std::string &obfuscation_hash,
                             const uint32_t &self_encryption_type);

/// Applies self-decryption algorithm to the contents of a chunk
bool SelfDecryptChunk(std::shared_ptr<std::string> content,
                             const std::string &encryption_hash,
                             const std::string &obfuscation_hash,
                             const uint32_t &self_encryption_type);



class SE { // Self Encryption of course
public:
  SE(std::shared_ptr<ChunkStore> chunk_store) :
                        data_map_(), complete_(false), chunk_size_(1024*256),
                        min_chunk_size_(1024),
                        main_encrypt_queue_(CryptoPP::MessageQueue()),
                        current_chunk_hash_filter_(hash_,new 
                                          CryptoPP::StringSink(current_chunk_and_hash_),
                                          true),
                        chunk1_hash_filter(hash_, new
                                           CryptoPP::StringSink(chunk1_and_hash_),
                                           true),
                        chunk2_hash_filter(hash_, new
                                           CryptoPP::StringSink(chunk2_and_hash_),
                                           true),
                        chunk_store_(chunk_store),
                        length_(0)
                        {}
  bool Write(const char* data, size_t length, bool complete);
  bool Read (char * data);
  bool PartialRead(char * data, size_t position, size_t length);
  DataMap2 getDataMap() { return data_map_; }

private:
  SE &operator = (const SE&) {} // no assignment 
//  SE (const SE&) {} // no copy
  bool EncryptChunkFromQueue(size_t chunk);
  bool EncryptaChunk(std::string &input, std::string *output);
  DataMap2 data_map_;
  bool complete_; // in case of requirement to send a complete only
  size_t chunk_size_;
  size_t min_chunk_size_;
  size_t length_;
  byte key_[32];
  byte iv_[16];
  byte obfuscation_pad_[128];
  CryptoPP::SHA512  hash_;
  std::string chunk1_and_hash_;
  std::string chunk2_and_hash_;
  std::string current_chunk_and_hash_;
  CryptoPP::MessageQueue main_encrypt_queue_;
  CryptoPP::HashFilter current_chunk_hash_filter_;
  CryptoPP::HashFilter chunk1_hash_filter; //(hash_, true); // hash and data
  CryptoPP::HashFilter chunk2_hash_filter; // (hash_, true);
  ChunkDetails2 chunk_data_;
  std::shared_ptr<ChunkStore> chunk_store_;
};

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_UTILS_H_
