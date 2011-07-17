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
#include "boost/filesystem.hpp"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

struct SelfEncryptionParams;

namespace utils {

static int kCompressionRatio = 3; // optimised for speed

/// XOR transformation class for pipe-lining
class XORFilter : public CryptoPP::Bufferless<CryptoPP::Filter> {
public:
  XORFilter(CryptoPP::BufferedTransformation *attachment = NULL,
            std::string pad = ""):
                                       pad_(pad) {
   CryptoPP::Filter::Detach(attachment);
  };
   size_t Put2(const byte* inString,
               size_t length,
               int messageEnd,
               bool blocking);
   bool IsolatedFlush(bool, bool) { return false; }
private:
  std::string pad_;
};

class AESFilter : public CryptoPP::Bufferless<CryptoPP::Filter> {
public:
  AESFilter(CryptoPP::BufferedTransformation *attachment = NULL,
            std::string enc_hash = "", bool encrypt = true,
            std::string *result_hash = NULL): enc_hash_(enc_hash),
                                              encrypt_(encrypt) {
   CryptoPP::Filter::Detach(attachment);
  };
   size_t Put2(const byte* inString,
               size_t length,
               int messageEnd,
               bool blocking);
   bool IsolatedFlush(bool, bool) { return false; }
private:
  std::string enc_hash_;
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


class SEWrite {
public:
  SEWrite() {}
  std::string Write(const char* data, size_t length); // return data map
  bool FinishWrite();
private:
  SEWrite &operator = (const SEWrite&) {} // no assignment
  SEWrite (const SEWrite&) {} // no copy
  Anchor anchor_;
  CryptoPP::ChannelSwitch channel_switch_;
  
};


class SE { // Self Encryption of course
public:
  
  std::string Write(const char* data, size_t length); // return data map
  bool FinishWrite();
  std::iostream Read (const std::string &DataMap); // return file
  std::string PartialRead(const std::string &DataMap); // return some data

private:
  SE &operator = (const SE&) {} // no assignment 
  SE (const SE&) {} // no copy
  Anchor WriteAnchor;
  Anchor ReadAnchor;
  Anchor PartialReadAnchor;
  
};

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_UTILS_H_
