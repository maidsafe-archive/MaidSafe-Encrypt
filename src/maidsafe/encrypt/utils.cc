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
 * @file  utils.cc
 * @brief Helper functions for self-encryption engine.
 * @date  2008-09-09
 */

#include "maidsafe/encrypt/utils.h"

#include <algorithm>
#include <set>

#include <boost/functional/hash.hpp>
#include "boost/filesystem/fstream.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/log.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace utils {

bool IsCompressedFile(const fs::path &file_path) {
  size_t ext_count = sizeof(kNoCompressType) / sizeof(kNoCompressType[0]);
  std::set<std::string> exts(kNoCompressType, kNoCompressType + ext_count);
  return (exts.find(boost::to_lower_copy(file_path.extension().string())) !=
          exts.end());
}

/**
 * Tries to compress the given sample using the specified compression type.
 * If that yields savings of at least 10%, we assume this can be extrapolated to
 * all the data.
 *
 * @param sample A data sample.
 * @param self_encryption_type Compression type.
 * @return True if input data is likely compressible.
 */
bool CheckCompressibility(const std::string &sample,
                          const uint32_t &self_encryption_type) {
  if (sample.empty())
    return false;

  std::string compressed_sample(Compress(sample, self_encryption_type));
  double ratio = compressed_sample.size() / sample.size();
  return !compressed_sample.empty() && ratio <= 0.9;
}

/**
 * @param self_encryption_params Parameters for the self-encryption algorithm.
 * @return True if parameters sane.
 */
bool CheckParams(const SelfEncryptionParams &self_encryption_params) {
  if (self_encryption_params.max_chunk_size == 0) {
    DLOG(ERROR) << "CheckParams: Chunk size can't be zero." << std::endl;
    return false;
  }

  if (self_encryption_params.max_includable_data_size < kMinChunks - 1) {
    DLOG(ERROR) << "CheckParams: Max includable data size must be at least "
                << kMinChunks - 1 << "." << std::endl;
    return false;
  }

  if (kMinChunks * self_encryption_params.max_includable_chunk_size >=
      self_encryption_params.max_includable_data_size) {
    DLOG(ERROR) << "CheckParams: Max includable data size must be bigger than "
                   "all includable chunks." << std::endl;
    return false;
  }

  if (kMinChunks * self_encryption_params.max_chunk_size <
      self_encryption_params.max_includable_data_size) {
    DLOG(ERROR) << "CheckParams: Max includable data size can't be bigger than "
                << kMinChunks << " chunks." << std::endl;
    return false;
  }

  return true;
}

std::string Compress(const std::string &input,
                     const uint32_t &self_encryption_type) {
  switch (self_encryption_type & kCompressionMask) {
    case kCompressionNone:
      return input;
    case kCompressionGzip:
      return crypto::Compress(input, 9);
    default:
      DLOG(ERROR) << "Compress: Invalid compression type passed." << std::endl;
  }
  return "";
}

std::string Uncompress(const std::string &input,
                       const uint32_t &self_encryption_type) {
  switch (self_encryption_type & kCompressionMask) {
    case kCompressionNone:
      return input;
    case kCompressionGzip:
      return crypto::Uncompress(input);
    default:
      DLOG(ERROR) << "Uncompress: Invalid compression type passed."
                  << std::endl;
  }
  return "";
}

std::string Hash(const std::string &input,
                 const uint32_t &self_encryption_type) {
  switch (self_encryption_type & kHashingMask) {
    case kHashingSha1:
      return crypto::Hash<crypto::SHA1>(input);
    case kHashingSha512:
      return crypto::Hash<crypto::SHA512>(input);
    case kHashingTiger:
      return crypto::Hash<crypto::Tiger>(input);
    default:
      DLOG(ERROR) << "Hash: Invalid hashing type passed." << std::endl;
  }
  return "";
}

bool ResizeObfuscationHash(const std::string &input,
                           const size_t &required_size,
                           std::string *resized_data) {
  if (input.empty() || !resized_data)
    return false;
  if (required_size == 0)
    return true;

  *resized_data = Hash(input, kHashingSha512);  // Just to be sure
  resized_data->reserve(required_size + (required_size/2));
  std::string temp_data = *resized_data;
  while (resized_data->size() < required_size) {
    temp_data = Hash(temp_data, kHashingSha512);
    resized_data->append(temp_data);
  }
  resized_data->resize(required_size);  // reduce only
  return true;
}

std::string SelfEncryptChunk(const std::string &content,
                             const std::string &encryption_hash,
                             const std::string &obfuscation_hash,
                             const uint32_t &self_encryption_type) {
  if (content.empty() || encryption_hash.empty() || obfuscation_hash.empty()) {
    DLOG(ERROR) << "SelfEncryptChunk: Invalid arguments passed." << std::endl;
    return "";
  }

  // TODO(Steve) chain all of the following, do processing in-place

  // compression
  std::string processed_content(Compress(content, self_encryption_type));

  // obfuscation
  switch (self_encryption_type & kObfuscationMask) {
    case kObfuscationNone:
      break;
    case kObfuscationRepeated:
      {
        std::string obfuscation_pad;
        if (!utils::ResizeObfuscationHash(obfuscation_hash,
                                          processed_content.size(),
                                          &obfuscation_pad)) {
          DLOG(ERROR) << "SelfEncryptChunk: Could not create obfuscation pad."
                      << std::endl;
          return "";
        }
        processed_content = crypto::XOR(processed_content, obfuscation_pad);
      }
      break;
    default:
      DLOG(ERROR) << "SelfEncryptChunk: Invalid obfuscation type passed."
                  << std::endl;
      return "";
  }

  // encryption
  switch (self_encryption_type & kCryptoMask) {
    case kCryptoNone:
      break;
    case kCryptoAes256:
      {
        std::string enc_hash;
        if (!ResizeObfuscationHash(encryption_hash,
                                   crypto::AES256_KeySize +
                                       crypto::AES256_IVSize,
                                   &enc_hash)) {
          DLOG(ERROR) << "SelfEncryptChunk: Could not expand encryption hash."
                      << std::endl;
          return "";
        }
        processed_content = crypto::SymmEncrypt(
            processed_content,
            enc_hash.substr(0, crypto::AES256_KeySize),
            enc_hash.substr(crypto::AES256_KeySize, crypto::AES256_IVSize));
      }
      break;
    default:
      DLOG(ERROR) << "SelfEncryptChunk: Invalid encryption type passed."
                  << std::endl;
      return "";
  }

  return processed_content;
}

std::string SelfDecryptChunk(const std::string &content,
                             const std::string &encryption_hash,
                             const std::string &obfuscation_hash,
                             const uint32_t &self_encryption_type) {
  if (content.empty() || encryption_hash.empty() || obfuscation_hash.empty()) {
    DLOG(ERROR) << "SelfDecryptChunk: Invalid arguments passed." << std::endl;
    return "";
  }

  std::string processed_content(content);

  // TODO(Steve) chain all of the following, do processing in-place

  // decryption
  switch (self_encryption_type & kCryptoMask) {
    case kCryptoNone:
      break;
    case kCryptoAes256:
      {
        std::string enc_hash;
        if (!ResizeObfuscationHash(encryption_hash,
                                   crypto::AES256_KeySize +
                                       crypto::AES256_IVSize,
                                   &enc_hash)) {
          DLOG(ERROR) << "SelfDecryptChunk: Could not expand encryption hash."
                      << std::endl;
          return "";
        }
        processed_content = crypto::SymmDecrypt(
            processed_content,
            enc_hash.substr(0, crypto::AES256_KeySize),
            enc_hash.substr(crypto::AES256_KeySize, crypto::AES256_IVSize));
      }
      break;
    default:
      DLOG(ERROR) << "SelfDecryptChunk: Invalid encryption type passed."
                  << std::endl;
      return "";
  }

  // de-obfuscation
  switch (self_encryption_type & kObfuscationMask) {
    case kObfuscationNone:
      break;
    case kObfuscationRepeated:
      {
        std::string obfuscation_pad;
        if (!utils::ResizeObfuscationHash(obfuscation_hash,
                                          processed_content.size(),
                                          &obfuscation_pad)) {
          DLOG(ERROR) << "SelfDecryptChunk: Could not create obfuscation pad."
                      << std::endl;
          return "";
        }
        processed_content = crypto::XOR(processed_content, obfuscation_pad);
      }
      break;
    default:
      DLOG(ERROR) << "SelfDecryptChunk: Invalid obfuscation type passed."
                  << std::endl;
      return "";
  }

  // decompression
  return Uncompress(processed_content, self_encryption_type);
}

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe
