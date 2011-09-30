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
  double ratio = static_cast<double>(compressed_sample.size()) / sample.size();
  return !compressed_sample.empty() && ratio <= 0.9;
}

/**
 * @param self_encryption_params Parameters for the self-encryption algorithm.
 * @return True if parameters sane.
 */
bool CheckParams(const SelfEncryptionParams &self_encryption_params) {
  if (self_encryption_params.max_chunk_size == 0) {
    DLOG(ERROR) << "CheckParams: Chunk size can't be zero.";
    return false;
  }

  if (self_encryption_params.max_includable_data_size < kMinChunks - 1) {
    DLOG(ERROR) << "CheckParams: Max includable data size must be at least "
                << kMinChunks - 1 << ".";
    return false;
  }

  if (kMinChunks * self_encryption_params.max_includable_chunk_size >=
      self_encryption_params.max_includable_data_size) {
    DLOG(ERROR) << "CheckParams: Max includable data size must be bigger than "
                   "all includable chunks.";
    return false;
  }

  if (kMinChunks * self_encryption_params.max_chunk_size <
      self_encryption_params.max_includable_data_size) {
    DLOG(ERROR) << "CheckParams: Max includable data size can't be bigger than "
                << kMinChunks << " chunks.";
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
      DLOG(ERROR) << "Compress: Invalid compression type passed.";
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
      DLOG(ERROR) << "Uncompress: Invalid compression type passed.";
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
      DLOG(ERROR) << "Hash: Invalid hashing type passed.";
  }
  return "";
}

/**
 * We expand the input string by simply repeating it until we reach the required
 * output size. Instead of just repeating it, we could as well repeatedly hash
 * it and append the resulting hashes. But this is thought to not be any more
 * secure than simple repetition when used together with encryption, just a lot
 * slower, so we avoid it until disproven.
 */
bool ResizeInput(const std::string &input,
                 const size_t &required_size,
                 std::string *resized_data) {
  if (input.empty() || !resized_data)
    return false;

  resized_data->resize(required_size);
  if (required_size == 0)
    return true;
  size_t input_size(std::min(input.size(), required_size)), copied(input_size);
  memcpy(&((*resized_data)[0]), input.data(), input_size);
  while (copied < required_size) {
    // input_size = std::min(input.size(), required_size - copied);  // slow
    input_size = std::min(copied, required_size - copied);  // fast
    memcpy(&((*resized_data)[copied]), resized_data->data(), input_size);
    copied += input_size;
  }
  return true;
}

std::string SelfEncryptChunk(const std::string &content,
                             const std::string &own_hash,
                             const std::string &encryption_hash,
                             const std::string &obfuscation_hash,
                             const uint32_t &self_encryption_type) {
  if (content.empty() || own_hash.empty() || encryption_hash.empty() ||
      obfuscation_hash.empty()) {
    DLOG(ERROR) << "SelfEncryptChunk: Invalid arguments passed.";
    return "";
  }

  // TODO(Steve) chain all of the following, do processing in-place

  // compression
  std::string processed_content(Compress(content, self_encryption_type));

  // encryption
  switch (self_encryption_type & kCryptoMask) {
    case kCryptoNone:
      break;
    case kCryptoAes256:
      {
        std::string enc_hash;
        if (!ResizeInput(encryption_hash,
                         crypto::AES256_KeySize + crypto::AES256_IVSize,
                         &enc_hash)) {
          DLOG(ERROR) << "SelfEncryptChunk: Could not expand encryption hash.";
          return "";
        }
        processed_content = crypto::SymmEncrypt(
            processed_content,
            enc_hash.substr(0, crypto::AES256_KeySize),
            enc_hash.substr(crypto::AES256_KeySize, crypto::AES256_IVSize));
      }
      break;
    default:
      DLOG(ERROR) << "SelfEncryptChunk: Invalid encryption type passed.";
      return "";
  }

  // obfuscation
  switch (self_encryption_type & kObfuscationMask) {
    case kObfuscationNone:
      break;
    case kObfuscationRepeated:
      {
        std::string obfuscation_pad;
        // concatenate any remainder of the encryption hash to the obfuscation
        // hash and lastly concatenate the chunk's own hash
        if (!utils::ResizeInput(
              obfuscation_hash +
                  ((encryption_hash.size() >
                      (crypto::AES256_KeySize + crypto::AES256_IVSize)) ?
                          encryption_hash.substr(crypto::AES256_KeySize +
                                                 crypto::AES256_IVSize) : "") +
                  own_hash,
              processed_content.size(),
              &obfuscation_pad)) {
          DLOG(ERROR) << "SelfEncryptChunk: Could not create obfuscation pad.";
          return "";
        }
        processed_content = crypto::XOR(processed_content, obfuscation_pad);
      }
      break;
    default:
      DLOG(ERROR) << "SelfEncryptChunk: Invalid obfuscation type passed.";
      return "";
  }

  return processed_content;
}

std::string SelfDecryptChunk(const std::string &content,
                             const std::string &own_hash,
                             const std::string &encryption_hash,
                             const std::string &obfuscation_hash,
                             const uint32_t &self_encryption_type) {
  if (content.empty() || own_hash.empty() || encryption_hash.empty() ||
      obfuscation_hash.empty()) {
    DLOG(ERROR) << "SelfDecryptChunk: Invalid arguments passed.";
    return "";
  }

  std::string processed_content(content);

  // TODO(Steve) chain all of the following, do processing in-place

  // de-obfuscation
  switch (self_encryption_type & kObfuscationMask) {
    case kObfuscationNone:
      break;
    case kObfuscationRepeated:
      {
        std::string obfuscation_pad;
        // concatenate any remainder of the encryption hash to the obfuscation
        // hash and lastly concatenate the chunk's own hash
        if (!utils::ResizeInput(
              obfuscation_hash +
                  ((encryption_hash.size() >
                      (crypto::AES256_KeySize + crypto::AES256_IVSize)) ?
                          encryption_hash.substr(crypto::AES256_KeySize +
                                                 crypto::AES256_IVSize) : "") +
                  own_hash,
              processed_content.size(),
              &obfuscation_pad)) {
          DLOG(ERROR) << "SelfDecryptChunk: Could not create obfuscation pad.";
          return "";
        }
        processed_content = crypto::XOR(processed_content, obfuscation_pad);
      }
      break;
    default:
      DLOG(ERROR) << "SelfDecryptChunk: Invalid obfuscation type passed.";
      return "";
  }

  // decryption
  switch (self_encryption_type & kCryptoMask) {
    case kCryptoNone:
      break;
    case kCryptoAes256:
      {
        std::string enc_hash;
        if (!ResizeInput(encryption_hash,
                         crypto::AES256_KeySize + crypto::AES256_IVSize,
                         &enc_hash)) {
          DLOG(ERROR) << "SelfDecryptChunk: Could not expand encryption hash.";
          return "";
        }
        processed_content = crypto::SymmDecrypt(
            processed_content,
            enc_hash.substr(0, crypto::AES256_KeySize),
            enc_hash.substr(crypto::AES256_KeySize, crypto::AES256_IVSize));
      }
      break;
    default:
      DLOG(ERROR) << "SelfDecryptChunk: Invalid encryption type passed.";
      return "";
  }

  // decompression
  return Uncompress(processed_content, self_encryption_type);
}

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe
