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

#include "maidsafe-encrypt/utils.h"

#include <algorithm>
#include <set>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-encrypt/config.h"
#include "maidsafe-encrypt/data_map.h"
#include "boost/filesystem/fstream.hpp"

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
 * Reads a small part from the current stream position and tries to compress
 * it. If that yields savings of at least 10%, we assume this can be
 * extrapolated to all the data.
 *
 * @pre Stream offset at middle of data or an otherwise representative spot.
 * @param input_stream The data source.
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

  return true;
}

/**
 * Limits with fixed 256K chunk size are:
 *   <= kMaxIncludableDataSize ---> to DM
 *   kMaxIncludableDataSize + 1 to kMinChunks * kDefaultChunkSize - 1 --->
 *       size = fsize / kMinChunks
 *   >= kMinChunks * kDefaultChunkSize ---> fixed size + remainder
 *
 * @param data_size Size of the input data.
 * @param self_encryption_params Parameters for the self-encryption algorithm.
 * @param chunk_sizes Pointer to a chunk size vector to be populated.
 * @return True if operation was successful.
 */
bool CalculateChunkSizes(const std::uint64_t &data_size,
                         const SelfEncryptionParams &self_encryption_params,
                         std::vector<std::uint32_t> *chunk_sizes) {
  if (!chunk_sizes) {
    DLOG(ERROR) << "CalculateChunkSizes: Pointer is NULL."
                << std::endl;
    return false;
  }

  if (data_size <= self_encryption_params.max_includable_data_size ||
      data_size < kMinChunks) {
    DLOG(ERROR) << "CalculateChunkSizes: Data should go directly into DataMap."
                << std::endl;
    return false;
  }

  std::uint64_t chunk_count, chunk_size;
  bool fixed_chunks(false);
  if (data_size < kMinChunks * self_encryption_params.max_chunk_size) {
    chunk_count = kMinChunks;
    chunk_size = data_size / kMinChunks;
  } else {
    chunk_count = data_size / self_encryption_params.max_chunk_size;
    chunk_size = self_encryption_params.max_chunk_size;
    fixed_chunks = true;
  }

  std::uint64_t remainder(data_size);
  std::uint64_t limit(fixed_chunks ? chunk_count : chunk_count - 1);
  for (std::uint64_t i = 0; i < limit; ++i) {
    chunk_sizes->push_back(chunk_size);
    remainder -= chunk_size;
  }
  if (remainder != 0)
    chunk_sizes->push_back(remainder);

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

  resized_data->resize(required_size);
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
      processed_content = crypto::SymmEncrypt(
          processed_content,
          encryption_hash.substr(0, crypto::AES256_KeySize),
          encryption_hash.substr(crypto::AES256_KeySize,
                                 crypto::AES256_IVSize));
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
      processed_content = crypto::SymmDecrypt(
          processed_content,
          encryption_hash.substr(0, crypto::AES256_KeySize),
          encryption_hash.substr(crypto::AES256_KeySize,
                                 crypto::AES256_IVSize));
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
