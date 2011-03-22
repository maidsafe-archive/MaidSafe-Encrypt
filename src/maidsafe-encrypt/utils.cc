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
 *
 * @todo  Allow for different types of obfuscation and encryption, including an
 *        option for no obf. and/or no enc.
 * @todo  Add support for large DataMaps (recursion).
 */

#include "maidsafe-encrypt/utils.h"

#include <set>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-encrypt/config.h"
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
bool CheckCompressibility(std::shared_ptr<std::istream> input_stream) {
  if (!input_stream || !input_stream->good())
    return false;

  std::string test_data(kCompressionSampleSize, 0);
  input_stream->read(&(test_data[0]), kCompressionSampleSize);
  test_data.resize(input_stream->gcount());

  if (test_data.empty())
    return false;

  std::string compressed_test_data(crypto::Compress(test_data,
                                                    kCompressionLevel));
  if (!compressed_test_data.empty()) {
    double ratio = compressed_test_data.size() / test_data.size();
    return (ratio <= 0.9);
  } else {
    DLOG(ERROR) << "CheckCompressibility: Error checking compressibility."
                << std::endl;
    return false;
  }
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

bool ResizeObfuscationHash(const std::string &input,
                           const size_t &required_size,
                           std::string *resized_data) {
  if (!resized_data) {
    DLOG(ERROR) << "ResizeObfuscationHash: resized_data null." << std::endl;
    return false;
  }
  resized_data->clear();
  resized_data->reserve(required_size);
  std::string hash(input);
  while (resized_data->size() < required_size) {
    hash = crypto::Hash<crypto::SHA512>(hash);
    resized_data->append(hash);
  }
  resized_data->resize(required_size);
  return true;
}

bool ReadFile(const fs::path &file_path, std::string *content) {
  if (!content)
    return false;
  try {
    std::uintmax_t file_size(fs::file_size(file_path));
    fs::ifstream file_in(file_path, std::ios::in | std::ios::binary);
    if (!file_in.good())
      return false;
    content->resize(file_size);
    file_in.read(&((*content)[0]), file_size);
    file_in.close();
  }
  catch(...) {
    return false;
  }
  return true;
}

bool WriteFile(const fs::path &file_path, const std::string &content) {
  try {
    fs::ofstream file_out(file_path, std::ios::out | std::ios::trunc |
                                     std::ios::binary);
    file_out.write(content.data(), content.size());
    file_out.close();
  }
  catch(...) {
    return false;
  }
  return true;
}

std::string SelfEncryptChunk(const std::string &content,
                             const std::string &encryption_hash,
                             const std::string &obfuscation_hash) {
  std::string encryption_key(encryption_hash.substr(0, crypto::AES256_KeySize));
  std::string encryption_iv(encryption_hash.substr(crypto::AES256_KeySize,
                                                   crypto::AES256_IVSize));

  std::string obfuscation_pad;
  utils::ResizeObfuscationHash(obfuscation_hash, content.size(),
                               &obfuscation_pad);

  // obfuscate and encrypt chunk data
  return crypto::SymmEncrypt(crypto::XOR(content, obfuscation_pad),
                             encryption_key, encryption_iv);
}

std::string SelfDecryptChunk(const std::string &content,
                             const std::string &encryption_hash,
                             const std::string &obfuscation_hash) {
  std::string encryption_key(encryption_hash.substr(0, crypto::AES256_KeySize));
  std::string encryption_iv(encryption_hash.substr(crypto::AES256_KeySize,
                                                   crypto::AES256_IVSize));

  // decrypt chunk data
  std::string temp_content = crypto::SymmDecrypt(content, encryption_key,
                                                 encryption_iv);

  // de-obfuscate chunk data
  std::string obfuscation_pad;
  utils::ResizeObfuscationHash(obfuscation_hash, temp_content.size(),
                               &obfuscation_pad);
  return crypto::XOR(temp_content, obfuscation_pad);
}

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe
