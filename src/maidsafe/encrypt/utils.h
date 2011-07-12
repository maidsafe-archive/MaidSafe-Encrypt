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

#include "boost/filesystem.hpp"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

struct SelfEncryptionParams;

namespace utils {

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
bool ResizeInput(const std::string &input,
                           const size_t &required_size,
                           std::string *resized_data);

/// Applies self-encryption algorithm to the contents of a chunk
std::string SelfEncryptChunk(const std::string &content,
                             const std::string &own_hash,
                             const std::string &encryption_hash,
                             const std::string &obfuscation_hash,
                             const uint32_t &self_encryption_type);

/// Applies self-decryption algorithm to the contents of a chunk
std::string SelfDecryptChunk(const std::string &content,
                             const std::string &own_hash,
                             const std::string &encryption_hash,
                             const std::string &obfuscation_hash,
                             const uint32_t &self_encryption_type);

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_UTILS_H_
