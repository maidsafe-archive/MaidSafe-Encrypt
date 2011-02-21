/*******************************************************************************
 *  Copyright 2008 maidsafe.net limited                                        *
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
#include <iostream>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"

namespace fs = boost::filesystem3;

namespace maidsafe {

namespace encrypt {

namespace utils {

/// Checks file extension against a list of known uncompressible file formats.
bool IsCompressedFile(const fs::path &file_path);

/// Estimates whether compression could result in space savings.
bool CheckCompressibility(std::istream *input_stream);

/// Determines the sizes of the chunks the input data will be split into.
bool CalculateChunkSizes(std::uint64_t data_size,
                         std::vector<std::uint32_t> *chunk_sizes);

/// Deterministically expands an input string to the required size.
bool ResizeObfuscationHash(const std::string &input,
                           const size_t &required_size,
                           std::string *resized_data);

/// Reads the given file and returns the contents as a string
bool ReadFile(const fs::path &file_path, std::string *content);

/// Writes the given content string to a file, overwriting if applicable
bool WriteFile(const fs::path &file_path, const std::string &content);

/// Applies self-encryption algorithm to the contents of a chunk
std::string SelfEncryptChunk(const std::string &content,
                             const std::string &encryption_hash,
                             const std::string &obfuscation_hash);

/// Applies self-decryption algorithm to the contents of a chunk
std::string SelfDecryptChunk(const std::string &content,
                             const std::string &encryption_hash,
                             const std::string &obfuscation_hash);

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_UTILS_H_
