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
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

class DataIOHandler;

namespace protobuf { class DataMap; }

namespace utils {

int EncryptContent(std::shared_ptr<DataIOHandler> input_handler,
                   const fs::path &output_dir,
                   protobuf::DataMap *data_map,
                   std::map<std::string, fs::path> *to_chunk_store);
int DecryptContent(const protobuf::DataMap &data_map,
                   std::vector<fs::path> chunk_paths,
                   const std::uint64_t &offset,
                   std::shared_ptr<DataIOHandler> output_handler);
int EncryptDataMap(const protobuf::DataMap &data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   std::string *encrypted_data_map);
int DecryptDataMap(const std::string &encrypted_data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   protobuf::DataMap *data_map);
// check to ensure entry is encryptable
int CheckEntry(std::shared_ptr<DataIOHandler> input_handler);
bool CheckCompressibility(std::shared_ptr<DataIOHandler> input_handler);
bool CalculateChunkSizes(const std::string &file_hash,
                         std::shared_ptr<DataIOHandler> input_handler,
                         protobuf::DataMap *data_map,
                         std::uint16_t *chunk_count);
// returns a positive or negative int based on char passed into it to
// allow for random chunk sizes '0' returns -8, '1' returns -7, etc...
// through to 'f' returns 7
int ChunkAddition(char hex_digit);
bool GeneratePreEncryptionHashes(
    std::shared_ptr<DataIOHandler> input_handler,
    protobuf::DataMap *data_map);
// Generate a string of required_size from input in a repeatable way
bool ResizeObfuscationHash(const std::string &input,
                           const size_t &required_size,
                           std::string *resized_data);
// ensure uniqueness of all chunk hashes (unless chunks are identical)
// if pre_encryption is true, hashes relate to pre-encryption, otherwise post-
bool HashUnique(const protobuf::DataMap &data_map,
                bool pre_encryption,
                std::string *hash);

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_UTILS_H_
