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
 * @file  self_encryption.h
 * @brief Provides self-encryption/self-decryption functionality.
 * @date  2008-09-09
 */

#ifndef MAIDSAFE_ENCRYPT_SELF_ENCRYPTION_H_
#define MAIDSAFE_ENCRYPT_SELF_ENCRYPTION_H_

#include <cstdint>
#include <memory>
#include <map>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace protobuf { class DataMap; }

// Encrypt input_file.  Derived chunks will be created in output_dir.  If
// data_map already has entry for file hash, this will be used.
int SelfEncryptFile(const fs::path &input_file,
                    const fs::path &output_dir,
                    protobuf::DataMap *data_map);

// Encrypt input_string.  Derived chunks will be created in output_dir.  If
// data_map already has entry for file hash, this will be used.
int SelfEncryptString(const std::string &input_string,
                      const fs::path &output_dir,
                      protobuf::DataMap *data_map);

// Decrypt chunks to output_file starting at chunklet spanning offset point.
// All neccessary chunks should be available and listed in chunk_paths
// (preferrably in same order as listed in data_map) and named as hex-encoded
// encrypted_chunk_name.
int SelfDecryptToFile(const protobuf::DataMap &data_map,
                      const std::vector<fs::path> &chunk_paths,
                      const std::uint64_t &offset,
                      bool overwrite,
                      const fs::path &output_file);

// Decrypt chunks to output_string starting at chunklet spanning offset point.
// All neccessary chunks should be available and listed in chunk_paths
// (preferrably in same order as listed in data_map) and named as hex-encoded
// encrypted_chunk_name.
int SelfDecryptToString(const protobuf::DataMap &data_map,
                        const std::vector<fs::path> &chunk_paths,
                        const boost::uint64_t &offset,
                        std::shared_ptr<std::string> output_string);

/// Encrypt a DataMap to a string
int EncryptDataMap(const protobuf::DataMap &data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   std::string *encrypted_data_map);

/// Decrypt an encrypted DataMap
int DecryptDataMap(const std::string &encrypted_data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   protobuf::DataMap *data_map);

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELF_ENCRYPTION_H_
