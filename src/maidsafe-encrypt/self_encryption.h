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
#include "maidsafe-encrypt/version.h"

#if MAIDSAFE_ENCRYPT_VERSION < 1
#error This API is not compatible with the installed library.\
  Please update the maidsafe-encrypt library.
#endif

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace protobuf { class DataMap; }

/// Generate secure chunks from a file.
int SelfEncryptFile(const fs::path &input_file,
                    const fs::path &output_dir,
                    protobuf::DataMap *data_map);

/// Generate secure chunks from a string.
int SelfEncryptString(const std::string &input_string,
                      const fs::path &output_dir,
                      protobuf::DataMap *data_map);

/// Assemble a file from secure chunks.
int SelfDecryptToFile(const protobuf::DataMap &data_map,
                      const std::vector<fs::path> &chunk_paths,
                      const std::uint64_t &offset,
                      bool overwrite,
                      const fs::path &output_file);

/// Assemble a string from secure chunks.
int SelfDecryptToString(const protobuf::DataMap &data_map,
                        const std::vector<fs::path> &chunk_paths,
                        const boost::uint64_t &offset,
                        std::shared_ptr<std::string> output_string);

/// Encrypts a DataMap to a string.
int EncryptDataMap(const protobuf::DataMap &data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   std::string *encrypted_data_map);

/// Decrypts an encrypted DataMap.
int DecryptDataMap(const std::string &encrypted_data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   protobuf::DataMap *data_map);

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELF_ENCRYPTION_H_
