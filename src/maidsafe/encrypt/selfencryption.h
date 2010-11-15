/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Self-encrypts/self-decrypts files
* Version:      1.0
* Created:      09/09/2008 12:14:35 PM
* Revision:     none
* Compiler:     gcc
* Author:       David Irvine (di), david.irvine@maidsafe.net
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_ENCRYPT_SELFENCRYPTION_H_
#define MAIDSAFE_ENCRYPT_SELFENCRYPTION_H_

#include <boost/cstdint.hpp>
#include <boost/filesystem.hpp>
#include <boost/tr1/memory.hpp>

#include <map>
#include <string>
#include <vector>

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

class DataMap;

// Encrypt input_file.  Derived chunks will be created in output_dir.  If
// data_map already has entry for file hash, this will be used.
int SelfEncryptFile(const fs::path &input_file,
                    const fs::path &output_dir,
                    DataMap *data_map);

// Encrypt input_string.  Derived chunks will be created in output_dir.  If
// data_map already has entry for file hash, this will be used.
int SelfEncryptString(const std::string &input_string,
                      const fs::path &output_dir,
                      DataMap *data_map);

// Decrypt chunks to output_file starting at chunklet spanning offset point.
// All neccessary chunks should be available and listed in chunk_paths
// (preferrably in same order as listed in data_map) and named as hex-encoded
// encrypted_chunk_name.
int SelfDecryptToFile(const DataMap &data_map,
                      const std::vector<fs::path> &chunk_paths,
                      const boost::uint64_t &offset,
                      bool overwrite,
                      const fs::path &output_file);

// Decrypt chunks to output_string starting at chunklet spanning offset point.
// All neccessary chunks should be available and listed in chunk_paths
// (preferrably in same order as listed in data_map) and named as hex-encoded
// encrypted_chunk_name.
int SelfDecryptToString(const DataMap &data_map,
                        const std::vector<fs::path> &chunk_paths,
                        const boost::uint64_t &offset,
                        std::tr1::shared_ptr<std::string> output_string);

// Encrypt a datamap to a string
int EncryptDataMap(const DataMap &data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   std::string *encrypted_data_map);

// Decrypt an encrypted datamap
int DecryptDataMap(const std::string &encrypted_data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   DataMap *data_map);

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELFENCRYPTION_H_
