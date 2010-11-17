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

#ifndef MAIDSAFE_ENCRYPT_SELFENCRYPTIONUTILS_H_
#define MAIDSAFE_ENCRYPT_SELFENCRYPTIONUTILS_H_

#include <boost/filesystem.hpp>
#include <boost/tr1/memory.hpp>

#include <map>
#include <string>
#include <vector>

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

class DataIOHandler;
class DataMap;

namespace utils {

int EncryptContent(std::tr1::shared_ptr<DataIOHandler> input_handler,
                   const fs::path &output_dir,
                   DataMap *data_map,
                   std::map<std::string, fs::path> *to_chunk_store);
int DecryptContent(const DataMap &data_map,
                   std::vector<fs::path> chunk_paths,
                   const boost::uint64_t &offset,
                   std::tr1::shared_ptr<DataIOHandler> output_handler);
int EncryptDataMap(const DataMap &data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   std::string *encrypted_data_map);
int DecryptDataMap(const std::string &encrypted_data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   DataMap *data_map);
// check to ensure entry is encryptable
int CheckEntry(std::tr1::shared_ptr<DataIOHandler> input_handler);
bool CheckCompressibility(std::tr1::shared_ptr<DataIOHandler> input_handler);
bool CalculateChunkSizes(const std::string &file_hash,
                         std::tr1::shared_ptr<DataIOHandler> input_handler,
                         DataMap *data_map,
                         boost::uint16_t *chunk_count);
// returns a positive or negative int based on char passed into it to
// allow for random chunk sizes '0' returns -8, '1' returns -7, etc...
// through to 'f' returns 7
int ChunkAddition(char hex_digit);
bool GeneratePreEncryptionHashes(
    std::tr1::shared_ptr<DataIOHandler> input_handler,
    DataMap *data_map);
// Generate a string of required_size from input in a repeatable way
bool ResizeObfuscationHash(const std::string &input,
                           const size_t &required_size,
                           std::string *resized_data);
// ensure uniqueness of all chunk hashes (unless chunks are identical)
// if pre_encryption is true, hashes relate to pre-encryption, otherwise post-
bool HashUnique(const DataMap &data_map,
                bool pre_encryption,
                std::string *hash);
std::string SHA512(const fs::path &file_path);
std::string SHA512(const std::string &content);

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELFENCRYPTIONUTILS_H_
