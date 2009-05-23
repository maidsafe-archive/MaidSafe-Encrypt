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

#ifndef MAIDSAFE_CLIENT_SELFENCRYPTION_H_
#define MAIDSAFE_CLIENT_SELFENCRYPTION_H_

#include <stdint.h>

#include <string>

#include "boost/filesystem.hpp"
#include "gtest/gtest_prod.h"

#include "fs/filesystem.h"
#include "protobuf/datamaps.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

class SelfEncryption {
 public:
  SelfEncryption();
  ~SelfEncryption() {}
  // encrypt entire file
  int Encrypt(const std::string &entry_str, maidsafe::DataMap *dm);
  // decrypt chunks starting at chunklet spanning offset point
  int Decrypt(const maidsafe::DataMap &dm,
              const std::string &entry_str,
              const uint64_t &offset,
              bool overwrite);
  std::string SHA512(const fs::path &file_path);
  std::string SHA512(const std::string &content);
  fs::path GetChunkPath(const std::string &chunk_name);

 private:
  // check to ensure entry is encryptable
  int CheckEntry(const fs::path &entry_path);
  bool CreateProcessDirectory(fs::path *processing_path);
  bool CheckCompressibility(const fs::path &entry_path);
  bool CalculateChunkSizes(const fs::path &entry_path,
                           maidsafe::DataMap *dm);
  // returns a positive or negative int based on char passed into it to
  // allow for random chunk sizes '0' returns -8, '1' returns -7, etc...
  // through to 'f' returns 7
  int ChunkAddition(const char &hex_digit);
  bool GeneratePreEncHashes(const fs::path &entry_path,
                            maidsafe::DataMap *dm);
  // ensure uniqueness of all chunk hashes (unless chunks are identical)
  // if pre_enc is true, hashes relate to pre-encryption, otherwise post-
  bool HashUnique(const maidsafe::DataMap &dm,
                  bool pre_enc,
                  std::string *hash);
  // concatenate copies of hash until desired length reached
  bool ResizeObfuscationHash(const std::string &obfuscate_hash,
                             const uint16_t &length_,
                             std::string *resized_obs_hash);
  FRIEND_TEST(TestSelfEncryption, FUNC_MAID_CheckEntry);
  FRIEND_TEST(TestSelfEncryption, BEH_MAID_CreateProcessDirectory);
  FRIEND_TEST(TestSelfEncryption, BEH_MAID_CheckCompressibility);
  FRIEND_TEST(TestSelfEncryption, FUNC_MAID_CalculateChunkSizes);
  FRIEND_TEST(TestSelfEncryption, BEH_MAID_ChunkAddition);
  FRIEND_TEST(TestSelfEncryption, FUNC_MAID_GeneratePreEncHashes);
  FRIEND_TEST(TestSelfEncryption, FUNC_MAID_HashUnique);
  FRIEND_TEST(TestSelfEncryption, FUNC_MAID_ResizeObfuscationHash);
  FRIEND_TEST(TestSelfEncryption, FUNC_MAID_EncryptFile);
  FRIEND_TEST(TestSelfEncryption, FUNC_MAID_DecryptFile);
  const std::string version_;
  const uint16_t min_chunks_;
  const uint16_t max_chunks_;
  const uint64_t default_chunk_size_;
  const uint16_t default_chunklet_size_;
  const uint16_t min_chunklet_size_;
  bool compress_;
  std::string file_hash_;
  int chunk_count_;
  file_system::FileSystem fsys_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_SELFENCRYPTION_H_
