/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in teh root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Sep 29, 2008
 *      Author: Haiyang, Jose
 */

#ifndef MAIDSAFE_VAULT_CHUNKSTORE_H_
#define MAIDSAFE_VAULT_CHUNKSTORE_H_

#include <boost/filesystem.hpp>
#include <boost/thread/mutex.hpp>
#include <list>
#include <string>

#include "base/crypto.h"

namespace fs = boost::filesystem;

namespace maidsafe_vault {

class ChunkStore {
 public:
  explicit ChunkStore(const std::string &chunkstore_dir);
  ~ChunkStore() {
//    printf("In ChunkStore destructor.\n");
  }
  bool HasChunk(const std::string &key);
  bool StoreChunk(const std::string &key, const std::string &value);
  bool UpdateChunk(const std::string &key, const std::string &value);
  bool LoadChunk(const std::string &key, std::string *value);
  bool LoadRandomChunk(std::string *key, std::string *value);
  bool DeleteChunk(const std::string &key);
  void GetAllChunks(std::list<std::string> *chunk_names);
  // Check that hash of value == key
  int HashCheckChunk(const std::string &key);
  // Hash check all local chunks and add to list those that fail.  Bool set to
  // true causes failed chunks to be deleted.
  int HashCheckAllChunks(bool delete_failures,
                         std::list<std::string> *failed_keys);
 private:
  ChunkStore(const ChunkStore&);
  ChunkStore& operator=(const ChunkStore&);
  bool Init();
  fs::path GetPathFromKey(const std::string &key);
  // Check that hash of value == key for file
  int HashCheckChunk(const fs::path &filepath);
  std::string chunkstore_dir_;
  bool init_;
  crypto::Crypto crypto_;
};
}  // namespace maidsafe_vault

#endif  // MAIDSAFE_VAULT_CHUNKSTORE_H_
