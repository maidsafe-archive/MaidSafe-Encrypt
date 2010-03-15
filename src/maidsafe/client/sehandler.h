/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Handler for self-encryption/decryption operations - an
*               interface between the clientcontroller and selfencryption
* Version:      1.0
* Created:      09/09/2008 12:14:35 PM
* Revision:     none
* Compiler:     gcc 4.3
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

#ifndef MAIDSAFE_CLIENT_SEHANDLER_H_
#define MAIDSAFE_CLIENT_SEHANDLER_H_

#include <boost/filesystem.hpp>
#include <boost/thread/condition.hpp>
#include <gtest/gtest_prod.h>

#include <map>
#include <string>

#include "protobuf/datamaps.pb.h"
#include "maidsafe/maidsafe.h"

namespace fs = boost::filesystem;

namespace maidsafe {

class ChunkStore;
class SessionSingleton;
class StoreManagerInterface;

const int kMaxStoreRetries = 2;
const int kMaxLoadRetries = 2;
const int kParallelStores = 1;
const int kParallelLoads = 3;

class SEHandler {
 public:
  SEHandler();
  ~SEHandler() {}
  void Init(boost::shared_ptr<StoreManagerInterface> storem,
            boost::shared_ptr<ChunkStore> client_chunkstore);
  //  Get the hash of the file contents if bool = true, else hash filename
  std::string SHA512(const std::string &full_entry,
                     bool hash_contents);
  int EncryptFile(const std::string &rel_entry,
                  const DirType &dir_type,
                  const std::string &msid);
  int EncryptString(const std::string &data,
                    std::string *ser_dm);
  bool ProcessMetaData(const std::string &rel_entry,
                       const ItemType &type,
                       const std::string &hash,
                       const boost::uint64_t &file_size,
                       std::string *ser_mdm);
  int DecryptFile(const std::string &rel_entry);
  int DecryptString(const std::string &ser_dm,
                    std::string *dec_string);
  bool MakeElement(const std::string &rel_entry,
                   const ItemType &type,
                   const std::string &directory_key);
  //  Gets a unique DHT key for dir's db identifier
  int GenerateUniqueKey(std::string *key);
  //  Retrieves DHT keys for dir and its parent dir if msid == "" or sets
  //  parent_key to MSID public key if msid != ""
  int GetDirKeys(const std::string &dir_path,
                 const std::string &msid,
                 std::string *key,
                 std::string *parent_key);
  //  Encrypts dir's db and sets ser_dm_ to encrypted datamap of db
  int EncryptDb(const std::string &dir_path,
                const DirType &dir_type,
                const std::string &dir_key,
                const std::string &msid,
                const bool &encrypt_dm,
                DataMap *dm);
  //  Decrypts dir's db by extracting datamap from ser_dm_
  int DecryptDb(const std::string &dir_path,
                const DirType &dir_type,
                const std::string &ser_dm,
                const std::string &dir_key,
                const std::string &msid,
                bool dm_encrypted,
                bool overwrite);

 private:
  SEHandler &operator=(const SEHandler &);
  SEHandler(const SEHandler &);
  FRIEND_TEST(SEHandlerTest, BEH_MAID_Check_Entry);
  FRIEND_TEST(SEHandlerTest, BEH_MAID_EncryptAndDecryptPrivateDb);
  ItemType CheckEntry(const fs::path &full_path,
                      boost::uint64_t *file_size,
                      std::string *file_hash);
  //  Encrypt db's datamap for storing on DHT
  int EncryptDm(const std::string &dir_path,
                const std::string &ser_dm,
                const std::string &msid,
                std::string *enc_dm);
  //  Decrypt db's datamap
  int DecryptDm(const std::string &dir_path,
                const std::string &enc_dm,
                const std::string &msid,
                std::string *ser_dm);
  void StoreChunks(const DataMap &dm,
                   const DirType &dir_type,
                   const std::string &msid);
  int LoadChunks(const DataMap &dm);
  int RemoveKeyFromUptodateDms(const std::string &key);
  void PacketOpCallback(const int &store_manager_result,
                        boost::mutex *mutex,
                        boost::condition_variable *cond_var,
                        int *op_result);
  boost::shared_ptr<StoreManagerInterface> storem_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  SessionSingleton *ss_;
  std::map<std::string, std::string> uptodate_datamaps_;
};

}  // namespace maidsafe
#endif  // MAIDSAFE_CLIENT_SEHANDLER_H_
