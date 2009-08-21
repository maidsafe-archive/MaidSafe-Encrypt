/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Manages data storage to local database (for testing)
* Version:      1.0
* Created:      2009-01-29-00.06.15
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#ifndef MAIDSAFE_CLIENT_LOCALSTOREMANAGER_H_
#define MAIDSAFE_CLIENT_LOCALSTOREMANAGER_H_

#include <boost/filesystem.hpp>
#include <boost/thread/mutex.hpp>

#include <string>

#include "maidsafe/cppsqlite3.h"
#include "maidsafe/client/storemanager.h"
#include "maidsafe/vault/vaultbufferpackethandler.h"

namespace maidsafe {

class ChunkStore;

class LocalStoreManager : public StoreManagerInterface {
 public:
  LocalStoreManager(boost::recursive_mutex *mutex,
                    boost::shared_ptr<ChunkStore> client_chunkstore);
  virtual ~LocalStoreManager() {}
  virtual void Init(int, base::callback_func_type cb);
  virtual void Close(base::callback_func_type cb, bool);
  virtual void CleanUpTransport() {}
  virtual int LoadChunk(const std::string &hex_chunk_name, std::string *data);
  virtual void StoreChunk(const std::string &hex_chunk_name,
                          const std::string &content,
                          const std::string &public_key,
                          const std::string &signed_public_key,
                          const std::string &signature,
                          base::callback_func_type cb);
  virtual void StoreChunk(const std::string &hex_chunk_name,
                          const DirType,
                          const std::string&);
  virtual void IsKeyUnique(const std::string &hex_key,
                           base::callback_func_type cb);
  virtual void DeletePacket(const std::string &hex_key,
                            const std::string &signature,
                            const std::string &public_key,
                            const std::string &signed_public_key,
                            const ValueType &type,
                            base::callback_func_type cb);
  virtual void StorePacket(const std::string &hex_key,
                           const std::string &value,
                           const std::string &signature,
                           const std::string &public_key,
                           const std::string &signed_public_key,
                           const ValueType &type,
                           bool update,
                           base::callback_func_type cb);
  virtual void LoadPacket(const std::string &hex_key,
                          base::callback_func_type cb);
  virtual void GetMessages(const std::string &hex_key,
                           const std::string &public_key,
                           const std::string &signed_public_key,
                           base::callback_func_type cb);
  virtual void PollVaultInfo(base::callback_func_type cb);
  virtual void VaultContactInfo(base::callback_func_type cb);
  virtual void OwnLocalVault(const std::string &priv_key, const std::string
      &pub_key, const std::string &signed_pub_key, const boost::uint32_t &port,
      const std::string &chunkstore_dir, const boost::uint64_t &space,
      boost::function<void(const OwnVaultResult&, const std::string&)> cb);

 private:
  LocalStoreManager &operator=(const LocalStoreManager&);
  LocalStoreManager(const LocalStoreManager&);
  CppSQLite3DB db_;
  packethandler::VaultBufferPacketHandler vbph_;
  crypto::Crypto crypto_obj_;
  boost::recursive_mutex *mutex_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  bool ValidateGenericPacket(std::string ser_gp, std::string public_key);
  // bool AddMessageToBufferPacket(std::string &key,
  //                               std::string &value,
  //                               std::string &public_key);
  bool ModifyBufferPacketInfo(const std::string &hex_key,
                              std::string *value,
                              const std::string &public_key);
  void StorePacket_InsertToDb(const std::string &hex_key,
                              const std::string &value,
                              base::callback_func_type cb);
  std::string GetValue_FromDB(const std::string &hex_key);
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_LOCALSTOREMANAGER_H_
