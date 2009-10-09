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
#include <gtest/gtest_prod.h>

#include <list>
#include <string>

#include "maidsafe/cppsqlite3.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/storemanager.h"
#include "maidsafe/vault/vaultbufferpackethandler.h"
#include "protobuf/datamaps.pb.h"

namespace maidsafe {

class ChunkStore;

class LocalStoreManager : public StoreManagerInterface {
 public:
  explicit LocalStoreManager(boost::shared_ptr<ChunkStore> client_chunkstore);
  virtual ~LocalStoreManager() {}
  virtual void Init(int, base::callback_func_type cb);
  virtual void Close(base::callback_func_type cb, bool);
  virtual void CleanUpTransport() {}
  virtual void ClearStoreQueue() {}
  virtual bool NotDoneWithUploading();
  virtual bool KeyUnique(const std::string &hex_key, bool check_local);

  // Chunks
  virtual int LoadChunk(const std::string &hex_chunk_name, std::string *data);
  virtual void StoreChunk(const std::string &hex_chunk_name,
                          const DirType,
                          const std::string&);

  // Packets
  virtual void LoadPacket(const std::string &hex_key,
                          std::string *result);
  virtual int StorePacket(const std::string &hex_packet_name,
                          const std::string &value,
                          PacketType system_packet_type,
                          DirType dir_type,
                          const std::string &msid);
  virtual void DeletePacket(const std::string &hex_key,
                            const std::string &signature,
                            const std::string &public_key,
                            const std::string &signed_public_key,
                            const ValueType &type,
                            base::callback_func_type cb);

  // Buffer packet
  virtual int CreateBP(const std::string &bufferpacketname,
                       const std::string &ser_packet);
  virtual int LoadBPMessages(const std::string &bufferpacketname,
                             std::list<std::string> *messages);
  virtual int ModifyBPInfo(const std::string &bufferpacketname,
                           const std::string &ser_gp);
  virtual int AddBPMessage(const std::string &bufferpacketname,
                           const std::string &ser_gp);

  // Vault
  virtual void PollVaultInfo(base::callback_func_type cb);
  virtual void VaultContactInfo(base::callback_func_type cb);
  virtual void OwnLocalVault(const std::string &priv_key, const std::string
      &pub_key, const std::string &signed_pub_key, const boost::uint32_t &port,
      const std::string &chunkstore_dir, const boost::uint64_t &space,
      boost::function<void(const OwnVaultResult&, const std::string&)> cb);
  virtual void LocalVaultStatus(boost::function<void(const VaultStatus&)> cb);

 private:
  FRIEND_TEST(ClientBufferPacketHandlerTest, BEH_MAID_AddBPMessage);
  FRIEND_TEST(ClientBufferPacketHandlerTest,
              BEH_MAID_AddBPMessageNonAuthorisedUser);
  FRIEND_TEST(ClientBufferPacketHandlerTest, BEH_MAID_DeleteBPUsers);
  FRIEND_TEST(ClientBufferPacketHandlerTest, BEH_MAID_MultipleBPMessages);
  FRIEND_TEST(ClientBufferPacketHandlerTest, BEH_MAID_ModifyBPUserInfo);
  LocalStoreManager &operator=(const LocalStoreManager&);
  LocalStoreManager(const LocalStoreManager&);
  CppSQLite3DB db_;
  VaultBufferPacketHandler vbph_;
  boost::mutex mutex_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  SessionSingleton *ss_;
  bool ValidateGenericPacket(std::string ser_gp, std::string public_key);
  int StorePacket_InsertToDb(const std::string &hex_key,
                              const std::string &value);
  std::string GetValue_FromDB(const std::string &hex_key);
  int FindAndLoadChunk(const std::string &chunkname, std::string *data);
  int FlushDataIntoChunk(const std::string &chunkname, const std::string &data,
                         const bool &overwrite);
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_LOCALSTOREMANAGER_H_
