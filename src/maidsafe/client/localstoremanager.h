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

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "maidsafe/common/cppsqlite3.h"
#include "maidsafe/common/vaultbufferpackethandler.h"
#include "maidsafe/client/storemanager.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace test {
class CCImMessagingTest;
class LocalStoreManagerTest_BEH_MAID_AddAndGetBufferPacketMessages_Test;
class LocalStoreManagerTest_BEH_MAID_AddRequestBufferPacketMessage_Test;
}  // namespace test

class ChunkStore;
class SessionSingleton;

class LocalStoreManager : public StoreManagerInterface {
 public:
  LocalStoreManager(boost::shared_ptr<ChunkStore> client_chunkstore,
                    const boost::uint8_t &k,
                    const fs::path &db_directory);
  virtual ~LocalStoreManager();
  virtual void Init(VoidFuncOneInt callback, const boost::uint16_t &port);
  virtual void Close(VoidFuncOneInt callback, bool cancel_pending_ops);
  virtual void CleanUpTransport() {}
  virtual void StopRvPing() {}
  virtual bool NotDoneWithUploading();
  virtual bool KeyUnique(const std::string &key, bool check_local);
  virtual void KeyUnique(const std::string &key,
                         bool check_local,
                         const VoidFuncOneInt &cb);

  // Chunks
  virtual int LoadChunk(const std::string &chunk_name, std::string *data);
  virtual int StoreChunk(const std::string &chunk_name,
                         DirType dir_type,
                         const std::string &msid);
  virtual int DeleteChunk(const std::string &chunk_name,
                          const boost::uint64_t &chunk_size,
                          DirType dir_type,
                          const std::string &msid);

  // Packets
  virtual int LoadPacket(const std::string &packet_name,
                         std::vector<std::string> *results);
  virtual void LoadPacket(const std::string &packet_name,
                          const LoadPacketFunctor &lpf);
  virtual void StorePacket(const std::string &packet_name,
                           const std::string &value,
                           passport::PacketType system_packet_type,
                           DirType dir_type,
                           const std::string &msid,
                           const VoidFuncOneInt &cb);
  // Deletes all values for the specified key
  virtual void DeletePacket(const std::string &packet_name,
                            const std::vector<std::string> values,
                            passport::PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const VoidFuncOneInt &cb);
  virtual void UpdatePacket(const std::string &packet_name,
                            const std::string &old_value,
                            const std::string &new_value,
                            passport::PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const VoidFuncOneInt &cb);

  // Buffer packet
  virtual int CreateBP();
  virtual int ModifyBPInfo(const std::string &info);
  virtual int LoadBPMessages(
      std::list<ValidatedBufferPacketMessage> *messages);
  virtual int SendMessage(const std::vector<std::string> &receivers,
                           const std::string &message,
                           const MessageType &m_type,
                           std::map<std::string, ReturnCode> *add_results);
  virtual int LoadBPPresence(std::list<LivePresence> *messages);
  virtual int AddBPPresence(
      const std::vector<std::string> &receivers,
      std::map<std::string, ReturnCode> *add_results);

  // Vault
  virtual void PollVaultInfo(kad::VoidFunctorOneString cb);
  virtual bool VaultContactInfo(kad::Contact *contact);
  virtual void SetLocalVaultOwned(const std::string &priv_key,
                                  const std::string &pub_key,
                                  const std::string &signed_pub_key,
                                  const boost::uint32_t &port,
                                  const std::string &vault_dir,
                                  const boost::uint64_t &space,
                                  const SetLocalVaultOwnedFunctor &functor);
  virtual void LocalVaultOwned(const LocalVaultOwnedFunctor &functor);
  virtual int CreateAccount(const boost::uint64_t&) { return kSuccess; }
  bool SendPresence(const std::string &) { return false; }
  void SendLogOutMessage(const std::string &) {}
  void SetSessionEndPoint() {}
  void SetInstantMessageNotifier(IMNotifier, IMStatusNotifier) {}
 private:
  friend class
      test::LocalStoreManagerTest_BEH_MAID_AddAndGetBufferPacketMessages_Test;
  friend class
      test::LocalStoreManagerTest_BEH_MAID_AddRequestBufferPacketMessage_Test;
  LocalStoreManager &operator=(const LocalStoreManager&);
  LocalStoreManager(const LocalStoreManager&);
  friend class test::CCImMessagingTest;
  bool ValidateGenericPacket(std::string ser_gp, std::string public_key);
  ReturnCode StorePacket_InsertToDb(const std::string &key,
                                    const std::string &value,
                                    const std::string &public_key,
                                    const bool &append);
  ReturnCode DeletePacket_DeleteFromDb(const std::string &key,
                                       const std::vector<std::string> &values,
                                       const std::string &public_key);
  int GetValue_FromDB(const std::string &key,
                      std::vector<std::string> *results);
  ReturnCode UpdatePacketInDb(const std::string &key,
                              const std::string &old_value,
                              const std::string &new_value);
  int FindAndLoadChunk(const std::string &chunkname, std::string *data);
  int FlushDataIntoChunk(const std::string &chunkname,
                         const std::string &data,
                         const bool &overwrite);
  std::string BufferPacketName();
  std::string BufferPacketName(const std::string &publicusername,
                               const std::string &public_key);
  std::string CreateMessage(const std::string &message,
                            const std::string &rec_public_key,
                            const MessageType &m_type,
                            const boost::uint32_t &timestamp);
  void CreateSerialisedSignedValue(const std::string &value,
                                   const std::string &private_key,
                                   std::string *ser_gp);
  void ExecStringCallback(kad::VoidFunctorOneString cb,
                          MaidsafeRpcResult result);
  void ExecuteReturnSignal(const std::string &chunkname, ReturnCode rc);
  void ExecReturnCodeCallback(VoidFuncOneInt cb, ReturnCode rc);
  void ExecReturnLoadPacketCallback(LoadPacketFunctor cb,
                                    std::vector<std::string> results,
                                    ReturnCode rc);

  const boost::uint8_t K_;
  const boost::uint16_t kUpperThreshold_;
  CppSQLite3DB db_;
  VaultBufferPacketHandler vbph_;
  boost::mutex mutex_;
  std::string local_sm_dir_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  SessionSingleton *ss_;
  std::set<std::string> chunks_pending_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_LOCALSTOREMANAGER_H_
