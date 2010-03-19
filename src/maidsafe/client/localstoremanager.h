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
#include <vector>

#include "maidsafe/cppsqlite3.h"
#include "maidsafe/vaultbufferpackethandler.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/storemanager.h"
#include "protobuf/datamaps.pb.h"

namespace maidsafe {

class ChunkStore;

class LocalStoreManager : public StoreManagerInterface {
 public:
  explicit LocalStoreManager(boost::shared_ptr<ChunkStore> client_chunkstore);
  virtual ~LocalStoreManager() {}
  virtual void Init(int, base::callback_func_type cb, fs::path db_directory);
  virtual void Close(base::callback_func_type cb, bool);
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
                         const DirType dir_type,
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
                           PacketType system_packet_type,
                           DirType dir_type,
                           const std::string &msid,
                           IfPacketExists if_packet_exists,
                           const VoidFuncOneInt &cb);
  // Deletes all values for the specified key
  virtual void DeletePacket(const std::string &packet_name,
                            const std::vector<std::string> values,
                            PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const VoidFuncOneInt &cb);
  // Buffer packet
  virtual int CreateBP();
  virtual int LoadBPMessages(
      std::list<maidsafe::ValidatedBufferPacketMessage> *messages);
  virtual int ModifyBPInfo(const std::string &info);
  virtual int AddBPMessage(const std::vector<std::string> &receivers,
                           const std::string &message,
                           const MessageType &m_type);
  virtual void ContactInfo(const std::string &public_username,
                           const std::string &me,
                           ContactInfoNotifier cin);
  virtual void OwnInfo(ContactInfoNotifier cin);

  // Vault
  virtual void PollVaultInfo(base::callback_func_type cb);
  virtual void VaultContactInfo(base::callback_func_type cb);
  virtual void SetLocalVaultOwned(const std::string &priv_key,
                                  const std::string &pub_key,
                                  const std::string &signed_pub_key,
                                  const boost::uint32_t &port,
                                  const std::string &vault_dir,
                                  const boost::uint64_t &space,
                                  const SetLocalVaultOwnedFunctor &functor);
  virtual void LocalVaultOwned(const LocalVaultOwnedFunctor &functor);
  virtual int CreateAccount(const boost::uint64_t&) { return kSuccess; }

 private:
  LocalStoreManager &operator=(const LocalStoreManager&);
  LocalStoreManager(const LocalStoreManager&);
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
  void SigningPublicKey(PacketType packet_type, DirType dt,
                        const std::string &msid, std::string *public_key);
  void SigningPrivateKey(PacketType packet_type, DirType dt,
                         const std::string &msid, std::string *private_key);
  void CreateSerialisedSignedValue(const std::string value,
                                   const PacketType &pt,
                                   const std::string &msid,
                                   std::string *ser_gp);

  CppSQLite3DB db_;
  VaultBufferPacketHandler vbph_;
  boost::mutex mutex_;
  std::string local_sm_dir_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  SessionSingleton *ss_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_LOCALSTOREMANAGER_H_
