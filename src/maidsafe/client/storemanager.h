/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Interface allowing storage of data to network or local database
* Version:      1.0
* Created:      2009-01-29-00.49.17
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

#ifndef MAIDSAFE_CLIENT_STOREMANAGER_H_
#define MAIDSAFE_CLIENT_STOREMANAGER_H_

#include <boost/thread/condition_variable.hpp>
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/utils.h>

#include <list>
#include <string>
#include <vector>

#include "protobuf/maidsafe_service_messages.pb.h"
#include "maidsafe/maidsafe.h"
#include "maidsafe/client/packetfactory.h"

namespace maidsafe {

enum IfPacketExists {
  kDoNothingReturnFailure,
  kDoNothingReturnSuccess,
  kOverwrite,
  kAppend
};

typedef boost::function<void(const OwnLocalVaultResult&, const std::string&)>
    SetLocalVaultOwnedFunctor;

typedef boost::function<void(const VaultStatus&)> LocalVaultOwnedFunctor;

typedef boost::function<void(const std::vector<std::string>&,
    const ReturnCode&)> LoadPacketFunctor;

typedef boost::function<void(const ReturnCode&)> CreateAccountFunctor;

class StoreManagerInterface {
 public:
  virtual ~StoreManagerInterface() {}
  virtual void Init(int port,
                    base::callback_func_type cb,
                    fs::path db_directory)=0;
  virtual void Close(base::callback_func_type cb, bool cancel_pending_ops)=0;
  virtual void CleanUpTransport()=0;
  virtual void StopRvPing()=0;
  virtual bool NotDoneWithUploading()=0;
  virtual bool KeyUnique(const std::string &key, bool check_local)=0;
  virtual void KeyUnique(const std::string &key,
                         bool check_local,
                         const VoidFuncOneInt &cb)=0;

  // Chunks
  virtual int LoadChunk(const std::string &chunk_name, std::string *data)=0;
  virtual int StoreChunk(const std::string &chunk_name,
                         DirType dir_type,
                         const std::string &msid)=0;
  virtual int DeleteChunk(const std::string &chunk_name,
                          const boost::uint64_t &chunk_size,
                          DirType dir_type,
                          const std::string &msid)=0;

  // Packets
  virtual int LoadPacket(const std::string &packet_name,
                         std::vector<std::string> *results)=0;
  virtual void LoadPacket(const std::string &packet_name,
                          const LoadPacketFunctor &lpf)=0;
  virtual void StorePacket(const std::string &packet_name,
                           const std::string &value,
                           PacketType system_packet_type,
                           DirType dir_type,
                           const std::string &msid,
                           IfPacketExists if_packet_exists,
                           const VoidFuncOneInt &cb)=0;
  // Deletes all values for the specified key
  virtual void DeletePacket(const std::string &packet_name,
                            const std::vector<std::string> values,
                            PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const VoidFuncOneInt &cb)=0;

  // Buffer packet
  virtual int CreateBP()=0;
  virtual int LoadBPMessages(
      std::list<maidsafe::ValidatedBufferPacketMessage> *messages)=0;
  virtual int ModifyBPInfo(const std::string &info)=0;
  virtual int AddBPMessage(const std::vector<std::string> &receivers,
                           const std::string &message,
                           const MessageType &m_type)=0;

  // Vault
  virtual void PollVaultInfo(base::callback_func_type cb)=0;
  virtual void VaultContactInfo(base::callback_func_type cb)=0;
  virtual void SetLocalVaultOwned(
      const std::string &priv_key,
      const std::string &pub_key,
      const std::string &signed_pub_key,
      const boost::uint32_t &port,
      const std::string &vault_dir,
      const boost::uint64_t &space,
      const SetLocalVaultOwnedFunctor &functor)=0;
  virtual void LocalVaultOwned(const LocalVaultOwnedFunctor &functor)=0;
  virtual int CreateAccount(const boost::uint64_t &space)=0;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_STOREMANAGER_H_
