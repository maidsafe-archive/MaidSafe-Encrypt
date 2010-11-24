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

#include <boost/function.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/thread/condition_variable.hpp>

#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/base/utils.h>
#include <maidsafe/passport/passport.h>

#include <list>
#include <map>
#include <string>
#include <vector>

#include "maidsafe/common/maidsafe.h"
#include "maidsafe/common/maidsafe_service_messages.pb.h"

namespace bs2 = boost::signals2;

/********************************** Signals **********************************/
typedef bs2::signal<void(const std::string&, maidsafe::ReturnCode)>
        OnChunkUploaded;
/*****************************************************************************/

namespace maidsafe {

enum IfPacketExists {
  kDoNothingReturnFailure,
  kDoNothingReturnSuccess,
  kOverwrite,
  kAppend
};

typedef boost::function<void(const OwnLocalVaultResult&, const std::string&)>
        SetLocalVaultOwnedFunctor;

typedef boost::function<void(const VaultOwnershipStatus&)>
    LocalVaultOwnedFunctor;

typedef boost::function<void(const std::vector<std::string>&,
                             const ReturnCode&)>
        LoadPacketFunctor;

typedef boost::function<void(const ReturnCode&)> CreateAccountFunctor;

typedef boost::function<void(const std::string&)> IMNotifier;
typedef boost::function<void(const std::string&, const int&)> IMStatusNotifier;

class StoreManagerInterface {
 public:
  virtual ~StoreManagerInterface() {}
  virtual void Init(VoidFuncOneInt callback, const boost::uint16_t &port)=0;
  virtual void SetPmid(const std::string &pmid_name)=0;
  virtual void Close(VoidFuncOneInt callback, bool cancel_pending_ops)=0;
  virtual void CleanUpTransport()=0;
  virtual void StopRvPing()=0;
  virtual bool NotDoneWithUploading()=0;
  virtual bool KeyUnique(const std::string &key, bool check_local)=0;
  virtual void KeyUnique(const std::string &key, bool check_local,
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
                           passport::PacketType system_packet_type,
                           DirType dir_type,
                           const std::string &msid,
                           const VoidFuncOneInt &cb)=0;
  virtual void DeletePacket(const std::string &packet_name,
                            const std::vector<std::string> values,
                            passport::PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const VoidFuncOneInt &cb)=0;
  virtual void UpdatePacket(const std::string &packet_name,
                            const std::string &old_value,
                            const std::string &new_value,
                            passport::PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const VoidFuncOneInt &cb)=0;

  // Buffer packet
  virtual int CreateBP()=0;
  virtual int ModifyBPInfo(const std::string &info)=0;
  virtual int LoadBPMessages(
      std::list<ValidatedBufferPacketMessage> *messages)=0;
  virtual int SendMessage(const std::vector<std::string> &receivers,
                           const std::string &message,
                           const MessageType &m_type,
                           std::map<std::string, ReturnCode> *add_results)=0;
  virtual int LoadBPPresence(std::list<LivePresence> *messages)=0;
  virtual int AddBPPresence(
      const std::vector<std::string> &receivers,
      std::map<std::string, ReturnCode> *add_results)=0;

  // Vault
  virtual bool VaultStoreInfo(boost::uint64_t *offered_space,
                              boost::uint64_t *free_space)=0;
  virtual bool VaultContactInfo(kad::Contact *contact)=0;
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

  // Instant Messaging
  virtual bool SendPresence(const std::string &contactname)=0;
  virtual void SendLogOutMessage(const std::string &contactname)=0;
  virtual void SetSessionEndPoint()=0;
  virtual void SetInstantMessageNotifier(IMNotifier on_msg,
                                         IMStatusNotifier status_notifier)=0;

/************************** Signals **************************/
  bs2::connection ConnectToOnChunkUploaded(
      const OnChunkUploaded::slot_type &slot) {
    return sig_chunk_uploaded_.connect(slot);
  }

 protected:
  StoreManagerInterface() : sig_chunk_uploaded_() {}
  OnChunkUploaded sig_chunk_uploaded_;
  boost::mutex signal_mutex_;

 private:
  StoreManagerInterface(const StoreManagerInterface&);
  StoreManagerInterface& operator=(const StoreManagerInterface&);
/*************************************************************/
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_STOREMANAGER_H_
