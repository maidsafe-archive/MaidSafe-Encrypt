/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Manages buffer packet messages to the maidsafe client
* Version:      1.0
* Created:      2009-01-28-23.10.42
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

#ifndef MAIDSAFE_CLIENT_CLIENTBUFFERPACKETHANDLER_H_
#define MAIDSAFE_CLIENT_CLIENTBUFFERPACKETHANDLER_H_

#include <boost/thread/mutex.hpp>
#include <maidsafe/crypto.h>

#include <list>
#include <set>
#include <string>

#include "maidsafe/maidsafe.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/storemanager.h"
#include "protobuf/packet.pb.h"
#include "protobuf/datamaps.pb.h"

namespace maidsafe {

class ClientBufferPacketHandler {
 public:
  ClientBufferPacketHandler(maidsafe::StoreManagerInterface *sm,
      boost::recursive_mutex *mutex);
  int CreateBufferPacket(const std::string &owner_id,
      const std::string &public_key, const std::string &private_key);
  int AddUsers(const std::set<std::string> &users,
               const PacketType &type);
  int DeleteUsers(const std::set<std::string> &users,
      const PacketType &type);
  int ChangeStatus(int status, const PacketType &type);
  // bool ListUsers(GenericPacket gp_info, std::set<std::string> *users);
  int GetMessages(
      const PacketType &type,
      std::list<ValidatedBufferPacketMessage> *valid_messages);
  void GetBufferPacket(const PacketType &type,
      base::callback_func_type cb);
  void ClearMessages(const PacketType &type,
      base::callback_func_type cb);
  void GetBufferPacketInfo(const PacketType &type,
      base::callback_func_type cb);

 private:
  crypto::Crypto crypto_obj_;
  maidsafe::SessionSingleton *ss_;
  maidsafe::StoreManagerInterface *sm_;
  boost::recursive_mutex *mutex_;

  bool UserList(std::set<std::string> *list, PacketType type);
  bool SetUserList(std::set<std::string> list, PacketType type);
  void GetBufferPacket_Callback(const std::string &result,
      const PacketType &type, base::callback_func_type cb);
  void GetBufferPacketInfo_Callback(const std::string &result,
      base::callback_func_type cb);
//  maidsafe::PacketType PacketHandler_PacketType(const PacketType &type);
  ClientBufferPacketHandler &operator=(const ClientBufferPacketHandler);
  ClientBufferPacketHandler(const ClientBufferPacketHandler&);
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_CLIENTBUFFERPACKETHANDLER_H_
