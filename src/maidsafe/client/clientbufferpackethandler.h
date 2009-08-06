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

#include <list>
#include <set>
#include <string>

#include "boost/thread/mutex.hpp"

#include "maidsafe/crypto.h"
#include "maidsafe/maidsafe.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/storemanager.h"
#include "protobuf/packet.pb.h"
#include "protobuf/datamaps.pb.h"

namespace packethandler {

class ClientBufferPacketHandler {
 public:
  ClientBufferPacketHandler(maidsafe::StoreManagerInterface *sm,
      boost::recursive_mutex *mutex);
  void CreateBufferPacket(const std::string &owner_id,
      const std::string &public_key, const std::string &private_key,
      base::callback_func_type cb);
  void AddUsers(const std::set<std::string> &users, base::callback_func_type cb,
                const BufferPacketType &type);
  void DeleteUsers(const std::set<std::string> &users,
      base::callback_func_type cb, const BufferPacketType &type);
  void ChangeStatus(int status, base::callback_func_type cb,
                    const BufferPacketType &type);
  // bool ListUsers(GenericPacket gp_info, std::set<std::string> *users);
  void GetMessages(const BufferPacketType &type, base::callback_func_type cb);
  void GetBufferPacket(const BufferPacketType &type,
      base::callback_func_type cb);
  void ClearMessages(const BufferPacketType &type,
      base::callback_func_type cb);
  void GetBufferPacketInfo(const BufferPacketType &type,
      base::callback_func_type cb);

 private:
  crypto::Crypto crypto_obj_;
  maidsafe::SessionSingleton *ss_;
  maidsafe::StoreManagerInterface *sm_;
  boost::recursive_mutex *mutex_;

  bool UserList(std::set<std::string> *list, BufferPacketType type);
  bool SetUserList(std::set<std::string> list, BufferPacketType type);
  void AddUsers_Callback(const std::string &result,
      const std::set<std::string> &users, const BufferPacketType &type,
      base::callback_func_type cb);
  void DeleleteUsers_Callback(const std::string &result,
      const std::set<std::string> &users,  const BufferPacketType type,
      base::callback_func_type cb);
  void GetMessages_Callback(const std::string &result,
      const BufferPacketType &type, base::callback_func_type cb);
  void GetBufferPacket_Callback(const std::string &result,
      const BufferPacketType &type, base::callback_func_type cb);
  void GetBufferPacketInfo_Callback(const std::string &result,
      base::callback_func_type cb);
  void ChangeStatus_Callback(const std::string &result,
      base::callback_func_type cb);
  maidsafe::PacketType PacketHandler_PacketType(const BufferPacketType &type);
  ClientBufferPacketHandler &operator=(const ClientBufferPacketHandler);
  ClientBufferPacketHandler(const ClientBufferPacketHandler&);
};

}  // namespace packethandler

#endif  // MAIDSAFE_CLIENT_CLIENTBUFFERPACKETHANDLER_H_
