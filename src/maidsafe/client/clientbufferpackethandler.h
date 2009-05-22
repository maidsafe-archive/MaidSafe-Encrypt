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
#include "maidsafe/rsakeypair.h"
#include "maidsafe/maidsafe.h"
#include "protobuf/packet.pb.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/storemanager.h"

namespace packethandler {

class ClientBufferPacketHandler {
 public:
  ClientBufferPacketHandler(maidsafe::StoreManagerInterface *sm,
    boost::recursive_mutex *mutex);
  void CreateBufferPacket(const std::string &owner_id,
    const std::string &public_key, const std::string &private_key,
    base::callback_func_type cb);
  void AddUsers(const std::set<std::string> &users, base::callback_func_type cb,
    const buffer_packet_type &type);
  void DeleteUsers(const std::set<std::string> &users,
    base::callback_func_type cb, const buffer_packet_type &type);
  // TODO(Jose): Implement this function if required
  void ChangeStatus(int status, base::callback_func_type cb,
    const buffer_packet_type &type);
  // bool ListUsers(GenericPacket gp_info, std::set<std::string> *users);
  void GetMessages(const buffer_packet_type &type, base::callback_func_type cb);
  void GetBufferPacket(const buffer_packet_type &type,
    base::callback_func_type cb);
  void ClearMessages(const buffer_packet_type &type,
    base::callback_func_type cb);

  // void SendAddContactRequest(const std::string &contact_name,
  //                            const std::string &contact_public_key,
  //                            base::callback_func cb,
  //                            const std::string &name = "",
  //                            const std::string &birthday = "",
  //                            const std::string &office_no = "",
  //                            const std::string &gender = "",
  //                            const std::string &country = "",
  //                            const std::string &language = "");

 private:
  maidsafe_crypto::Crypto crypto_obj_;
  maidsafe::SessionSingleton *ss_;
  maidsafe::StoreManagerInterface *sm_;
  boost::recursive_mutex *mutex_;

  bool UserList(std::set<std::string> *list, buffer_packet_type type);
  bool SetUserList(std::set<std::string> list, buffer_packet_type type);
  void AddUsers_Callback(const std::string &result,
    const std::set<std::string> &users, const buffer_packet_type &type,
    base::callback_func_type cb);
  void DeleleteUsers_Callback(const std::string &result,
    const std::set<std::string> &users,  const buffer_packet_type type,
    base::callback_func_type cb);
  void GetMessages_Callback(const std::string &result,
    const buffer_packet_type &type, base::callback_func_type cb);
  void GetBufferPacket_Callback(const std::string &result,
    const buffer_packet_type &type, base::callback_func_type cb);
  void ChangeStatus_Callback(const std::string &result,
    base::callback_func_type cb);
//   std::string CreateMessage(const std::string &sender_id,
//     const std::string &msg, const MessageType &type, const std::string
//     &contact_public_key, const std::string &sender_private_key, const
//     std::string &sender_public_key="");
  ClientBufferPacketHandler &operator=(const ClientBufferPacketHandler);
  ClientBufferPacketHandler(const ClientBufferPacketHandler&);
};

}  // namespace packethandler

#endif  // MAIDSAFE_CLIENT_CLIENTBUFFERPACKETHANDLER_H_
