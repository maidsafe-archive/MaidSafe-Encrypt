/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 13, 2008
 *      Author: Team
 */

#include "maidsafe/client/clientbufferpackethandler.h"

namespace maidsafe {

ClientBufferPacketHandler::ClientBufferPacketHandler(
    maidsafe::StoreManagerInterface *sm)
        : crypto_obj_(),
          ss_(maidsafe::SessionSingleton::getInstance()),
          sm_(sm) {
  crypto_obj_.set_hash_algorithm(crypto::SHA_512);
  crypto_obj_.set_symm_algorithm(crypto::AES_256);
}

int ClientBufferPacketHandler::CreateBufferPacket(
    const std::string &owner_id,
    const std::string &public_key,
    const std::string &private_key) {
  BufferPacket buffer_packet;
  GenericPacket *ser_owner_info = buffer_packet.add_owner_info();
  BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(owner_id);
  buffer_packet_info.set_ownerpublickey(public_key);
  buffer_packet_info.set_online(1);
  std::string ser_info;
  if (!buffer_packet_info.SerializeToString(&ser_info))
    return kBPInfoSerialiseError;
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(crypto_obj_.AsymSign(
    ser_info, "", private_key, crypto::STRING_STRING));
  std::string bufferpacketname =
    crypto_obj_.Hash(owner_id + public_key, "", crypto::STRING_STRING, true);

  std::string ser_packet;
  if (!buffer_packet.SerializeToString(&ser_packet))
    return kBPSerialiseError;
  int res = sm_->CreateBP(bufferpacketname, ser_packet);
  return (res == kSuccess) ? kSuccess : kStoreNewBPError;
}

int ClientBufferPacketHandler::ChangeStatus(
    const int &status,
    const PacketType &type) {
  BufferPacketInfo packet_info;
  GenericPacket user_info;

  std::set<std::string> current_users;
  if (!UserList(MPID, &current_users))
    return kBPError;

  packet_info.set_owner(ss_->PublicUsername());
  packet_info.set_ownerpublickey(ss_->PublicKey(type));
  packet_info.set_online(status);

  for (std::set<std::string>::iterator p = current_users.begin();
      p != current_users.end(); p++) {
    packet_info.add_users(*p);
  }

  std::string ser_info;
  if (!packet_info.SerializeToString(&ser_info))
    return kBPInfoSerialiseError;
  user_info.set_data(ser_info);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) +
                                 ss_->PublicKey(type), "",
                                 crypto::STRING_STRING, true);
  user_info.set_signature(crypto_obj_.AsymSign(ser_info, "",
      ss_->PrivateKey(type), crypto::STRING_STRING));
  std::string ser_gp;
  if (!user_info.SerializeToString(&ser_gp))
    return kBPError;

  int res = sm_->ModifyBPInfo(bufferpacketname, ser_gp);
  return (res == kSuccess) ? kSuccess : kModifyBPError;
}

bool ClientBufferPacketHandler::UserList(const PacketType &type,
                                         std::set<std::string> *list) {
  switch (type) {
    case MPID:
      *list = ss_->AuthorisedUsers();
      break;
    case MAID:
      *list = ss_->MaidAuthorisedUsers();
      break;
    default:
      return false;
  }
  return true;
}

bool ClientBufferPacketHandler::SetUserList(const PacketType &type,
                                            const std::set<std::string> &list) {
  switch (type) {
    case MPID:
      ss_->SetAuthorisedUsers(list);
      break;
    case MAID:
      ss_->SetMaidAuthorisedUsers(list);
      break;
    default:
      return false;
  }
  return true;
}

int ClientBufferPacketHandler::AddUsers(const std::set<std::string> &users,
                                        const PacketType &type) {
  if (users.empty()) {
#ifdef DEBUG
    printf("ClientBufferPacketHandler::AddUsers - Users empty.\n");
#endif
    return kBPError;
  }

  BufferPacketInfo packet_info;
  GenericPacket user_info;

  std::set<std::string> current_users;
  if (!UserList(type, &current_users))
    return kBPError;

  std::set<std::string> local_users = users;
  for (std::set<std::string>::iterator p = local_users.begin();
    p != local_users.end(); ++p) {
    current_users.insert(*p);
  }

  packet_info.set_owner(ss_->PublicUsername());
  packet_info.set_ownerpublickey(ss_->PublicKey(type));
  packet_info.set_online(0);

  for (std::set<std::string>::iterator p = current_users.begin();
    p != current_users.end(); p++) {
    packet_info.add_users(*p);
  }

  std::string ser_info;
  if (!packet_info.SerializeToString(&ser_info))
    return kBPInfoSerialiseError;
  user_info.set_data(ser_info);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) +
                                 ss_->PublicKey(type), "",
                                 crypto::STRING_STRING, true);
  user_info.set_signature(crypto_obj_.AsymSign(ser_info, "",
      ss_->PrivateKey(type), crypto::STRING_STRING));

  std::string ser_gp;
  if (!user_info.SerializeToString(&ser_gp))
    return kBPError;

  int res = sm_->ModifyBPInfo(bufferpacketname, ser_gp);
#ifdef DEBUG
  printf("ClientBufferPacketHandler::AddUsers - ModifyBPInfo %d. %s %s\n", res,
         ss_->Id(type).c_str(), HexCstring(ss_->PublicKey(type)));
#endif
  if (res == kSuccess) {
    return SetUserList(type, users) ? kSuccess : kBPAddUserError;
  } else {
    return kBPStoreAddedUserError;
  }
}

int ClientBufferPacketHandler::DeleteUsers(const std::set<std::string> &users,
                                           const PacketType &type) {
  std::set<std::string> current_users;
  if (type == MPID)
    current_users = ss_->AuthorisedUsers();
  else
    current_users = ss_->MaidAuthorisedUsers();

  std::set<std::string> local_users = users;
  for (std::set<std::string>::iterator p = local_users.begin();
      p != local_users.end(); ++p)
    current_users.erase(*p);

  BufferPacketInfo packet_info;
  GenericPacket gp;
  for (std::set<std::string>::iterator p = current_users.begin();
      p != current_users.end(); ++p)
    packet_info.add_users(*p);
  packet_info.set_owner(ss_->PublicUsername());
  packet_info.set_ownerpublickey(ss_->PublicKey(type));
  packet_info.set_online(0);

  std::string ser_info;
  if (!packet_info.SerializeToString(&ser_info))
    return kBPInfoSerialiseError;
  gp.set_data(ser_info);
  gp.set_signature(crypto_obj_.AsymSign(ser_info, "", ss_->PrivateKey(type),
      crypto::STRING_STRING));
  std::string ser_gp;
  if (!gp.SerializeToString(&ser_gp))
    return kBPError;
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) +
                                 ss_->PublicKey(type), "",
                                 crypto::STRING_STRING, true);
  int res = sm_->ModifyBPInfo(bufferpacketname, ser_gp);
  if (res == kSuccess) {
    if (type == MPID) {
      return ss_->SetAuthorisedUsers(current_users) ? kSuccess :
          kBPDeleteUserError;
    } else {
      return ss_->SetMaidAuthorisedUsers(current_users) ? kSuccess :
          kBPDeleteUserError;
    }
  } else {
    return kBPStoreDeletedUserError;
  }
}

int ClientBufferPacketHandler::GetMessages(
    const PacketType &type,
    std::list<ValidatedBufferPacketMessage> *valid_messages) {
  valid_messages->clear();
// TODO(Team#5#): 2009-09-15 - Confirm that mutex is not required here
// base::pd_scoped_lock gaurd(*mutex_);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) +
                                 ss_->PublicKey(type), "",
                                 crypto::STRING_STRING, true);
  std::string signed_public_key = crypto_obj_.AsymSign(
      ss_->PublicKey(type), "", ss_->PrivateKey(type), crypto::STRING_STRING);
  std::list<std::string> messages;
  if (sm_->LoadBPMessages(bufferpacketname, &messages) != kSuccess)
    return kBPMessagesRetrievalError;
  while (!messages.empty()) {
    ValidatedBufferPacketMessage valid_message;
    if (valid_message.ParseFromString(messages.front())) {
      std::string aes_key = crypto_obj_.AsymDecrypt(valid_message.index(), "",
          ss_->PrivateKey(type), crypto::STRING_STRING);
      valid_message.set_message(crypto_obj_.SymmDecrypt(valid_message.message(),
          "", crypto::STRING_STRING, aes_key));
      valid_messages->push_back(valid_message);
      messages.pop_front();
// TODO(Team#5#): 2009-09-15 - Add message saying corrupted messge not parsed?
//    } else {
//      valid_message.set_sender("");
//      valid_message.set_message("You got a corrupted message.");
//      valid_message.set_index("");
//      valid_message.set_type(0);
//      valid_messages->push_back(valid_message);
//      messages.pop_front();
    }
  }
  return kSuccess;
}

int ClientBufferPacketHandler::GetBufferPacketInfo(const PacketType &type) {
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) +
                                 ss_->PublicKey(type), "",
                                 crypto::STRING_STRING, true);
  std::string packet_content;
  if (sm_->LoadChunk(bufferpacketname, &packet_content) != kSuccess)
    return kBPRetrievalError;
  BufferPacket bp;
  BufferPacketInfo bpi;
  if (!bp.ParseFromString(packet_content)) {
    return kBPParseError;
  }

  if (!bpi.ParseFromString(bp.owner_info(0).data())) {
    return kBPInfoParseError;
  }
  std::set<std::string> users;
  for (int i = 0; i < bpi.users_size(); ++i) {
    users.insert(bpi.users(i));
  }
  return ss_->SetAuthorisedUsers(users) ? kSuccess : kGetBPInfoError;
}

//  int ClientBufferPacketHandler::ClearMessages(const PacketType &type) {
//    std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) +
//                                   ss_->PublicKey(type), "",
//                                   crypto::STRING_STRING, true);
//    std::string signed_public_key = crypto_obj_.AsymSign(
//                                    ss_->PublicKey(type), "",
//                                    ss_->PrivateKey(type),
//                                    crypto::STRING_STRING);
//    std::string non_hex_bufferpacketname("");
//    base::decode_from_hex(bufferpacketname, &non_hex_bufferpacketname);
//    std::string signed_request = crypto_obj_.AsymSign(
//      crypto_obj_.Hash(ss_->PublicKey(type) + signed_public_key +
//      non_hex_bufferpacketname, "", crypto::STRING_STRING, false), "",
//      ss_->PrivateKey(type), crypto::STRING_STRING);
//
//    sm_->DeletePacket(bufferpacketname, signed_request,
//        ss_->PublicKey(type), signed_public_key,
//        maidsafe::BUFFER_PACKET_MESSAGE, cb);
//  }

}  // namespace maidsafe
