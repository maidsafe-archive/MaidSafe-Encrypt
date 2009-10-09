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

int ClientBufferPacketHandler::CreateBufferPacket(const std::string &owner_id,
    const std::string &public_key, const std::string &private_key) {
  BufferPacket buffer_packet;
  GenericPacket *ser_owner_info = buffer_packet.add_owner_info();
  BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(owner_id);
  buffer_packet_info.set_ownerpublickey(public_key);
  buffer_packet_info.set_online(1);
  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(crypto_obj_.AsymSign(
    ser_info, "", private_key, crypto::STRING_STRING));
  std::string bufferpacketname =
    crypto_obj_.Hash(owner_id + public_key, "", crypto::STRING_STRING, true);

  std::string ser_packet;
  buffer_packet.SerializeToString(&ser_packet);
  return sm_->CreateBP(bufferpacketname, ser_packet);
}

int ClientBufferPacketHandler::ChangeStatus(int status,
    const PacketType &type) {
  BufferPacketInfo packet_info;
  GenericPacket user_info;

  std::set<std::string> current_users;
  UserList(&current_users, MPID);

  packet_info.set_owner(ss_->PublicUsername());
  packet_info.set_ownerpublickey(ss_->PublicKey(type));
  packet_info.set_online(status);

  for (std::set<std::string>::iterator p = current_users.begin();
      p != current_users.end(); p++) {
    packet_info.add_users(*p);
  }

  std::string ser_info;
  packet_info.SerializeToString(&ser_info);
  user_info.set_data(ser_info);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) +
                                 ss_->PublicKey(type), "",
                                 crypto::STRING_STRING, true);
  user_info.set_signature(crypto_obj_.AsymSign(ser_info, "",
      ss_->PrivateKey(type), crypto::STRING_STRING));
  std::string ser_gp;
  user_info.SerializeToString(&ser_gp);

  return sm_->ModifyBPInfo(bufferpacketname, ser_gp);
}

bool ClientBufferPacketHandler::UserList(std::set<std::string> *list,
                                         PacketType type) {
  switch (type) {
    case MPID: *list = ss_->AuthorisedUsers(); break;
    case MAID: *list = ss_->MaidAuthorisedUsers(); break;
    default: break;
  }
  return true;
}

bool ClientBufferPacketHandler::SetUserList(std::set<std::string> list,
                                            PacketType type) {
  switch (type) {
    case MPID: ss_->SetAuthorisedUsers(list); break;
    case MAID: ss_->SetMaidAuthorisedUsers(list); break;
    default: break;
  }
  return true;
}

int ClientBufferPacketHandler::AddUsers(const std::set<std::string> &users,
                                        const PacketType &type) {
  if (users.empty()) {
#ifdef DEBUG
    printf("ClientBufferPacketHandler::AddUsers - Users empty.\n");
#endif
    return -1;
  }

  BufferPacketInfo packet_info;
  GenericPacket user_info;

  std::set<std::string> current_users;
  UserList(&current_users, type);

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
  packet_info.SerializeToString(&ser_info);
  user_info.set_data(ser_info);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) +
                                 ss_->PublicKey(type), "",
                                 crypto::STRING_STRING, true);
  user_info.set_signature(crypto_obj_.AsymSign(ser_info, "",
      ss_->PrivateKey(type), crypto::STRING_STRING));

  std::string ser_gp;
  user_info.SerializeToString(&ser_gp);

  int n = sm_->ModifyBPInfo(bufferpacketname, ser_gp);
#ifdef DEBUG
  printf("ClientBufferPacketHandler::AddUsers - ModifyBPInfo %d. %s %s\n", n,
         ss_->Id(type).c_str(),
         HexEncodeSubstring(ss_->PublicKey(type)).c_str());
#endif
  if (n == 0)
    SetUserList(users, type);
  return n;
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
  packet_info.SerializeToString(&ser_info);
  gp.set_data(ser_info);
  gp.set_signature(crypto_obj_.AsymSign(ser_info, "", ss_->PrivateKey(type),
      crypto::STRING_STRING));
  std::string ser_gp;
  gp.SerializeToString(&ser_gp);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) +
                                 ss_->PublicKey(type), "",
                                 crypto::STRING_STRING, true);
  int n = sm_->ModifyBPInfo(bufferpacketname, ser_gp);
  if (n == 0) {
    if (type == MPID)
      ss_->SetAuthorisedUsers(current_users);
    else
      ss_->SetMaidAuthorisedUsers(current_users);
  }
  return n;
}

int ClientBufferPacketHandler::GetMessages(const PacketType &type,
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
  if (sm_->LoadBPMessages(bufferpacketname, &messages) != 0)
    return -1;
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
  return 0;
}

int ClientBufferPacketHandler::GetBufferPacketInfo(const PacketType &type) {
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) +
                                 ss_->PublicKey(type), "",
                                 crypto::STRING_STRING, true);
  std::string packet_content;
  sm_->LoadChunk(bufferpacketname, &packet_content);
  BufferPacket bp;
  BufferPacketInfo bpi;
  if (!bp.ParseFromString(packet_content)) {
    return -1;
  }

  if (!bpi.ParseFromString(bp.owner_info(0).data())) {
    return -1;
  }
  std::set<std::string> users;
  for (int i = 0; i < bpi.users_size(); ++i) {
    users.insert(bpi.users(i));
  }
  ss_->SetAuthorisedUsers(users);
  return 0;
}

int ClientBufferPacketHandler::GetBufferPacket(const PacketType &type,
    std::list<ValidatedBufferPacketMessage> *valid_messages) {
//  std::string packet_content;
//  if (sm_->LoadChunk(bufferpacketname, &packet_content) != 0)
//    return -1;
//  BufferPacket bp;
//  BufferPacketInfo bpi;
//  if (!bp.ParseFromString(packet_content)) {
//    return -1;
//  }
//
//  if (!bpi.ParseFromString(bp.owner_info(0).data())) {
//    return -1;
//  }
//  std::set<std::string> users;
//  for (int i = 0; i < bpi.users_size(); ++i) {
//    users.insert(bpi.users(i));
//  }
//  ss_->SetAuthorisedUsers(users);
  if (GetBufferPacketInfo(type) != 0)
    return -1;

  std::list<std::string> encrypted_messages;
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(type) +
                                 ss_->PublicKey(type), "",
                                 crypto::STRING_STRING, true);
  if (sm_->LoadBPMessages(bufferpacketname, &encrypted_messages) != 0)
    return -1;

  valid_messages->clear();
  while (!encrypted_messages.empty()) {
    ValidatedBufferPacketMessage valid_message;
    if (valid_message.ParseFromString(encrypted_messages.front())) {
      std::string aes_key = crypto_obj_.AsymDecrypt(valid_message.index(), "",
          ss_->PrivateKey(type), crypto::STRING_STRING);
      valid_message.set_message(crypto_obj_.SymmDecrypt(valid_message.message(),
          "", crypto::STRING_STRING, aes_key));
      valid_messages->push_back(valid_message);
    }
    encrypted_messages.pop_front();
  }
  return 0;
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
