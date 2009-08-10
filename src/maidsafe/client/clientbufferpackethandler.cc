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
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace packethandler {

void ExecuteFailureCallback(base::callback_func_type cb,
    boost::recursive_mutex *mutex) {
  base::pd_scoped_lock gaurd(*mutex);
  maidsafe::GenericResponse result;
  result.set_result(kNack);
  std::string ser_result;
  result.SerializeToString(&ser_result);
  cb(ser_result);
}

ClientBufferPacketHandler::ClientBufferPacketHandler(
    maidsafe::StoreManagerInterface *sm, boost::recursive_mutex *mutex)
        : crypto_obj_(),
          ss_(maidsafe::SessionSingleton::getInstance()),
          sm_(sm),
          mutex_(mutex) {
  crypto_obj_.set_hash_algorithm(crypto::SHA_512);
  crypto_obj_.set_symm_algorithm(crypto::AES_256);
}

void ClientBufferPacketHandler::CreateBufferPacket(
    const std::string &owner_id, const std::string &public_key,
    const std::string &private_key, base::callback_func_type cb) {
  BufferPacket buffer_packet;
  GenericPacket *ser_owner_info = buffer_packet.add_owner_info();
  BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(owner_id);
  buffer_packet_info.set_ownerpublickey(public_key);
  buffer_packet_info.set_online(1);

//  #ifdef DEBUG
//    printf("buffer_packet_info.online: %i\n", buffer_packet_info.online());
//  #endif
//
  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(crypto_obj_.AsymSign(
    ser_info, "", private_key, crypto::STRING_STRING));
  std::string bufferpacketname =
    crypto_obj_.Hash(owner_id + "BUFFER", "", crypto::STRING_STRING, true);
  std::string ser_packet;
  buffer_packet.SerializeToString(&ser_packet);
  std::string ser_bp = ser_packet;

  std::string signed_public_key =
    crypto_obj_.AsymSign(public_key, "", private_key, crypto::STRING_STRING);
  std::string non_hex_bufferpacketname("");
  base::decode_from_hex(bufferpacketname, &non_hex_bufferpacketname);
  std::string signed_request =
    crypto_obj_.AsymSign(crypto_obj_.Hash(public_key + signed_public_key +
    non_hex_bufferpacketname, "", crypto::STRING_STRING, true), "",
    private_key, crypto::STRING_STRING);
  sm_->StorePacket(bufferpacketname, ser_bp, signed_request, public_key,
    signed_public_key, maidsafe::BUFFER_PACKET, false, cb);
}

void ClientBufferPacketHandler::ChangeStatus(int status,
    base::callback_func_type cb, const BufferPacketType &type) {
  maidsafe::PacketType pt = PacketHandler_PacketType(type);
  BufferPacketInfo packet_info;
  GenericPacket user_info;

  std::set<std::string> current_users;
  UserList(&current_users, MPID_BP);

  packet_info.set_owner(ss_->PublicUsername());
  packet_info.set_ownerpublickey(ss_->PublicKey(pt));
  packet_info.set_online(status);

  for (std::set<std::string>::iterator p = current_users.begin();
      p != current_users.end(); p++) {
    packet_info.add_users(*p);
  }

  std::string ser_info;
  packet_info.SerializeToString(&ser_info);
  user_info.set_data(ser_info);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(pt) + "BUFFER", "",
      crypto::STRING_STRING, true);
  user_info.set_signature(crypto_obj_.AsymSign(ser_info, "",
      ss_->PrivateKey(pt), crypto::STRING_STRING));
  std::string signed_public_key = crypto_obj_.AsymSign(
      ss_->PublicKey(pt), "", ss_->PrivateKey(pt), crypto::STRING_STRING);
  std::string non_hex_bufferpacketname("");
  base::decode_from_hex(bufferpacketname, &non_hex_bufferpacketname);
  std::string signed_request = crypto_obj_.AsymSign(
    crypto_obj_.Hash(ss_->PublicKey(pt) + signed_public_key +
    non_hex_bufferpacketname, "", crypto::STRING_STRING, true), "",
    ss_->PrivateKey(pt), crypto::STRING_STRING);
  std::string ser_gp;
  user_info.SerializeToString(&ser_gp);

  sm_->StorePacket(bufferpacketname, ser_gp, signed_request,
      ss_->PublicKey(pt), signed_public_key,
      maidsafe::BUFFER_PACKET_INFO, true, boost::bind(
      &ClientBufferPacketHandler::ChangeStatus_Callback, this, _1, cb));
}

bool ClientBufferPacketHandler::UserList(
    std::set<std::string> *list, BufferPacketType type) {
  switch (type) {
    case MPID_BP: *list = ss_->AuthorisedUsers(); break;
    case MAID_BP: *list = ss_->MaidAuthorisedUsers(); break;
    default: break;
  }
  return true;
}

bool ClientBufferPacketHandler::SetUserList(std::set<std::string> list,
    BufferPacketType type) {
  switch (type) {
    case MPID_BP: ss_->SetAuthorisedUsers(list); break;
    case MAID_BP: ss_->SetMaidAuthorisedUsers(list); break;
    default: break;
  }
  return true;
}

void ClientBufferPacketHandler::AddUsers(const std::set<std::string> &users,
    base::callback_func_type cb, const BufferPacketType &type) {
  maidsafe::PacketType pt = PacketHandler_PacketType(type);
  // Why is a thread created here???
  // TODO(jose): remove thread and just call the callback function with
  // a failure result
  if (users.empty()) {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
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
  packet_info.set_ownerpublickey(ss_->PublicKey(pt));
  packet_info.set_online(0);

  for (std::set<std::string>::iterator p = current_users.begin();
    p != current_users.end(); p++) {
    packet_info.add_users(*p);
  }

  std::string ser_info;
  packet_info.SerializeToString(&ser_info);
  user_info.set_data(ser_info);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(pt) + "BUFFER", "",
      crypto::STRING_STRING, true);
  user_info.set_signature(crypto_obj_.AsymSign(ser_info, "",
      ss_->PrivateKey(pt), crypto::STRING_STRING));
  std::string signed_public_key = crypto_obj_.AsymSign(ss_->PublicKey(pt),
      "", ss_->PrivateKey(pt), crypto::STRING_STRING);
  std::string non_hex_bufferpacketname("");
  base::decode_from_hex(bufferpacketname, &non_hex_bufferpacketname);
  std::string signed_request = crypto_obj_.AsymSign(
      crypto_obj_.Hash(ss_->PublicKey(pt) + signed_public_key +
      non_hex_bufferpacketname, "", crypto::STRING_STRING, true), "",
      ss_->PrivateKey(pt), crypto::STRING_STRING);
  std::string ser_gp;
  user_info.SerializeToString(&ser_gp);

  sm_->StorePacket(bufferpacketname, ser_gp, signed_request,
      ss_->PublicKey(pt), signed_public_key, maidsafe::BUFFER_PACKET_INFO,
      true, boost::bind(&ClientBufferPacketHandler::AddUsers_Callback, this, _1,
      current_users, type, cb));
}

void ClientBufferPacketHandler::ChangeStatus_Callback(const std::string &result,
    base::callback_func_type cb) {
  maidsafe::UpdateResponse local_result;
  std::string str_local_result;
  if (!local_result.ParseFromString(result)) {
    local_result.set_result(kNack);
    local_result.SerializeToString(&str_local_result);
    cb(str_local_result);
    return;
  }
//  if (local_result.result() == kAck) {
//    ss_->SetConnectionStatus(status);
//  }
  local_result.SerializeToString(&str_local_result);
  cb(str_local_result);
}

void ClientBufferPacketHandler::AddUsers_Callback(const std::string &result,
  const std::set<std::string> &users, const BufferPacketType &type,
  base::callback_func_type cb) {
  maidsafe::UpdateResponse local_result;
  std::string str_local_result;
  if (!local_result.ParseFromString(result)) {
    local_result.set_result(kNack);
    local_result.SerializeToString(&str_local_result);
    cb(str_local_result);
    return;
  }
  if (local_result.result() == kAck) {
    SetUserList(users, type);
  }
  local_result.SerializeToString(&str_local_result);
  cb(str_local_result);
}

void ClientBufferPacketHandler::DeleteUsers(const std::set<std::string> &users,
    base::callback_func_type cb, const BufferPacketType &type) {
  maidsafe::PacketType pt = PacketHandler_PacketType(type);
  std::set<std::string> current_users;
  if (type == MPID_BP)
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
  packet_info.set_ownerpublickey(ss_->PublicKey(pt));
  packet_info.set_online(0);

  std::string ser_info;
  packet_info.SerializeToString(&ser_info);
  gp.set_data(ser_info);
  gp.set_signature(crypto_obj_.AsymSign(ser_info, "", ss_->PrivateKey(pt),
      crypto::STRING_STRING));
  std::string ser_gp;
  gp.SerializeToString(&ser_gp);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(pt) + "BUFFER",
      "", crypto::STRING_STRING, true);
  std::string signed_public_key = crypto_obj_.AsymSign(ss_->PublicKey(pt),
      "", ss_->PrivateKey(pt), crypto::STRING_STRING);
  std::string non_hex_bufferpacketname("");
  base::decode_from_hex(bufferpacketname, &non_hex_bufferpacketname);
  std::string signed_request = crypto_obj_.AsymSign(
    crypto_obj_.Hash(ss_->PublicKey(pt) + signed_public_key +
    non_hex_bufferpacketname, "", crypto::STRING_STRING, true), "",
    ss_->PrivateKey(pt), crypto::STRING_STRING);

  sm_->StorePacket(bufferpacketname, ser_gp, signed_request,
    ss_->PublicKey(pt), signed_public_key, maidsafe::BUFFER_PACKET_INFO,
    true, boost::bind(&ClientBufferPacketHandler::DeleleteUsers_Callback,
    this, _1, current_users, type, cb));
}

void ClientBufferPacketHandler::DeleleteUsers_Callback(
    const std::string &result, const std::set<std::string> &users,
    const BufferPacketType type, base::callback_func_type cb) {
  maidsafe::UpdateResponse local_result;
  std::string str_local_result;
  if (!local_result.ParseFromString(result)) {
    local_result.set_result(kNack);
    local_result.SerializeToString(&str_local_result);
    cb(str_local_result);
    return;
  }
  if (local_result.result() == kAck) {
    if (type == MPID_BP)
      ss_->SetAuthorisedUsers(users);
    else
      ss_->SetMaidAuthorisedUsers(users);
  }
  local_result.SerializeToString(&str_local_result);
  cb(str_local_result);
}

void ClientBufferPacketHandler::GetMessages(const BufferPacketType &type,
    base::callback_func_type cb) {
  maidsafe::PacketType pt = PacketHandler_PacketType(type);
  base::pd_scoped_lock gaurd(*mutex_);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(pt) + "BUFFER", "",
      crypto::STRING_STRING, true);
  std::string signed_public_key = crypto_obj_.AsymSign(
      ss_->PublicKey(pt), "", ss_->PrivateKey(pt), crypto::STRING_STRING);

  sm_->GetMessages(bufferpacketname, ss_->PublicKey(pt),
      signed_public_key, boost::bind(
      &ClientBufferPacketHandler::GetMessages_Callback, this, _1, type, cb));
}

void ClientBufferPacketHandler::GetMessages_Callback(const std::string &result,
    const BufferPacketType &type, base::callback_func_type cb) {
  maidsafe::PacketType pt = PacketHandler_PacketType(type);
  maidsafe::GetMessagesResponse local_result;
  std::string str_local_result;
  if (!local_result.ParseFromString(result)) {
    local_result.set_result(kNack);
    local_result.SerializeToString(&str_local_result);
    cb(str_local_result);
    return;
  }
  if (local_result.result() == kAck) {
    maidsafe::GetMessagesResponse result_dec_msgs;
    result_dec_msgs.set_result(kAck);
    for (int i = 0; i < local_result.messages_size() ; i++) {
      ValidatedBufferPacketMessage msg;
      std::string ser_msg = local_result.messages(i);
      if (msg.ParseFromString(ser_msg)) {
        std::string aes_key = crypto_obj_.AsymDecrypt(msg.index(), "",
          ss_->PrivateKey(pt), crypto::STRING_STRING);
        std::string enc_msg = msg.message();
        msg.set_message(crypto_obj_.SymmDecrypt(enc_msg, "",
          crypto::STRING_STRING, aes_key));
        std::string ser_decmsg;
        msg.SerializeToString(&ser_decmsg);
        result_dec_msgs.add_messages(ser_decmsg);
      }
    }
    result_dec_msgs.SerializeToString(&str_local_result);
  } else {
    local_result.SerializeToString(&str_local_result);
  }
  cb(str_local_result);
}

void ClientBufferPacketHandler::GetBufferPacket(const BufferPacketType &type,
    base::callback_func_type cb) {
  std::string bufferpacketname = crypto_obj_.Hash(
      ss_->Id(PacketHandler_PacketType(type)) + "BUFFER", "",
      crypto::STRING_STRING, true);
  sm_->LoadPacket(bufferpacketname,
      boost::bind(&ClientBufferPacketHandler::GetBufferPacket_Callback, this,
      _1, type, cb));
}

void ClientBufferPacketHandler::GetBufferPacket_Callback(
    const std::string &result, const BufferPacketType &type,
    base::callback_func_type cb) {
  maidsafe::GetResponse local_result;
  std::string str_local_result;
  if ((!local_result.ParseFromString(result))||
      (!local_result.has_content())) {
    local_result.set_result(kNack);
    local_result.SerializeToString(&str_local_result);
    cb(str_local_result);
    return;
  }
  maidsafe::GetMessagesResponse msgs_result;
  msgs_result.set_result(kAck);
  BufferPacket bp;
  BufferPacketInfo bpi;
  bp.ParseFromString(local_result.content());
  bpi.ParseFromString(bp.owner_info(0).data());
  std::set<std::string> users;
  for (int i = 0; i < bpi.users_size(); ++i) {
    printf("ClientBufferPacketHandler::GetBufferPacket_Callback - AU: %s\n",
            bpi.users(i).c_str());
    users.insert(bpi.users(i));
  }
  ss_->SetAuthorisedUsers(users);


  GenericPacket gp;
  BufferPacketMessage bpm;
  std::string aes_key;
  for (int i = 0; i < bp.messages_size(); ++i) {
    gp = bp.messages(i);
    if (bpm.ParseFromString(gp.data()))
      if ((bpm.type() == ADD_CONTACT_RQST) ||
          (crypto_obj_.AsymCheckSig(gp.data(), gp.signature(),
          bpm.sender_public_key(), crypto::STRING_STRING))) {
        ValidatedBufferPacketMessage msg;
        msg.set_index(bpm.rsaenc_key());
        aes_key = crypto_obj_.AsymDecrypt(msg.index(), "",
            ss_->PrivateKey(PacketHandler_PacketType(type)),
            crypto::STRING_STRING);
        msg.set_message(crypto_obj_.SymmDecrypt(bpm.aesenc_message(), "",
            crypto::STRING_STRING, aes_key));
        msg.set_sender(bpm.sender_id());
        msg.set_type(bpm.type());
        std::string ser_msg;
        msg.SerializeToString(&ser_msg);
        msgs_result.add_messages(ser_msg);
      }
  }
  msgs_result.SerializeToString(&str_local_result);
  cb(str_local_result);
}

void ClientBufferPacketHandler::GetBufferPacketInfo(
    const BufferPacketType &type, base::callback_func_type cb) {
  std::string bufferpacketname = crypto_obj_.Hash(
      ss_->Id(PacketHandler_PacketType(type)) + "BUFFER", "",
      crypto::STRING_STRING, true);
  sm_->LoadPacket(bufferpacketname,
      boost::bind(&ClientBufferPacketHandler::GetBufferPacket_Callback, this,
      _1, type, cb));
}

void ClientBufferPacketHandler::GetBufferPacketInfo_Callback(
    const std::string &result, base::callback_func_type cb) {
  maidsafe::GetResponse local_result;
  std::string str_local_result;
  if ((!local_result.ParseFromString(result))||
      (!local_result.has_content())) {
    local_result.set_result(kNack);
    local_result.SerializeToString(&str_local_result);
    cb(str_local_result);
    return;
  }
  maidsafe::GetMessagesResponse msgs_result;
  msgs_result.set_result(kAck);
  BufferPacket bp;
  BufferPacketInfo bpi;
  bp.ParseFromString(local_result.content());
  bpi.ParseFromString(bp.owner_info(0).data());
  std::set<std::string> users;
  for (int i = 0; i < bpi.users_size(); ++i)
    users.insert(bpi.users(i));
  ss_->SetAuthorisedUsers(users);
  local_result.set_result(kAck);
  local_result.SerializeToString(&str_local_result);
  cb(str_local_result);
}

void ClientBufferPacketHandler::ClearMessages(const BufferPacketType &type,
    base::callback_func_type cb) {
  maidsafe::PacketType pt = PacketHandler_PacketType(type);
  std::string bufferpacketname = crypto_obj_.Hash(ss_->Id(pt) + "BUFFER", "",
      crypto::STRING_STRING, true);
  std::string signed_public_key = crypto_obj_.AsymSign(
      ss_->PublicKey(pt), "", ss_->PrivateKey(pt), crypto::STRING_STRING);
  std::string non_hex_bufferpacketname("");
  base::decode_from_hex(bufferpacketname, &non_hex_bufferpacketname);
  std::string signed_request = crypto_obj_.AsymSign(
    crypto_obj_.Hash(ss_->PublicKey(pt) + signed_public_key +
    non_hex_bufferpacketname, "", crypto::STRING_STRING, true), "",
    ss_->PrivateKey(pt), crypto::STRING_STRING);

  sm_->DeletePacket(bufferpacketname, signed_request,
      ss_->PublicKey(pt), signed_public_key,
      maidsafe::BUFFER_PACKET_MESSAGE, cb);
}

maidsafe::PacketType ClientBufferPacketHandler::PacketHandler_PacketType(
    const BufferPacketType &type) {
  //  MPID_BP, MAID_BP, PMID_BP
  switch (type) {
    case MAID_BP: return maidsafe::MAID;
    case PMID_BP: return maidsafe::PMID;
    default: return maidsafe::MPID;
  }
}

}  // namespace packethandler
