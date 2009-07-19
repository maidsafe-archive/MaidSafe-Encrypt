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

#include "maidsafe/vault/vaultbufferpackethandler.h"
#include <cstdio>
#include "protobuf/packet.pb.h"

namespace packethandler {

VaultBufferPacketHandler::VaultBufferPacketHandler() : crypto_obj_() {
  crypto_obj_.set_hash_algorithm(crypto::SHA_512);
  crypto_obj_.set_symm_algorithm(crypto::AES_256);
}

//  bool VaultBufferPacketHandler::OnlineStatus() {
//    return false;
//  }

bool VaultBufferPacketHandler::CheckMsgStructure(
    const std::string &ser_message,
    std::string &sender_id, MessageType &type) {
  GenericPacket message;

  if (!message.ParseFromString(ser_message))
    return false;

  BufferPacketMessage bpm;
  if (!bpm.ParseFromString(message.data()))
    return false;

  sender_id = bpm.sender_id();
  type = bpm.type();
  return true;
}

bool VaultBufferPacketHandler::IsOwner(std::string owner_id,
  GenericPacket gp_info) {
  BufferPacketInfo bpi;
  if (!bpi.ParseFromString(gp_info.data()))
    return false;
  if (bpi.owner() == owner_id)
    return true;
  return false;
}

bool VaultBufferPacketHandler::ValidateOwnerSignature(std::string public_key,
  std::string ser_bufferpacket) {
  BufferPacket bp;
  if (!bp.ParseFromString(ser_bufferpacket))
    return false;
  return crypto_obj_.AsymCheckSig(bp.owner_info(0).data(),
    bp.owner_info(0).signature(), public_key, crypto::STRING_STRING);
}

bool VaultBufferPacketHandler::GetMessages(const std::string &ser_bp,
  std::vector<std::string> *msgs) {
  BufferPacket bp;
  if (!bp.ParseFromString(ser_bp))
    return false;
  GenericPacket gp;
  BufferPacketMessage bpm;
  ValidatedBufferPacketMessage msg;
  for (int i = 0; i < bp.messages_size(); i++) {
    gp = bp.messages(i);
    if (bpm.ParseFromString(gp.data())) {
      msg.clear_index();
      msg.clear_message();
      msg.clear_sender();
      msg.clear_type();

      msg.set_index(bpm.rsaenc_key());
      msg.set_message(bpm.aesenc_message());
      msg.set_sender(bpm.sender_id());

      // printf("Message: %s\n", msg.message);
      // printf("Sender: %s\n", msg.sender);
      msg.set_type(bpm.type());
      std::string ser_msg;
      msg.SerializeToString(&ser_msg);
      msgs->push_back(ser_msg);
    }
  }
  return true;
}

bool VaultBufferPacketHandler::ClearMessages(std::string *ser_bufferpacket) {
  BufferPacket bp;
  if (!bp.ParseFromString(*ser_bufferpacket)) {
    printf("No parsea como bufferpacket");
    return false;
  }
  bp.clear_messages();
  bp.SerializeToString(ser_bufferpacket);
  return true;
}

bool VaultBufferPacketHandler::ChangeOwnerInfo(std::string ser_gp,
  std::string *ser_packet, std::string public_key) {
  if (!ValidateOwnerSignature(public_key, *ser_packet))
    return false;
  BufferPacket bp;
  bp.ParseFromString(*ser_packet);
  bp.clear_owner_info();
  GenericPacket *gp = bp.add_owner_info();
  if (!gp->ParseFromString(ser_gp)) {
    return false;
  } else {
    BufferPacketInfo bpi;
    if (!bpi.ParseFromString(gp->data()))
      return false;
  }
  bp.SerializeToString(ser_packet);
  return true;
}

bool VaultBufferPacketHandler::CheckStatus(const std::string &current_bp,
    const std::string &ser_message, const std::string &signed_public_key,
    int *status) {
  GenericPacket message;
  if (!message.ParseFromString(ser_message)) {
#ifdef DEBUG
    printf("invalid msg\n");
#endif
    return false;
  }

  BufferPacket bufferpacket;
  if (!bufferpacket.ParseFromString(current_bp)) {
#ifdef DEBUG
    printf("invalid bufferpacket\n");
#endif
    return false;
  }

  // getting message from signed data sent
  BufferPacketMessage bpm;
  if (!bpm.ParseFromString(message.data())) {
#ifdef DEBUG
    printf("invalid bpmessage\n");
#endif
    return false;
  }

  if (bpm.type() != STATUS_CHECK) {
#ifdef DEBUG
    printf("invalid message type\n");
#endif
    return false;
  }

  std::string public_key = bpm.sender_public_key();
  if (!crypto_obj_.AsymCheckSig(public_key, signed_public_key,
      public_key, crypto::STRING_STRING)) {
#ifdef DEBUG
    printf("invalid public key signature\n");
#endif
    return false;
  }

  if (!crypto_obj_.AsymCheckSig(message.data(), message.signature(),
      public_key, crypto::STRING_STRING)) {
#ifdef DEBUG
    printf("invalid message signature\n");
#endif
    return false;
  }

  BufferPacketInfo bpi;
  bpi.ParseFromString(bufferpacket.owner_info(0).data());
  if (!bpi.has_online()) {
#ifdef DEBUG
    printf("NO STATUS\n");
#endif
  }

  bool flag = false;
  // TODO(dan): here ther should be no check for user in list
  // if it is decided to accept from all
  for (int i = 0; i < bpi.users_size(); i++)
    if (bpi.users(i) == bpm.sender_id()) {
      flag = true;
      break;
    }
  if (!flag) {
#ifdef DEBUG
    printf("unauthorised user\n");
#endif
    return false;
  }

  *status = bpi.online();
  return true;
}

bool VaultBufferPacketHandler::AddMessage(const std::string &current_bp,
    const std::string &ser_message, const std::string &signed_public_key,
    std::string *updated_bp) {
  GenericPacket message;
  if (!message.ParseFromString(ser_message)) {
    printf("invalid msg\n");
    return false;
  }

  BufferPacket bufferpacket;
  if (!bufferpacket.ParseFromString(current_bp)) {
    printf("invalid bufferpacket\n");
    return false;
  }

  // getting message from signed data sent
  BufferPacketMessage bpm;
  if (!bpm.ParseFromString(message.data())) {
    printf("invalid bpmessage\n");
    return false;
  }

  // Checking signature or by name of id_package
  std::string public_key;
  //  These are the messages that are not sent with the MPID.
  //  Other new messages sent with the MPID should be here as well.
  if (bpm.type() != INSTANT_MSG && bpm.type() != ADD_CONTACT_RQST) {
    public_key = bpm.sender_public_key();
    std::string id = crypto_obj_.Hash(public_key+signed_public_key, "",
      crypto::STRING_STRING, true);
    if (id != bpm.sender_id()) {
      printf("invalid sender_id\n");
      return false;
    }
  } else {
    public_key = bpm.sender_public_key();
  }

  if (!crypto_obj_.AsymCheckSig(message.data(), message.signature(),
    public_key, crypto::STRING_STRING)) {
    printf("invalid message signature\n");
    return false;
  }

  if (bpm.type() != ADD_CONTACT_RQST) {
    BufferPacketInfo bpi;
    bpi.ParseFromString(bufferpacket.owner_info(0).data());
    bool flag = false;
    // TODO(dan): here ther should be no check for user in list
    // if it is decided to accept from all
    for (int i = 0; i < bpi.users_size(); i++)
      if (bpi.users(i) == bpm.sender_id()) {
        i = bpi.users_size();
        flag = true;
      }
    if (!flag) {
      printf("unauthorised user\n");
      return false;
    }
  }

  GenericPacket *gp = bufferpacket.add_messages();
  gp->set_data(message.data());
  gp->set_signature(message.signature());

  bufferpacket.SerializeToString(updated_bp);
  return true;
}

}   // namespace packethandler
