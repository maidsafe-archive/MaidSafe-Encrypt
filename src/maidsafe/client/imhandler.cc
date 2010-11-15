/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Class that Validates and creates messages for im
* Version:      1.0
* Created:      2010-04-13
* Revision:     none
* Compiler:     gcc
* Author:
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

#include <maidsafe/maidsafe-dht_config.h>

#include "maidsafe/common/commonutils.h"
#include "maidsafe/client/imhandler.h"
#include "maidsafe/client/sessionsingleton.h"

namespace maidsafe {

IMHandler::IMHandler() : ss_(SessionSingleton::getInstance()), crypto_() {}

std::string IMHandler::CreateMessage(const std::string &msg,
                                     const std::string &receiver) {
  maidsafe::BufferPacketMessage bpmsg;
  bpmsg.set_sender_id(ss_->PublicUsername());
  bpmsg.set_type(INSTANT_MSG);
  std::string aes_key =
      base::RandomString(crypto::AES256_KeySize + crypto::AES256_IVSize);
  bpmsg.set_aesenc_message(crypto_.SymmEncrypt(msg, "", crypto::STRING_STRING,
                                               aes_key));
  std::string rec_pub_key(ss_->GetContactPublicKey(receiver));
  bpmsg.set_rsaenc_key(crypto_.AsymEncrypt(aes_key, "", rec_pub_key,
                                           crypto::STRING_STRING));
  std::string mpid_private;
  ss_->MPublicID(NULL, NULL, &mpid_private, NULL);
  GenericPacket gp;
  gp.set_data(bpmsg.SerializeAsString());
  gp.set_signature(RSASign(gp.data(), mpid_private));
  return gp.SerializeAsString();
}

std::string IMHandler::CreateMessageEndpoint(const std::string &receiver) {
  InstantMessage msg;
  msg.set_sender(ss_->PublicUsername());
  msg.set_message("");
  msg.set_date(base::GetEpochTime());
  msg.set_status(ss_->ConnectionStatus());
  EndPoint *endpoint = msg.mutable_endpoint();
  *endpoint = ss_->Ep();
  std::string ser_msg(msg.SerializeAsString());

  BufferPacketMessage bpmsg;
  bpmsg.set_sender_id(ss_->PublicUsername());
  bpmsg.set_type(HELLO_PING);
  std::string aes_key =
      base::RandomString(crypto::AES256_KeySize + crypto::AES256_IVSize);
  bpmsg.set_aesenc_message(crypto_.SymmEncrypt(ser_msg, "",
      crypto::STRING_STRING, aes_key));
  std::string rec_pub_key(ss_->GetContactPublicKey(receiver));
  bpmsg.set_rsaenc_key(crypto_.AsymEncrypt(aes_key, "",
      rec_pub_key, crypto::STRING_STRING));

  std::string mpid_private;
  ss_->MPublicID(NULL, NULL, &mpid_private, NULL);
  GenericPacket gp;
  gp.set_data(bpmsg.SerializeAsString());
  gp.set_signature(RSASign(gp.data(), mpid_private));
  return gp.SerializeAsString();
}

std::string IMHandler::CreateLogOutMessage(const std::string &receiver) {
  InstantMessage msg;
  msg.set_sender(ss_->PublicUsername());
  msg.set_message("");
  msg.set_date(base::GetEpochTime());
  msg.set_status(ss_->ConnectionStatus());
  std::string ser_msg(msg.SerializeAsString());

  BufferPacketMessage bpmsg;
  bpmsg.set_sender_id(ss_->PublicUsername());
  bpmsg.set_type(LOGOUT_PING);
  std::string aes_key =
      base::RandomString(crypto::AES256_KeySize + crypto::AES256_IVSize);
  bpmsg.set_aesenc_message(crypto_.SymmEncrypt(ser_msg, "",
      crypto::STRING_STRING, aes_key));
  std::string rec_pub_key(ss_->GetContactPublicKey(receiver));
  bpmsg.set_rsaenc_key(crypto_.AsymEncrypt(aes_key, "",
      rec_pub_key, crypto::STRING_STRING));

  std::string mpid_private;
  ss_->MPublicID(NULL, NULL, &mpid_private, NULL);
  GenericPacket gp;
  gp.set_data(bpmsg.SerializeAsString());
  gp.set_signature(RSASign(gp.data(), mpid_private));
  return gp.SerializeAsString();
}

bool IMHandler::ValidateMessage(const std::string &ser_msg,
                                MessageType *type,
                                std::string *validated_msg) {
  validated_msg->clear();
  GenericPacket gp;
  if (!gp.ParseFromString(ser_msg)) {
    return false;
  }
  BufferPacketMessage bpmsg;
  if (!bpmsg.ParseFromString(gp.data())) {
    return false;
  }
  std::string send_pub_key(ss_->GetContactPublicKey(bpmsg.sender_id()));
  if (!RSACheckSignedData(gp.data(), gp.signature(), send_pub_key)) {
    return false;
  }

  std::string mpid_private;
  ss_->MPublicID(NULL, NULL, &mpid_private, NULL);
  std::string aes_key(crypto_.AsymDecrypt(bpmsg.rsaenc_key(), "",
      mpid_private, crypto::STRING_STRING));
  *validated_msg = crypto_.SymmDecrypt(bpmsg.aesenc_message(), "",
      crypto::STRING_STRING, aes_key);
  *type = bpmsg.type();
  return true;
}

}  // namespace
