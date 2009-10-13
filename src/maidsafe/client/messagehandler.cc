/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Handles messages!
* Version:      1.0
* Created:      09/09/2008 12:14:35 PM
* Revision:     none
* Compiler:     gcc
* Author:       David Irvine (di), david.irvine@maidsafe.net
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

#include "maidsafe/client/messagehandler.h"

#include <stdlib.h>
#include <time.h>

#include <cstdio>
#include <list>

#include "protobuf/packet.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace maidsafe {

MessageHandler::MessageHandler(StoreManagerInterface *sm)
    : ss_(SessionSingleton::getInstance()), sm_(sm), co_(), mutex_() {
  co_.set_hash_algorithm(crypto::SHA_512);
  co_.set_symm_algorithm(crypto::AES_256);
}

void MessageHandler::SendMessage(const std::string &msg,
                                 const std::vector<Receivers> &receivers,
                                 const PacketType &p_type,
                                 const MessageType &m_type,
                                 base::callback_func_type cb) {
  boost::mutex::scoped_lock gaurd(mutex_);
  boost::shared_ptr<SendMessagesData> data(new SendMessagesData());
  data->index = -1;
  data->is_calledback = false;
  data->cb = cb;
  data->active_sends = 0;
  data->receivers = receivers;
  std::vector<std::string> no_auth_rec;
  data->no_auth_rec = no_auth_rec;
  data->successful_stores = 0;
  data->stores_done = 0;
  data->p_type = p_type;
  data->m_type = m_type;
  data->msg = msg;
  data->timestamp = base::get_epoch_time();
  IterativeStoreMsgs(data);
}

std::string MessageHandler::CreateMessage(
    const std::string &msg,
    const std::string &rec_public_key,
    const MessageType &m_type,
    const PacketType &p_type,
    const boost::uint32_t &timestamp) {
  BufferPacketMessage bpm;
  GenericPacket gp;

  bpm.set_sender_id(ss_->Id(p_type));
  bpm.set_sender_public_key(ss_->PublicKey(p_type));
  bpm.set_type(m_type);
  int iter = base::random_32bit_uinteger() % 1000 +1;
  std::string aes_key = co_.SecurePassword(
      co_.Hash(msg, "", crypto::STRING_STRING, true),
      iter);
  bpm.set_rsaenc_key(co_.AsymEncrypt(aes_key, "", rec_public_key,
                                     crypto::STRING_STRING));
  bpm.set_aesenc_message(co_.SymmEncrypt(msg, "", crypto::STRING_STRING,
                                         aes_key));
  bpm.set_timestamp(timestamp);
  std::string ser_bpm;
  bpm.SerializeToString(&ser_bpm);
  gp.set_data(ser_bpm);
  gp.set_signature(co_.AsymSign(gp.data(),
                                "",
                                ss_->PrivateKey(p_type),
                                crypto::STRING_STRING));
  std::string ser_gp;
  gp.SerializeToString(&ser_gp);
  return ser_gp;
}

void MessageHandler::CreateSignature(const std::string &buffer_name,
                                     const PacketType &type,
                                     std::string *signed_request,
                                     std::string *signed_public_key) {
  *signed_public_key = co_.AsymSign(ss_->PublicKey(type),
                                    "",
                                    ss_->PrivateKey(type),
                                    crypto::STRING_STRING);
  *signed_request = co_.AsymSign(co_.Hash(ss_->PublicKey(type) +
                    *signed_public_key + base::DecodeFromHex(buffer_name), "",
                    crypto::STRING_STRING, false), "", ss_->PrivateKey(type),
                    crypto::STRING_STRING);
}

void MessageHandler::IterativeStoreMsgs(
    boost::shared_ptr<SendMessagesData> data) {
  if (data->is_calledback) {
    return;
  }
  if (data->stores_done == static_cast<int>(data->receivers.size())) {
    StoreMessagesResult result;
    if (data->successful_stores == 0)
      result.set_result(kNack);
    else
      result.set_result(kAck);
    result.set_stored_msgs(data->successful_stores);
    for (int i = 0; i < static_cast<int>(data->no_auth_rec.size()); ++i) {
      result.add_failed(data->no_auth_rec[i]);
    }
    data->is_calledback = true;
    std::string str_result;
    result.SerializeToString(&str_result);
    data->cb(str_result);
    return;
  }

  if (data->index < static_cast<int>(data->receivers.size())) {
    int msgs_to_send = parallelSendMsgs - data->active_sends;

    for (int n = 0;
         n < msgs_to_send &&
         data->index < static_cast<int>(data->receivers.size());
         ++n) {
      ++data->index;
      std::string rec_public_key;
      std::string ser_packet="";
      std::string sys_packet_name;
      switch (data->p_type) {
        case ADD_CONTACT_RQST:
        case INSTANT_MSG:
            sys_packet_name = co_.Hash(data->receivers[data->index].id,
                                       "",
                                       crypto::STRING_STRING,
                                       true);
            break;
        default : sys_packet_name = data->receivers[data->index].id;
      }
      ++data->active_sends;
      StoreMessage(data->index, data);
    }
  }
}

void MessageHandler::StoreMessage(int index,
    boost::shared_ptr<SendMessagesData> data) {
  if (data->is_calledback) {
    return;
  }
  std::string ser_msg = CreateMessage(data->msg,
                                      data->receivers[index].public_key,
                                      data->m_type,
                                      data->p_type,
                                      data->timestamp);
  std::string bufferpacketname = co_.Hash(data->receivers[index].id +
                                 data->receivers[index].public_key, "",
                                 crypto::STRING_STRING, true);
#ifdef DEBUG
  // printf("\nBufferpacket name (Saving):\n%s\n\n", bufferpacketname.c_str());
#endif
  std::string signed_public_key, signed_request;
  CreateSignature(bufferpacketname,
                  data->p_type,
                  &signed_request,
                  &signed_public_key);
  if (sm_->AddBPMessage(bufferpacketname, ser_msg) == 0) {
    ++data->successful_stores;
  } else {
    data->no_auth_rec.push_back(data->receivers[index].id);
  }
  --data->active_sends;
  ++data->stores_done;
  IterativeStoreMsgs(data);
}

}  //  namespace maidsafe
