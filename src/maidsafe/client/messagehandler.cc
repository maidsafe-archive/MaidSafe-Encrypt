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

MessageHandler::MessageHandler(StoreManagerInterface *sm,
                               boost::recursive_mutex *mutex)
                                   : ss_(SessionSingleton::getInstance()),
                                     sm_(sm),
                                     co_(),
                                     mutex_(mutex) {
  co_.set_hash_algorithm("SHA512");
  co_.set_symm_algorithm("AES_256");
}

void MessageHandler::SendMessage(const std::string &msg,
                                 const std::vector<Receivers> &receivers,
                                 const buffer_packet_type &p_type,
                                 const packethandler::MessageType &m_type,
                                 base::callback_func_type cb) {
  base::pd_scoped_lock gaurd(*mutex_);
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
  IterativeStoreMsgs(data);
}

std::string MessageHandler::CreateMessage(
    const std::string &msg,
    const std::string &rec_public_key,
    const packethandler::MessageType &m_type,
    const buffer_packet_type &p_type) {
  packethandler::BufferPacketMessage bpm;
  packethandler::GenericPacket gp;

  bpm.set_sender_id(ss_->GetId(p_type));
  bpm.set_sender_public_key(ss_->GetPublicKey(p_type));
  bpm.set_type(m_type);
  int iter = base::random_32bit_uinteger() % 1000 +1;
  std::string aes_key = co_.SecurePassword(
      co_.Hash(msg, "", maidsafe_crypto::STRING_STRING, true),
      iter);
  bpm.set_rsaenc_key(co_.AsymEncrypt(aes_key,
                                     "",
                                     rec_public_key,
                                     maidsafe_crypto::STRING_STRING));
  bpm.set_aesenc_message(co_.SymmEncrypt(msg,
                                         "",
                                         maidsafe_crypto::STRING_STRING,
                                         aes_key));
  std::string ser_bpm;
  bpm.SerializeToString(&ser_bpm);
  gp.set_data(ser_bpm);
  gp.set_signature(co_.AsymSign(gp.data(),
                                "",
                                ss_->GetPrivateKey(p_type),
                                maidsafe_crypto::STRING_STRING));
  std::string ser_gp;
  gp.SerializeToString(&ser_gp);
  return ser_gp;
}

void MessageHandler::CreateSignature(const std::string &buffer_name,
                                     const buffer_packet_type &type,
                                     std::string *signed_request,
                                     std::string *signed_public_key) {
  *signed_public_key = co_.AsymSign(ss_->GetPublicKey(type),
                                    "",
                                    ss_->GetPrivateKey(type),
                                    maidsafe_crypto::STRING_STRING);
  std::string non_hex_buffer_name("");
  base::decode_from_hex(buffer_name, &non_hex_buffer_name);
  *signed_request = co_.AsymSign(
      co_.Hash(ss_->GetPublicKey(type) + *signed_public_key +
               non_hex_buffer_name, "", maidsafe_crypto::STRING_STRING, true),
      "",
      ss_->GetPrivateKey(type),
      maidsafe_crypto::STRING_STRING);
}

// bool MessageHandler::HandleMessages(std::list<dht::entry> msgs) {
//   while (!msgs.empty()){
//     packethandler::ValidatedBufferPacketMessage msg;
//     std::string ser_msg = msgs.front().string();
//     msgs.pop_front();
//     if (msg.ParseFromString(ser_msg)) {
//       packethandler::ContactInfo ci;
//       switch (msg.type()){
//         case packethandler::SHARE:
// #ifdef DEBUG
//             printf("Msg Received: %s\n", msg.message);
//             printf("Sender: %s\n", msg.sender());
//             printf("msg is a share.");
// #endif
//             break;
//         case packethandler::ADD_CONTACT_RQST:
// #ifdef DEBUG
//             printf("ADD_CONTACT_RQST received.");
//             printf("Sender: %s\n", msg.sender().c_str());
// #endif
//             if (!ci.ParseFromString(msg.message())) {
// #ifdef DEBUG
//               printf("mesage didn't parse as contact info.\n");
// #endif
//               return false;
//             }
//             // TODO(Richard): return the message to be handled in Contacts
//             // return choice to the user to accept/reject contact
//             // 1. Add to my contacts & authorised users
//             // 2. Send a response with my details to the contacter
//             break;
//         // case packethandler::ADD_CONTACT_RESPONSE:
//         default: ;  // TODO define other type of messages
//       }
//     }
//   }
//   return true;
// }

void MessageHandler::IterativeStoreMsgs(
    boost::shared_ptr<SendMessagesData> data) {
  if (data->is_calledback) {
    return;
  }
  if (data->stores_done == static_cast<int>(data->receivers.size())) {
    packethandler::StoreMessagesResult result;
    if (data->successful_stores == 0)
      result.set_result(kCallbackFailure);
    else
      result.set_result(kCallbackSuccess);
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
//        case packethandler::SHARE:
//            sys_packet_name = co_.Hash(data->receivers[data->index].id,
//                                       "",
//                                       maidsafe_crypto::STRING_STRING,
//                                       true);
//            break;
        case packethandler::ADD_CONTACT_RQST:
//            sys_packet_name = co_.Hash(data->receivers[data->index].id,
//                                       "",
//                                       maidsafe_crypto::STRING_STRING,
//                                       true);
//            break;
//        case packethandler::ADD_CONTACT_RESPONSE:
//            sys_packet_name = co_.Hash(data->receivers[data->index].id,
//                                       "",
//                                       maidsafe_crypto::STRING_STRING,
//                                       true);
//            break;
//        case packethandler::GENERAL:
//            sys_packet_name = co_.Hash(data->receivers[data->index].id,
//                                       "",
//                                       maidsafe_crypto::STRING_STRING,
//                                       true);
//            break;
        case packethandler::INSTANT_MSG:
            sys_packet_name = co_.Hash(data->receivers[data->index].id,
                                       "",
                                       maidsafe_crypto::STRING_STRING,
                                       true);
            break;
        default : sys_packet_name = data->receivers[data->index].id;
      }
      ++data->active_sends;
      StoreMessage(data->index, data);
    }
  }
}

void MessageHandler::StoreMessage(
    int index,
    boost::shared_ptr<SendMessagesData> data) {
  if (data->is_calledback) {
    return;
  }
  std::string ser_msg = CreateMessage(data->msg,
                                      data->receivers[index].public_key,
                                      data->m_type,
                                      data->p_type);
  std::string bufferpacketname = co_.Hash(data->receivers[index].id+"BUFFER",
                                          "",
                                          maidsafe_crypto::STRING_STRING,
                                          true);
#ifdef DEBUG
  // printf("\nBufferpacket name (Saving):\n%s\n\n", bufferpacketname.c_str());
#endif
  std::string signed_public_key, signed_request;
  CreateSignature(bufferpacketname,
                  data->p_type,
                  &signed_request,
                  &signed_public_key);
  sm_->StorePacket(bufferpacketname,
                   ser_msg,
                   signed_request,
                   ss_->GetPublicKey(data->p_type),
                   signed_public_key,
                   BUFFER_PACKET_MESSAGE,
                   true,
                   boost::bind(&MessageHandler::StoreMessage_Callback,
                               this,
                               _1,
                               index,
                               data));
}

void MessageHandler::StoreMessage_Callback(
    const std::string &result,
    int index,
    boost::shared_ptr<SendMessagesData> data) {
  if (data->is_calledback) {
    return;
  }
  UpdateResponse result_msg;
  if ((result_msg.ParseFromString(result)) &&
      (result_msg.result() == kCallbackSuccess)) {
    ++data->successful_stores;
  } else {
    data->no_auth_rec.push_back(data->receivers[index].id);
  }
  --data->active_sends;
  ++data->stores_done;
  IterativeStoreMsgs(data);
}

}  //  namespace maidsafe
