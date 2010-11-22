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

#include "maidsafe/common/clientbufferpackethandler.h"
#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/kadops.h"
#include "maidsafe/common/bufferpacketrpc.h"


namespace maidsafe {

void ClientBufferPacketHandler::CreateBufferPacket(
    const BPInputParameters &args, bp_operations_cb cb,
    const boost::int16_t &transport_id) {
  BufferPacket buffer_packet;
  GenericPacket *ser_owner_info = buffer_packet.add_owner_info();
  BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(args.kPublicUsername);
  buffer_packet_info.set_owner_publickey(args.kMpidPublicKey);
  ser_owner_info->set_data(buffer_packet_info.SerializeAsString());
  ser_owner_info->set_signature(
      RSASign(ser_owner_info->data(), args.kMpidPrivateKey));

  boost::shared_ptr<ChangeBPData> data(new ChangeBPData);
  data->cb = cb;
  data->create_request.set_bufferpacket_name(
      SHA512String(args.kPublicUsername + args.kMpidPublicKey));

  data->create_request.set_data(buffer_packet.SerializePartialAsString());
  data->create_request.set_pmid(args.kPublicUsername);
  data->create_request.set_public_key(args.kMpidPublicKey);
  data->create_request.set_signed_public_key(
      RSASign(args.kMpidPublicKey, args.kMpidPrivateKey));
  data->create_request.set_signed_request(RSASign(SHA512String(
      args.kMpidPublicKey + data->create_request.signed_public_key() +
      data->create_request.bufferpacket_name()), args.kMpidPrivateKey));

  FindNodes(boost::bind(&ClientBufferPacketHandler::FindNodesCallback,
            this, _1, _2, data, transport_id), data);
}

void ClientBufferPacketHandler::ModifyOwnerInfo(
    const BPInputParameters &args, const std::vector<std::string> &users,
    bp_operations_cb cb, const boost::int16_t &transport_id) {
  boost::shared_ptr<ChangeBPData> data(new ChangeBPData);
  BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(args.kPublicUsername);
  buffer_packet_info.set_owner_publickey(args.kMpidPublicKey);
  for (unsigned int i = 0; i < users.size(); ++i)
    buffer_packet_info.add_users(users.at(i));

  GenericPacket ser_owner_info;
  ser_owner_info.set_data(buffer_packet_info.SerializeAsString());
  ser_owner_info.set_signature(
      RSASign(ser_owner_info.data(), args.kMpidPrivateKey));

  data->modify_request.set_data(ser_owner_info.SerializeAsString());
  data->modify_request.set_bufferpacket_name(
      SHA512String(args.kPublicUsername + args.kMpidPublicKey));
  data->modify_request.set_pmid(args.kPublicUsername);
  data->modify_request.set_public_key(args.kMpidPublicKey);
  data->modify_request.set_signed_public_key(
      RSASign(args.kMpidPublicKey, args.kMpidPrivateKey));
  data->modify_request.set_signed_request(RSASign(SHA512String(
      args.kMpidPublicKey + data->modify_request.signed_public_key() +
      data->modify_request.bufferpacket_name()), args.kMpidPrivateKey));

  data->cb = cb;
  data->type = MODIFY_INFO;
  FindNodes(boost::bind(&ClientBufferPacketHandler::FindNodesCallback,
            this, _1, _2, data, transport_id), data);
}

void ClientBufferPacketHandler::GetMessages(
    const BPInputParameters &args, bp_getmessages_cb cb,
    const boost::int16_t &transport_id) {
  boost::shared_ptr<ChangeBPData> data(new ChangeBPData);
  std::string bpname(SHA512String(args.kPublicUsername + args.kMpidPublicKey));
  data->get_msgs_request.set_bufferpacket_name(bpname);
  data->get_msgs_request.set_public_key(args.kMpidPublicKey);
  data->get_msgs_request.set_pmid(args.kPublicUsername);
  std::string pubkey_signature(RSASign(args.kMpidPublicKey,
                                       args.kMpidPrivateKey));
  data->get_msgs_request.set_signed_public_key(pubkey_signature);
  std::string req_signature(RSASign(SHA512String(
      args.kMpidPublicKey + pubkey_signature + bpname), args.kMpidPrivateKey));
  data->get_msgs_request.set_signed_request(req_signature);

  data->cb_getmsgs = cb;
  data->type = GET_MESSAGES;
  data->private_key = args.kMpidPrivateKey;
  FindNodes(boost::bind(&ClientBufferPacketHandler::FindNodesCallback,
            this, _1, _2, data, transport_id), data);
}

void ClientBufferPacketHandler::AddMessage(
    const BPInputParameters &args, const std::string &my_pu,
    const std::string &recver_public_key, const std::string &receiver_id,
    const std::string &message, const MessageType &m_type,
    bp_operations_cb cb, const boost::int16_t &transport_id) {
  boost::shared_ptr<ChangeBPData> data(new ChangeBPData);

  BufferPacketMessage bpmsg;
  bpmsg.set_sender_id(my_pu);
  bpmsg.set_sender_public_key(args.kMpidPublicKey);
  bpmsg.set_type(m_type);
  bpmsg.set_timestamp(base::GetEpochTime());
  // generating key to encrypt msg with AES
  std::string aes_key =
      base::RandomString(crypto::AES256_KeySize + crypto::AES256_IVSize);
  bpmsg.set_aesenc_message(AESEncrypt(message, aes_key));
  // encrypting key with receivers public key
  bpmsg.set_rsaenc_key(RSAEncrypt(aes_key, recver_public_key));

  GenericPacket ser_bpmsg;
  ser_bpmsg.set_data(bpmsg.SerializeAsString());
  ser_bpmsg.set_signature(RSASign(ser_bpmsg.data(), args.kMpidPrivateKey));

  data->add_msg_request.set_data(ser_bpmsg.SerializeAsString());

  data->add_msg_request.set_bufferpacket_name(
      SHA512String(receiver_id + recver_public_key));
  data->add_msg_request.set_pmid(args.kPublicUsername);
  data->add_msg_request.set_public_key(args.kMpidPublicKey);
  data->add_msg_request.set_signed_public_key(
      RSASign(args.kMpidPublicKey, args.kMpidPrivateKey));
  data->add_msg_request.set_signed_request(RSASign(SHA512String(
      args.kMpidPublicKey + data->add_msg_request.signed_public_key() +
      data->add_msg_request.bufferpacket_name()), args.kMpidPrivateKey));

  data->cb = cb;
  data->type = ADD_MESSAGE;
  FindNodes(boost::bind(&ClientBufferPacketHandler::FindNodesCallback,
            this, _1, _2, data, transport_id), data);
}

void ClientBufferPacketHandler::GetPresence(
    const BPInputParameters &args, bp_getpresence_cb cb,
    const boost::int16_t &transport_id) {
  boost::shared_ptr<ChangeBPData> data(new ChangeBPData);
  std::string bpname(SHA512String(args.kPublicUsername + args.kMpidPublicKey));
  data->get_presence_request.set_bufferpacket_name(bpname);
  data->get_presence_request.set_public_key(args.kMpidPublicKey);
  data->get_presence_request.set_pmid(args.kPublicUsername);
  std::string pubkey_signature(RSASign(args.kMpidPublicKey,
                                       args.kMpidPrivateKey));
  data->get_presence_request.set_signed_public_key(pubkey_signature);
  std::string req_signature(RSASign(SHA512String(args.kMpidPublicKey +
      pubkey_signature + bpname), args.kMpidPrivateKey));
  data->get_presence_request.set_signed_request(req_signature);

  data->cb_getpresence = cb;
  data->type = GET_PRESENCE;
  data->private_key = args.kMpidPrivateKey;
  FindNodes(boost::bind(&ClientBufferPacketHandler::FindNodesCallback,
            this, _1, _2, data, transport_id), data);
}

void ClientBufferPacketHandler::AddPresence(
    const BPInputParameters &args, const std::string &my_pu,
    const std::string &recver_public_key, const std::string &receiver_id,
    bp_operations_cb cb, const boost::int16_t &transport_id) {
  boost::shared_ptr<ChangeBPData> data(new ChangeBPData);

  LivePresence lp;
  lp.set_contact_id(my_pu);
  EndPoint ep;
  kad_ops_->SetThisEndpoint(&ep);
  std::string s_ep(ep.SerializeAsString());
  lp.set_end_point(RSAEncrypt(s_ep, recver_public_key));

  GenericPacket ser_lp;
  ser_lp.set_data(lp.SerializeAsString());
  ser_lp.set_signature(RSASign(ser_lp.data(), args.kMpidPrivateKey));

  data->add_presence_request.set_data(ser_lp.SerializeAsString());
  std::string bpname(SHA512String(receiver_id + recver_public_key));
  data->add_presence_request.set_bufferpacket_name(bpname);
  data->add_presence_request.set_pmid(args.kPublicUsername);
  data->add_presence_request.set_public_key(args.kMpidPublicKey);
  std::string pubkey_sig(RSASign(args.kMpidPublicKey, args.kMpidPrivateKey));
  data->add_presence_request.set_signed_public_key(pubkey_sig);
  data->add_presence_request.set_signed_request(RSASign(SHA512String(
      args.kMpidPublicKey + pubkey_sig + bpname), args.kMpidPrivateKey));

  data->cb = cb;
  data->type = ADD_PRESENCE;
  FindNodes(boost::bind(&ClientBufferPacketHandler::FindNodesCallback,
            this, _1, _2, data, transport_id), data);
}

void ClientBufferPacketHandler::FindNodes(
    VoidFuncIntContacts cb, boost::shared_ptr<ChangeBPData> data) {
  switch (data->type) {
    case CREATEBP:
        kad_ops_->FindKClosestNodes(data->create_request.bufferpacket_name(),
                                    cb);
        break;
    case MODIFY_INFO:
        kad_ops_->FindKClosestNodes(data->modify_request.bufferpacket_name(),
                                    cb);
        break;
    case GET_MESSAGES:
        kad_ops_->FindKClosestNodes(data->get_msgs_request.bufferpacket_name(),
                                    cb);
        break;
    case ADD_MESSAGE:
        kad_ops_->FindKClosestNodes(data->add_msg_request.bufferpacket_name(),
                                    cb);
        break;
    case GET_PRESENCE:
        kad_ops_->FindKClosestNodes(
            data->get_presence_request.bufferpacket_name(), cb);
        break;
    case ADD_PRESENCE:
        kad_ops_->FindKClosestNodes(
            data->add_presence_request.bufferpacket_name(), cb);
        break;
  }
}

void ClientBufferPacketHandler::FindNodesCallback(
    const ReturnCode &result, const std::vector<kad::Contact> &closest_nodes,
    boost::shared_ptr<ChangeBPData> data, const boost::int16_t &transport_id) {
  if (result != kSuccess || closest_nodes.size() < kUpperThreshold_) {
    switch (data->type) {
      case CREATEBP: data->cb(kStoreNewBPError);
                     break;
      case MODIFY_INFO: data->cb(kModifyBPError);
                        break;
      case GET_MESSAGES: {
                           std::list<ValidatedBufferPacketMessage> msgs;
                           data->cb_getmsgs(kBPMessagesRetrievalError,
                                            msgs, true);
                           break;
                         }
      case ADD_MESSAGE: data->cb(kBPAddMessageError);
                        break;
      case GET_PRESENCE: {
                           std::list<std::string> lps;
                           data->cb_getpresence(kBPGetPresenceError,
                                                lps, true);
                           break;
                         }
      case ADD_PRESENCE: data->cb(kBPAddPresenceError);
                         break;
    }
    return;
  }

  boost::shared_ptr<std::vector<ModifyBPCallbackData> >
      cb_datas(new std::vector<ModifyBPCallbackData>);
  for (size_t n = 0; n < closest_nodes.size(); ++n) {
    ModifyBPCallbackData cb_data;
    cb_data.data = data;
    cb_data.transport_id = transport_id;
    cb_data.ctrl = new rpcprotocol::Controller;
    cb_data.ctc = closest_nodes.at(n);

    switch (cb_data.data->type) {
      case CREATEBP:
          cb_data.create_response = new CreateBPResponse;
          break;
      case MODIFY_INFO:
          cb_data.modify_response = new ModifyBPInfoResponse;
          break;
      case GET_MESSAGES:
          cb_data.get_msgs_response = new GetBPMessagesResponse;
          break;
      case ADD_MESSAGE:
          cb_data.add_msg_response = new AddBPMessageResponse;
          break;
      case GET_PRESENCE:
          cb_data.get_presence_response = new GetBPPresenceResponse;
          break;
      case ADD_PRESENCE:
          cb_data.add_presence_response = new AddBPPresenceResponse;
          break;
    }
    cb_datas->push_back(cb_data);
  }

  if (cb_datas->size() < kUpperThreshold_) {
    switch (data->type) {
      case CREATEBP: data->cb(kStoreNewBPError);
                   break;
      case MODIFY_INFO: data->cb(kModifyBPError);
                        break;
      case GET_MESSAGES: {
                           std::list<ValidatedBufferPacketMessage> msgs;
                           data->cb_getmsgs(kBPMessagesRetrievalError,
                                            msgs, true);
                           break;
                         }
      case ADD_MESSAGE: data->cb(kBPAddMessageError);
                        break;
      case GET_PRESENCE: {
                           std::list<std::string> lps;
                           data->cb_getpresence(kBPGetPresenceError,
                                                lps, true);
                           break;
                         }
      case ADD_PRESENCE: data->cb(kBPAddPresenceError);
                         break;
    }
    return;
  }

  for (size_t a = 0; a < cb_datas->size(); ++a) {
    bool local = kad_ops_->AddressIsLocal(cb_datas->at(a).ctc);

    google::protobuf::Closure *done = NULL;
    switch (data->type) {
      case CREATEBP:
        done = google::protobuf::NewCallback(this,
               &ClientBufferPacketHandler::ActionOnBpDone, cb_datas,
               boost::int16_t(a));
        rpcs_->CreateBP(cb_datas->at(a).ctc, local,
                        cb_datas->at(a).transport_id,
                        &data->create_request, cb_datas->at(a).create_response,
                        cb_datas->at(a).ctrl, done);
        break;
      case MODIFY_INFO:
        done = google::protobuf::NewCallback(this,
               &ClientBufferPacketHandler::ActionOnBpDone, cb_datas,
               boost::int16_t(a));
        rpcs_->ModifyBPInfo(cb_datas->at(a).ctc, local,
                            cb_datas->at(a).transport_id,
                            &data->modify_request,
                            cb_datas->at(a).modify_response,
                            cb_datas->at(a).ctrl, done);
        break;
      case GET_MESSAGES:
        done = google::protobuf::NewCallback(this,
               &ClientBufferPacketHandler::ActionOnBpDone, cb_datas,
               boost::int16_t(a));
        rpcs_->GetBPMessages(cb_datas->at(a).ctc, local,
                             cb_datas->at(a).transport_id,
                             &data->get_msgs_request,
                             cb_datas->at(a).get_msgs_response,
                             cb_datas->at(a).ctrl,
                             done);
        break;
      case ADD_MESSAGE:
        done = google::protobuf::NewCallback(this,
               &ClientBufferPacketHandler::ActionOnBpDone, cb_datas,
               boost::int16_t(a));
        rpcs_->AddBPMessage(cb_datas->at(a).ctc, local,
                            cb_datas->at(a).transport_id,
                            &data->add_msg_request,
                            cb_datas->at(a).add_msg_response,
                            cb_datas->at(a).ctrl,
                            done);
        break;
      case GET_PRESENCE:
        done = google::protobuf::NewCallback(this,
               &ClientBufferPacketHandler::ActionOnBpDone, cb_datas,
               boost::int16_t(a));
        rpcs_->GetBPPresence(cb_datas->at(a).ctc, local,
                             cb_datas->at(a).transport_id,
                             &data->get_presence_request,
                             cb_datas->at(a).get_presence_response,
                             cb_datas->at(a).ctrl,
                             done);
        break;
      case ADD_PRESENCE:
        done = google::protobuf::NewCallback(this,
               &ClientBufferPacketHandler::ActionOnBpDone, cb_datas,
               boost::int16_t(a));
        rpcs_->AddBPPresence(cb_datas->at(a).ctc, local,
                             cb_datas->at(a).transport_id,
                             &data->add_presence_request,
                             cb_datas->at(a).add_presence_response,
                             cb_datas->at(a).ctrl,
                             done);
        break;
    }
  }
}

void ClientBufferPacketHandler::ActionOnBpDone(
    boost::shared_ptr<std::vector<ModifyBPCallbackData> > cb_datas,
    boost::int16_t index) {
  cb_datas->at(index).is_calledback = true;
  // Reply of ModifyBPInfo Rpc
  if (cb_datas->at(index).ctrl != NULL) {
    if (!cb_datas->at(index).ctrl->Failed()) {
      switch (cb_datas->at(index).data->type) {
        case CREATEBP:
            if (cb_datas->at(index).create_response->IsInitialized() &&
                cb_datas->at(index).create_response->result() == kAck &&
                cb_datas->at(index).create_response->pmid_id() ==
                    cb_datas->at(index).ctc.node_id().String()) {
                  ++cb_datas->at(index).data->successful_ops;
                }
            delete cb_datas->at(index).create_response;
            break;
        case MODIFY_INFO:
            if (cb_datas->at(index).modify_response->IsInitialized() &&
                cb_datas->at(index).modify_response->result() == kAck &&
                cb_datas->at(index).modify_response->pmid_id() ==
                    cb_datas->at(index).ctc.node_id().String()) {
                  ++cb_datas->at(index).data->successful_ops;
                }
            delete cb_datas->at(index).modify_response;
            break;
        case GET_MESSAGES:
            if (cb_datas->at(index).get_msgs_response->IsInitialized() &&
                cb_datas->at(index).get_msgs_response->result() == kAck &&
                cb_datas->at(index).get_msgs_response->pmid_id() ==
                    cb_datas->at(index).ctc.node_id().String()) {
                  ++cb_datas->at(index).data->successful_ops;
                  std::list<ValidatedBufferPacketMessage> msgs =
                      ValidateMsgs(cb_datas->at(index).get_msgs_response,
                                   cb_datas->at(index).data->private_key);
                  cb_datas->at(index).data->cb_getmsgs(kSuccess, msgs, false);
                }
            delete cb_datas->at(index).get_msgs_response;
            break;
        case ADD_MESSAGE:
            if (cb_datas->at(index).add_msg_response->IsInitialized() &&
                cb_datas->at(index).add_msg_response->result() == kAck &&
                cb_datas->at(index).add_msg_response->pmid_id() ==
                    cb_datas->at(index).ctc.node_id().String()) {
                  ++cb_datas->at(index).data->successful_ops;
                }
            delete cb_datas->at(index).add_msg_response;
            break;
        case GET_PRESENCE:
            if (cb_datas->at(index).get_presence_response->IsInitialized() &&
                cb_datas->at(index).get_presence_response->result() == kAck &&
                cb_datas->at(index).get_presence_response->pmid_id() ==
                    cb_datas->at(index).ctc.node_id().String()) {
                  ++cb_datas->at(index).data->successful_ops;
                  std::list<std::string> lps;
                  GetBPPresenceResponse *response =
                      cb_datas->at(index).get_presence_response;
                  for (int n = 0; n < response->messages_size(); ++n)
                    lps.push_back(response->messages(n));
                  cb_datas->at(index).data->cb_getpresence(kSuccess, lps,
                                                           false);
                }
            delete cb_datas->at(index).get_msgs_response;
            break;
        case ADD_PRESENCE:
            if (cb_datas->at(index).add_presence_response->IsInitialized() &&
                cb_datas->at(index).add_presence_response->result() == kAck &&
                cb_datas->at(index).add_presence_response->pmid_id() ==
                    cb_datas->at(index).ctc.node_id().String()) {
                  ++cb_datas->at(index).data->successful_ops;
                }
            delete cb_datas->at(index).add_msg_response;
            break;
      }
    }
    delete cb_datas->at(index).ctrl;
  }

  bool finished(true);
  for (size_t n = 0; n < cb_datas->size(); ++n) {
    finished = finished && cb_datas->at(n).is_calledback;
    if (!finished)
      break;
  }

  if (finished) {
    switch (cb_datas->at(index).data->type) {
      case CREATEBP:
          if (cb_datas->at(index).data->successful_ops >= kUpperThreshold_)
            cb_datas->at(index).data->cb(kSuccess);
          else
            cb_datas->at(index).data->cb(kStoreNewBPError);
          break;
      case MODIFY_INFO:
          if (cb_datas->at(index).data->successful_ops >= kUpperThreshold_)
            cb_datas->at(index).data->cb(kSuccess);
          else
            cb_datas->at(index).data->cb(kModifyBPError);
          break;
      case GET_MESSAGES: {
          std::list<ValidatedBufferPacketMessage> msgs;
          if (cb_datas->at(index).data->successful_ops >= kUpperThreshold_)
            cb_datas->at(index).data->cb_getmsgs(kSuccess, msgs, true);
          else
            cb_datas->at(index).data->cb_getmsgs(kBPMessagesRetrievalError,
                                                 msgs, true);
          break;
      }
      case ADD_MESSAGE:
          if (cb_datas->at(index).data->successful_ops >= kUpperThreshold_)
            cb_datas->at(index).data->cb(kSuccess);
          else
            cb_datas->at(index).data->cb(kBPAddMessageError);
          break;
      case GET_PRESENCE: {
          std::list<std::string> lps;
          if (cb_datas->at(index).data->successful_ops >= kUpperThreshold_)
            cb_datas->at(index).data->cb_getpresence(kSuccess, lps, true);
          else
            cb_datas->at(index).data->cb_getpresence(kBPGetPresenceError,
                                                     lps, true);
          break;
      }
      case ADD_PRESENCE:
          if (cb_datas->at(index).data->successful_ops >= kUpperThreshold_)
            cb_datas->at(index).data->cb(kSuccess);
          else
            cb_datas->at(index).data->cb(kBPAddPresenceError);
          break;
    }
  }
}

std::list<ValidatedBufferPacketMessage> ClientBufferPacketHandler::ValidateMsgs(
    const GetBPMessagesResponse *response, const std::string &private_key) {
  std::list<ValidatedBufferPacketMessage> result;
  for (int i = 0; i < response->messages_size(); ++i) {
    ValidatedBufferPacketMessage msg;
    if (msg.ParseFromString(response->messages(i))) {
      std::string aes_key(RSADecrypt(msg.index(), private_key));
      msg.set_message(AESDecrypt(msg.message(), aes_key));
      msg.set_index("");
      result.push_back(msg);
    }
  }
  return result;
}

}  // namespace maidsafe
