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

#ifndef MAIDSAFE_CLIENTBUFFERPACKETHANDLER_H_
#define MAIDSAFE_CLIENTBUFFERPACKETHANDLER_H_

#include <boost/thread/mutex.hpp>
#include <boost/cstdint.hpp>
#include <maidsafe/crypto.h>

#include <list>
#include <vector>
#include <string>

#include "maidsafe/maidsafe.h"
#include "maidsafe/bufferpacketrpc.h"
#include "protobuf/packet.pb.h"

namespace maidsafe {

typedef boost::function<void(const ReturnCode&)> bp_operations_cb;
typedef boost::function<void(const ReturnCode&,
  const std::list<ValidatedBufferPacketMessage>&)> bp_getmessages_cb;
typedef boost::function<void(const ReturnCode&, const EndPoint&,
  const boost::uint32_t&)> bp_getcontactinfo_cb;

enum BpOpType {MODIFY_INFO, ADD_MESSAGE, GET_MESSAGES, GET_INFO};

struct CreateBPData {
  CreateBPData() : request(), exclude_ctcs(), successful_stores(0),
    is_calledback(false), cb(0) {}
  CreateBPRequest request;
  std::vector<kad::Contact> exclude_ctcs;
  boost::uint16_t successful_stores;
  bool is_calledback;
  bp_operations_cb cb;
};

struct ChangeBPData {
  ChangeBPData() : modify_request(), add_msg_request(), get_msgs_request(),
    holder_ids(), successful_ops(0), idx(0), is_calledback(false), type(),
    cb(0), cb_getmsgs(0), private_key("") {}
  ModifyBPInfoRequest modify_request;
  AddBPMessageRequest add_msg_request;
  GetBPMessagesRequest get_msgs_request;
  ContactInfoRequest contactinfo_request;
  std::vector<std::string> holder_ids;
  boost::uint16_t successful_ops, idx;
  bool is_calledback;
  BpOpType type;
  bp_operations_cb cb;
  bp_getmessages_cb cb_getmsgs;
  bp_getcontactinfo_cb cb_getinfo;
  std::string private_key;
};

struct CreateBPCallbackData {
  rpcprotocol::Controller *ctrl;
  kad::Contact ctc;
  boost::shared_ptr<CreateBPData> data;
};

struct ModifyBPCallbackData {
  ModifyBPCallbackData()
    : ctrl(NULL), modify_response(NULL),
      add_msg_response(NULL), get_msgs_response(NULL),
      contactinfo_response(NULL), ctc(), data() {}
  rpcprotocol::Controller *ctrl;
  ModifyBPInfoResponse *modify_response;
  AddBPMessageResponse *add_msg_response;
  GetBPMessagesResponse *get_msgs_response;
  ContactInfoResponse *contactinfo_response;
  kad::Contact ctc;
  boost::shared_ptr<ChangeBPData> data;
};

struct BPInputParameters {
  std::string sign_id, public_key, private_key;
};

class ClientBufferPacketHandler {
  static const boost::uint16_t kParallelStores = 1;
  static const boost::uint16_t kParallelFindCtcs = 1;
 public:
  ClientBufferPacketHandler(boost::shared_ptr<maidsafe::BufferPacketRpcs> rpcs,
    boost::shared_ptr<kad::KNode> knode);
  virtual ~ClientBufferPacketHandler() {}
  void CreateBufferPacket(const BPInputParameters &args, bp_operations_cb cb);
  void ModifyOwnerInfo(const BPInputParameters &args, const int &status,
    const std::vector<std::string> &users, bp_operations_cb cb);
  void GetMessages(const BPInputParameters &args, bp_getmessages_cb cb);
  void AddMessage(const BPInputParameters &args, const std::string &my_pu,
    const std::string &recver_public_key, const std::string &receiver_id,
    const std::string &message, const MessageType &m_type, bp_operations_cb cb);
  void ContactInfo(const BPInputParameters &my_signing_credentials,
                   const std::string &my_pu,
                   const std::string &recs_pu,
                   const std::string &recs_pk,
                   bp_getcontactinfo_cb cicb);
 private:
  void IterativeStore(boost::shared_ptr<CreateBPData> data);
  void CreateBPCallback(const CreateBPResponse* resp,
    CreateBPCallbackData cb_data);
  virtual void FindReferences(base::callback_func_type cb,
    boost::shared_ptr<ChangeBPData> data);
  void FindReferences_CB(const std::string &result,
    boost::shared_ptr<ChangeBPData> data);
  void IterativeFindContacts(ModifyBPCallbackData data);
  virtual void FindRemoteContact(base::callback_func_type cb,
    boost::shared_ptr<ChangeBPData> data, const int &idx);
  void FindRemoteContact_CB(const std::string &result,
    boost::shared_ptr<ChangeBPData> data);
  std::list<ValidatedBufferPacketMessage> ValidateMsgs(const
    GetBPMessagesResponse *response, const std::string &private_key);
  ClientBufferPacketHandler &operator=(const ClientBufferPacketHandler);
  ClientBufferPacketHandler(const ClientBufferPacketHandler&);
  crypto::Crypto crypto_obj_;
  boost::shared_ptr<maidsafe::BufferPacketRpcs> rpcs_;
  boost::shared_ptr<kad::KNode> knode_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENTBUFFERPACKETHANDLER_H_
