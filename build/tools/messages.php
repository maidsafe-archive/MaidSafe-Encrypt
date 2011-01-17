<?php

// this script generates the content for messagehandler.(h|cc)

$messages = array(
  'StoreChunk',
  'GetChunk',
  'HasChunk',
  'GetChunkReferences',
  'AddToWatchList',
  'RemoveFromWatchList',
  'AddToReferenceList',
  'AmendAccount',
  'ExpectAmendment',
  'AccountStatus',
  'GetSyncData',
  'GetAccount',
  'GetChunkInfo',
  'GetBuffer',
  'CreateBuffer',
  'ModifyBufferInfo',
  'GetBufferMessages',
  'AddBufferMessage',
  'GetBufferPresence',
  'AddBufferPresence');

function CamelConv($str) {
  $segs = preg_split('/([A-Z][a-z]+)/', $str, -1, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
  $segs = array_map("strtolower", $segs);
  return implode('_', $segs);
}

?>/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Description:  Class for processing RPC messages.
* Created:      2011-01-17
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

#ifndef MAIDSAFE_COMMON_MESSAGEHANDLER_H_
#define MAIDSAFE_COMMON_MESSAGEHANDLER_H_

#include <boost/shared_ptr.hpp>
#include <boost/function.hpp>
#include <boost/signals2/signal.hpp>
#include <maidsafe/kademlia/messagehandler.h>

#include <string>

namespace bs2 = boost::signals2;

namespace maidsafe {

namespace protobuf {
class StorePrepRequest;
class StorePrepResponse;
<?php foreach ($messages as $message): ?>
class <?= $message ?>Request;
class <?= $message ?>Response;
<?php endforeach; ?>
}  // namespace protobuf

// Highest possible message type ID, use as offset for type extensions.
const int kMaxMessageType(kademlia::kMaxMessageType);

class MessageHandler : public transport::MessageHandler {
 public:
<?php foreach ($messages as $message): ?>
  // <?= $message ?> signal pointers
  typedef boost::shared_ptr< bs2::signal< void(const transport::Info&,
      const protobuf::<?= $message ?>Request&,
      protobuf::<?= $message ?>Response*)> > <?= $message ?>ReqSigPtr;
  typedef boost::shared_ptr< bs2::signal< void(
      const protobuf::<?= $message ?>Response&)> ><?= strlen($message) > 17 ? "\n      " : ' ' ?><?= $message ?>RspSigPtr;
<?php endforeach; ?>

  MessageHandler()
<?php foreach ($messages as $message): ?>
    <?= $message == $messages[0] ? ':' : ' ' ?> on_<?= CamelConv($message) ?>_request_(<?= strlen($message) > 15 ? "\n          " : '' ?>new <?= $message ?>ReqSigPtr::element_type),
      on_<?= CamelConv($message) ?>_response_(<?= strlen($message) > 15 ? "\n          " : '' ?>new <?= $message ?>RspSigPtr::element_type)<?= $message == $messages[count($messages) - 1] ? ' {}' : ',' ?>

<?php endforeach; ?>
  virtual ~MessageHandler() {}

<?php foreach ($messages as $message): ?>
  std::string WrapMessage(const protobuf::<?= $message ?>Request &msg);
  std::string WrapMessage(const protobuf::<?= $message ?>Response &msg);
<?php endforeach; ?>

<?php foreach ($messages as $message): ?>
  <?= $message ?>ReqSigPtr on_<?= CamelConv($message) ?>_request() {
    return on_<?= CamelConv($message) ?>_request_;
  }
  <?= $message ?>RspSigPtr on_<?= CamelConv($message) ?>_response() {
    return on_<?= CamelConv($message) ?>_response_;
  }
<?php endforeach; ?>
 protected:
  virtual void ProcessSerialisedMessage(const int &message_type,
                                        const std::string &payload,
                                        const transport::Info &info,
                                        std::string *response,
                                        transport::Timeout *timeout);
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
<?php foreach ($messages as $message): ?>
  <?= $message ?>ReqSigPtr on_<?= CamelConv($message) ?>_request_;
  <?= $message ?>RspSigPtr on_<?= CamelConv($message) ?>_response_;
<?php endforeach; ?>
};

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_MESSAGEHANDLER_H_




/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Description:  Class for processing RPC messages.
* Created:      2011-01-17
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

#include "maidsafe/common/messagehandler.h"
// #include "maidsafe/common/XXX.pb.h"

namespace kademlia {

enum MessageType {
<?php foreach ($messages as $message): ?>
  k<?= $message ?>Request<?= $message == $messages[0] ? ' = kademlia::kMaxMessageType + 1' : '' ?>,
  k<?= $message ?>Response<?= $message == $messages[count($messages) - 1] ? '' : ',' ?>

<?php endforeach; ?>
};

<?php foreach ($messages as $message): ?>
std::string MessageHandler::WrapMessage(<?= strlen($message) > 9 ? "\n    " : '' ?>const protobuf::<?= $message ?>Request &msg) {
  return MakeSerialisedWrapperMessage(k<?= $message ?>Request,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(<?= strlen($message) > 8 ? "\n    " : '' ?>const protobuf::<?= $message ?>Response &msg) {
  return MakeSerialisedWrapperMessage(k<?= $message ?>Response,
                                      msg.SerializeAsString());
}

<?php endforeach; ?>
void MessageHandler::ProcessSerialisedMessage(const int& message_type,
                                              const std::string& payload,
                                              const transport::Info& info,
                                              std::string* response,
                                              transport::Timeout* timeout) {
  response->clear();
  *timeout = transport::kImmediateTimeout;

  switch (message_type) {
<?php foreach ($messages as $message): ?>
    case k<?= $message ?>Request: {
      protobuf::<?= $message ?>Request req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::<?= $message ?>Response rsp;
        (*on_<?= CamelConv($message) ?>_request_)(info, req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case k<?= $message ?>Response: {
      protobuf::<?= $message ?>Response req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_<?= CamelConv($message) ?>_response_)(req);
      break;
    }

<?php endforeach; ?>
    default:
      transport::MessageHandler::ProcessSerialisedMessage(message_type, payload,
                                                          info, response,
                                                          timeout);
  }
}

}  // namespace maidsafe
