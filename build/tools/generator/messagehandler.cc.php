<?= PrintHeader('Class for processing RPC messages.') ?>

#include "maidsafe/common/messagehandler.h"

<?php foreach ($groups as $name => $funcs): ?>
#include "maidsafe/common/<?= CamelConv($name) ?>_messages.pb.h"
<?php endforeach; ?>

namespace maidsafe {

enum MessageType {
<?php $i = 0; foreach ($groups as $name => $funcs): ?>
  // <?= $name ?> message types
<?php foreach ($funcs as $func): ?>
  k<?= $func ?>Request<?= $i == 0 ? ' = kademlia::kMaxMessageType + 1' : '' ?>,
  k<?= $func ?>Response<?= $i == $func_count - 1 ? '' : ',' ?>

<?php ++$i; endforeach; endforeach; ?>
};

<?php foreach ($groups as $name => $funcs): ?>
<?php foreach ($funcs as $func): ?>
std::string MessageHandler::WrapMessage(<?= strlen($func) > 9 ? "\n    " : '' ?>const protobuf::<?= $func ?>Request &msg) {
  return MakeSerialisedWrapperMessage(k<?= $func ?>Request,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(<?= strlen($func) > 8 ? "\n    " : '' ?>const protobuf::<?= $func ?>Response &msg) {
  return MakeSerialisedWrapperMessage(k<?= $func ?>Response,
                                      msg.SerializeAsString());
}

<?php endforeach; endforeach; ?>
void MessageHandler::ProcessSerialisedMessage(const int& message_type,
                                              const std::string& payload,
                                              const transport::Info& info,
                                              std::string* response,
                                              transport::Timeout* timeout) {
  response->clear();
  *timeout = transport::kImmediateTimeout;

  switch (message_type) {
<?php foreach ($groups as $name => $funcs): ?>
<?php foreach ($funcs as $func): ?>
    case k<?= $func ?>Request: {
      protobuf::<?= $func ?>Request in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::<?= $func ?>Response out_msg;
        (*on_<?= CamelConv($func) ?>_request_)(info, in_msg, &out_msg);
        if (!(*response = WrapMessage(out_msg)).empty())
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case k<?= $func ?>Response: {
      protobuf::<?= $func ?>Response in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized())
        (*on_<?= CamelConv($func) ?>_response_)(in_msg);
      break;
    }

<?php endforeach; endforeach; ?>
    default:
      transport::MessageHandler::ProcessSerialisedMessage(message_type, payload,
                                                          info, response,
                                                          timeout);
  }
}

}  // namespace maidsafe
