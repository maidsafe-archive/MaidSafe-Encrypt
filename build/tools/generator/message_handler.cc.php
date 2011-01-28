<?= PrintHeader('Provides a class for processing messages.', $template, $filename) ?>

#include "maidsafe/common/message_handler.h"
<?php foreach ($groups as $name => $funcs): ?>
#include "maidsafe/common/<?= CamelConv($name) ?>_messages.pb.h"
<?php endforeach; ?>

namespace maidsafe {

enum MessageType {
<?php $i = 0; foreach ($groups as $name => $funcs): ?>
  // <?= $name ?> message types
<?php foreach ($funcs as $func => $desc): ?>
  k<?= $func ?>Request<?= $i == 0 ? ' = kademlia::kMaxMessageType + 1' : '' ?>,
  k<?= $func ?>Response<?= $i == $func_count - 1 ? '' : ',' ?>

<?php ++$i; endforeach; endforeach; ?>
};

<?php foreach ($groups as $name => $funcs): ?>
<?php foreach ($funcs as $func => $desc): ?>
/**
 * @brief Serialises and wraps a %<?= $func ?> request message.
 * @param msg The %<?= $func ?> request message.
 * @return Serialised %<?= $func ?> request.
 */
std::string MessageHandler::WrapMessage(<?= strlen($func) > 9 ? "\n    " : '' ?>const protobuf::<?= $func ?>Request &msg) {
  return MakeSerialisedWrapperMessage(k<?= $func ?>Request,
                                      msg.SerializeAsString(),
                                      kSign | kAsymmetricEncrypt);
}

/**
 * @brief Serialises and wraps a %<?= $func ?> response message.
 * @param msg The %<?= $func ?> response message.
 * @return Serialised %<?= $func ?> response.
 */
std::string MessageHandler::WrapMessage(<?= strlen($func) > 8 ? "\n    " : '' ?>const protobuf::<?= $func ?>Response &msg) {
  return MakeSerialisedWrapperMessage(k<?= $func ?>Response,
                                      msg.SerializeAsString(),
                                      kSign | kAsymmetricEncrypt);
}

<?php endforeach; endforeach; ?>
void MessageHandler::ProcessSerialisedMessage(
    const int &message_type,
    const std::string &payload,
    const std::string &message_signature,
    const transport::Info &info,
    bool asymmetrical_encrypted,
    std::string *response,
    transport::Timeout* timeout) {
  response->clear();
  *timeout = transport::kImmediateTimeout;

  switch (message_type) {
<?php foreach ($groups as $name => $funcs): ?>
<?php foreach ($funcs as $func => $desc): ?>
    case k<?= $func ?>Request: {
      if (!asymmetrical_encrypted || message_signature.empty())
        return;
      protobuf::<?= $func ?>Request in_msg;
      if (in_msg.ParseFromString(payload) && in_msg.IsInitialized()) {
        protobuf::<?= $func ?>Response out_msg;
        (*on_<?= CamelConv($func) ?>_request_)(info, message_signature, in_msg,
                                               &out_msg);
        *response = WrapMessage(out_msg);
      }
      break;
    }
    case k<?= $func ?>Response: {
      if (!asymmetrical_encrypted || message_signature.empty())
        return;
      protobuf::<?= $func ?>Response in_msg;
      if (in_msg.ParseFromString(payload))
        (*on_<?= CamelConv($func) ?>_response_)(info, message_signature, in_msg);
      break;
    }

<?php endforeach; endforeach; ?>
    default:
      kademlia::MessageHandler::ProcessSerialisedMessage(
          message_type, payload, message_signature, info,
          asymmetrical_encrypted, response, timeout);
  }
}

}  // namespace maidsafe
