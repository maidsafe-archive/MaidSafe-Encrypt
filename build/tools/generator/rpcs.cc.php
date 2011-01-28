<?= PrintHeader("Provides a class for %$name RPCs.", $template, $filename) ?>

#include "maidsafe/common/<?= CamelConv($name) ?>_rpcs.h"
#include "maidsafe-dht/transport/udttransport.h"
#include "maidsafe/common/message_handler.h"
#include "maidsafe/common/<?= CamelConv($name) ?>_messages.pb.h"

namespace arg = std::placeholders;

namespace maidsafe {

<?php foreach ($funcs as $func => $desc): ?>
/**
 * Detailed description for <?= $func ?>...
 *
 * @param contact The remote node to call %<?= $func ?> on.
 * @param callback The function to be called with the operation's result.
 */
<?php $ind = str_repeat(' ', strlen($func) + strlen($name) + 12); ?>
void <?= $name ?>Rpcs::<?= $func ?>(const kademlia::Contact &contact,
<?= $ind . $func ?>Functor callback) {
  // set up transport & msg handler and connect signals
  std::shared_ptr<MessageHandler> message_handler(
      new MessageHandler(securifier_));
  std::shared_ptr<transport::Transport> transport(
      new transport::UdtTransport(asio_service_));
  transport->on_message_received()->connect(std::bind(
      &MessageHandler::OnMessageReceived, message_handler.get(),
      arg::_1, arg::_2, arg::_3, arg::_4));
  message_handler->on_<?= CamelConv($func) ?>_response()->connect(std::bind(
      &<?= $name ?>Rpcs::<?= $func ?>Callback, this, arg::_2,
      callback, transport::kSuccess, arg::_1, message_handler, transport));
  message_handler->on_error()->connect(std::bind(
      &<?= $name ?>Rpcs::<?= $func ?>Callback, this,
      protobuf::<?= $func ?>Response(), callback, arg::_1,
      transport::Info(), message_handler, transport));

  // assemble the request message
  protobuf::<?= $func ?>Request req;
  // TODO implement <?= $name ?>Rpcs::<?= $func ?> body

  transport->Send(message_handler->WrapMessage(req),
                  contact.GetPreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

void <?= $name ?>Rpcs::<?= $func ?>Callback(
    const protobuf::<?= $func ?>Response &response,
    <?= $func ?>Functor callback,
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    std::shared_ptr<MessageHandler> message_handler,
    std::shared_ptr<transport::Transport> transport) {
  int result = transport_condition;
  if (transport_condition == transport::kSuccess && response.IsInitialized()
      /* && response.result() */) {
    // TODO implement <?= $name ?>Rpcs::<?= $func ?>Callback body
  } else {
    result = -1;
  }
  if (callback)
    callback(info, result);
}

<?php endforeach; ?>

}  // namespace maidsafe
