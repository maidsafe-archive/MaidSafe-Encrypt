<?= PrintHeader("Class providing $name RPCs.", $template) ?>

#include "maidsafe/common/<?= strtolower($name) ?>rpcs.h"

#include <maidsafe/transport/transport.h>
#include <maidsafe/transport/udttransport.h>
#include <maidsafe/kademlia/contact.h>

#include "maidsafe/common/messagehandler.h"
#include "maidsafe/common/<?= CamelConv($name) ?>_messages.pb.h"

namespace maidsafe {

<?php foreach ($funcs as $func): ?>
<?php $ind = str_repeat(' ', strlen($func) + strlen($name) + 12); ?>
void <?= $name ?>Rpcs::<?= $func ?>(const kademlia::Contact &contact,
<?= $ind . $func ?>Functor callback) {
  // set up transport & msg handler and connect signals
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<transport::Transport> transport =
      new transport::UdtTransport(asio_service_);
  transport->on_message_received()->connect(boost::bind(
      &MessageHandler::OnMessageReceived, message_handler.get(),
      _1, _2, _3, _4));
  message_handler->on_<?= CamelConv($func) ?>_response()->connect(boost::bind(
      &<?= $name ?>Rpcs::<?= $func ?>Callback, this, _1,
      callback, message_handler, transport));

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
    boost::shared_ptr<MessageHandler> message_handler,
    boost::shared_ptr<transport::Transport> transport) {
  // TODO implement <?= $name ?>Rpcs::<?= $func ?>Callback body
  // callback(response.result(), ...);
  callback(false);
}

<?php endforeach; ?>

}  // namespace maidsafe
