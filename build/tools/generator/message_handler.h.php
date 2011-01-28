<?= PrintHeader('Provides a class for processing messages.', $template, $filename) ?>

#ifndef MAIDSAFE_COMMON_MESSAGE_HANDLER_H_
#define MAIDSAFE_COMMON_MESSAGE_HANDLER_H_

#include <functional>
#include <string>

#include "boost/signals2/signal.hpp"
#include "maidsafe-dht/transport/transport.h"
#include "maidsafe-dht/kademlia/message_handler.h"

namespace bs2 = boost::signals2;

namespace maidsafe {

class Securifier;

namespace protobuf {
<?php foreach ($groups as $name => $funcs): ?>
// <?= $name ?> messages
<?php foreach ($funcs as $func => $desc): ?>
class <?= $func ?>Request;
class <?= $func ?>Response;
<?php endforeach; endforeach; ?>
}  // namespace protobuf

/// Highest possible message type ID, used as offset for type extensions.
const int kMaxMessageType(kademlia::kMaxMessageType);

/**
 * @brief Handles message parsing and serialisation.
 *
 * This class can be used to serialise messages into a string via the
 * WrapMessage methods, which can then be send using a
 * @ref kademlia::Transport "Transport". It can also be connected to a
 * @ref kademlia::Transport "Transport" directly and then fire signals depending
 * on the respective message type.
 *
 * Optionally deals with message crypto and signatures.
 */
class MessageHandler : public kademlia::MessageHandler {
 public:
<?php foreach ($groups as $name => $funcs): ?>
<?php foreach ($funcs as $func => $desc): ?>
  /// %<?= $func ?> request signal pointer
  typedef std::shared_ptr<bs2::signal<void(const transport::Info&,     // NOLINT
      const std::string&, const protobuf::<?= $func ?>Request&,
      protobuf::<?= $func ?>Response*)>> <?= $func ?>ReqSigPtr;
  /// %<?= $func ?> response signal pointer
  typedef std::shared_ptr<bs2::signal<void(const transport::Info&,     // NOLINT
      const std::string&, const protobuf::<?= $func ?>Response&)>>
      <?= $func ?>RspSigPtr;
<?php endforeach; endforeach; ?>

  MessageHandler(std::shared_ptr<Securifier> securifier)
    : kademlia::MessageHandler(securifier),
<?php $i = 0; foreach ($groups as $name => $funcs): ?>
<?php foreach ($funcs as $func => $desc): ?>
      on_<?= CamelConv($func) ?>_request_(<?= strlen($func) > 15 ? "\n          " : '' ?>new <?= $func ?>ReqSigPtr::element_type),
      on_<?= CamelConv($func) ?>_response_(<?= strlen($func) > 15 ? "\n          " : '' ?>new <?= $func ?>RspSigPtr::element_type)<?= $i == $func_count - 1 ? ' {}' : ',' ?>

<?php ++$i; endforeach; endforeach; ?>
  virtual ~MessageHandler() {}

<?php foreach ($groups as $name => $funcs): ?>
<?php foreach ($funcs as $func => $desc): ?>
  std::string WrapMessage(const protobuf::<?= $func ?>Request &msg);
  std::string WrapMessage(const protobuf::<?= $func ?>Response &msg);
<?php endforeach; endforeach; ?>

<?php foreach ($groups as $name => $funcs): ?>
<?php foreach ($funcs as $func => $desc): ?>
  <?= $func ?>ReqSigPtr on_<?= CamelConv($func) ?>_request() {
    return on_<?= CamelConv($func) ?>_request_;
  }
  <?= $func ?>RspSigPtr on_<?= CamelConv($func) ?>_response() {
    return on_<?= CamelConv($func) ?>_response_;
  }
<?php endforeach; endforeach; ?>
 protected:
  virtual void ProcessSerialisedMessage(const int &message_type,
                                        const std::string &payload,
                                        const std::string &message_signature,
                                        const transport::Info &info,
                                        bool asymmetrical_encrypted,
                                        std::string *response,
                                        transport::Timeout *timeout);
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
<?php foreach ($groups as $name => $funcs): ?>
<?php foreach ($funcs as $func => $desc): ?>
  <?= $func ?>ReqSigPtr on_<?= CamelConv($func) ?>_request_;
  <?= $func ?>RspSigPtr on_<?= CamelConv($func) ?>_response_;
<?php endforeach; endforeach; ?>
};

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_MESSAGE_HANDLER_H_
