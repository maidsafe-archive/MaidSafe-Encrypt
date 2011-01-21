<?= PrintHeader("Provides a class for %$name RPCs.", $template, $filename) ?>

#ifndef MAIDSAFE_COMMON_<?= strtoupper($name) ?>RPCS_H_
#define MAIDSAFE_COMMON_<?= strtoupper($name) ?>RPCS_H_

#include <boost/cstdint.hpp>
#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/asio/io_service.hpp>
#include <maidsafe/transport/transport.h>
#include <maidsafe/kademlia/contact.h>

namespace maidsafe {

class MessageHandler;

namespace protobuf {
<?php foreach ($funcs as $func => $desc): ?>
class <?= $func ?>Response;
<?php endforeach; ?>
}  // namespace protobuf

<?php foreach ($funcs as $func => $desc): ?>
/// Callback executed by <?= $func ?>Callback
typedef boost::function<void(bool)> <?= $func ?>Functor;
<?php endforeach; ?>

/**
 * @brief Abstracts functionality to call remote %<?= $name ?> services.
 *
 * %<?= $name ?> services are used to...
 *
 * Each RPC method creates a @ref kademlia::Transport "Transport" and a
 * MessageHandler object. The request message is compiled based on the passed
 * arguments, serialised with the MessageHandler and then sent to the node
 * providing the @ref vault::<?= $name ?>Service "<?= $name ?>Service".
 *
 * On receipt of the response message, the @ref kademlia::Transport "Transport"
 * passes it to the MessageHandler, where it is parsed and passed to the
 * appropriate RPC callback method. There the results are analysed and passed to
 * the initially provided callback, if available.
 *
 * @msc
 *   Client, <?= $name ?>Rpcs, MessageHandler, Transport, Service;
 *   Client => <?= $name ?>Rpcs [label = "RPC params"];
 *   <?= $name ?>Rpcs => MessageHandler [label = "WrapMessage()"];
 *   <?= $name ?>Rpcs << MessageHandler [label = "message string"];
 *   <?= $name ?>Rpcs => Transport [label = "Send()"];
 *   <?= $name ?>Rpcs << Transport;
 *   Client << <?= $name ?>Rpcs;
 *   Transport -> Service [label = "request"];
 *   ...;
 *   Transport <- Service [label = "response"];
 *   MessageHandler <<= Transport [label = "OnMessageReceived()"];
 *   <?= $name ?>Rpcs <<= MessageHandler [label = "RPC callback"];
 *   Client <<= <?= $name ?>Rpcs [label="results"];
 * @endmsc
 *
 * @see vault::<?= $name ?>Service
<?php foreach ($groups as $name_ => $funcs_): if ($name_ != $name): ?>
 * @see <?= $name_ ?>Rpcs
<?php endif; endforeach; ?>
 */
class <?= $name ?>Rpcs {
 public:
  <?= $name ?>Rpcs(boost::shared_ptr<boost::asio::io_service> asio_service)
    : asio_service_(asio_service) {}
<?php foreach ($funcs as $func => $desc): ?>
  /// <?= $desc ?>

  void <?= $func ?>(const kademlia::Contact &contact,
       <?= str_repeat(' ', strlen($func)) ?> /* TODO add data args */
       <?= str_repeat(' ', strlen($func)) ?> <?= $func ?>Functor callback);
<?php endforeach; ?>
  // TODO setters...
 private:
  <?= $name ?>Rpcs(const <?= $name ?>Rpcs&);
  <?= $name ?>Rpcs& operator=(const <?= $name ?>Rpcs&);
<?php foreach ($funcs as $func => $desc): ?>
  void <?= $func ?>Callback(
      const protobuf::<?= $func ?>Response &response,
      <?= $func ?>Functor callback,
      boost::shared_ptr<MessageHandler> message_handler,
      boost::shared_ptr<transport::Transport> transport);
<?php endforeach; ?>
  // TODO private helper methods...
  boost::shared_ptr<boost::asio::io_service> asio_service_;
  // TODO private member variables...
};

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_<?= strtoupper($name) ?>RPCS_H_
