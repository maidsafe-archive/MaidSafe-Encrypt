<?= PrintHeader("Class providing $name RPCs.", $template) ?>

#ifndef MAIDSAFE_COMMON_<?= strtoupper($name) ?>RPCS_H_
#define MAIDSAFE_COMMON_<?= strtoupper($name) ?>RPCS_H_

#include <boost/cstdint.hpp>
#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/asio/io_service.hpp>

namespace transport {
class Transport;
}  // namespace transport

namespace kademlia {
class Contact;
}  // namespace kademlia

namespace maidsafe {

namespace protobuf {
<?php foreach ($funcs as $func): ?>
class <?= $func ?>Response;
<?php endforeach; ?>
}  // namespace protobuf

<?php foreach ($funcs as $func): ?>
typedef boost::function<void(bool)> <?= $func ?>Functor;
<?php endforeach; ?>

class <?= $name ?>Rpcs {
 public:
  <?= $name ?>Rpcs(boost::shared_ptr<boost::asio::io_service> asio_service)
    : asio_service_(asio_service) {}
<?php foreach ($funcs as $func): ?>
  void <?= $func ?>(const kademlia::Contact &contact,
       <?= str_repeat(' ', strlen($func)) ?> /* TODO add data args */
       <?= str_repeat(' ', strlen($func)) ?> <?= $func ?>Functor callback);
<?php endforeach; ?>
  // TODO setters...
 private:
  <?= $name ?>Rpcs(const <?= $name ?>Rpcs&);
  <?= $name ?>Rpcs& operator=(const <?= $name ?>Rpcs&);
<?php foreach ($funcs as $func): ?>
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
