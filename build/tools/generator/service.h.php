<?= PrintHeader("Provides a class for %$name services.", $template, $filename) ?>

#ifndef MAIDSAFE_VAULT_<?= strtoupper(CamelConv($name)) ?>_SERVICE_H_
#define MAIDSAFE_VAULT_<?= strtoupper(CamelConv($name)) ?>_SERVICE_H_

namespace transport { class Info; }

namespace maidsafe {

namespace protobuf {
<?php foreach ($funcs as $func => $desc): ?>
class <?= $func ?>Request;
class <?= $func ?>Response;
<?php endforeach; ?>
}  // namespace protobuf

namespace vault {

/**
 * @brief Provides %<?= $name ?> services to remote nodes.
 *
 * %<?= $name ?> services are used to...
 *
 * Incoming request messages are passed to the respective service method, where
 * they are processed. A response message is generated and sent on return of
 * the respective method. This process is blocking and keeps the connection
 * to the requester open, if applicable. Thus, complex tasks need to be handed
 * off to a worker thread, so they don't cause the connection to time-out.
 *
 * @see <?= $name ?>Rpcs
<?php foreach ($groups as $name_ => $funcs_): if ($name_ != $name): ?>
 * @see <?= $name_ ?>Service
<?php endif; endforeach; ?>
 */
class <?= $name ?>Service {
 public:
  <?= $name ?>Service() {}
<?php foreach ($funcs as $func => $desc): ?>
  /// <?= $desc ?>

  void <?= $func ?>(const transport::Info &info,
       <?= str_repeat(' ', strlen($func)) ?> const protobuf::<?= $func ?>Request &request,
       <?= str_repeat(' ', strlen($func)) ?> protobuf::<?= $func ?>Response *response);
<?php endforeach; ?>
  // TODO setters...
 private:
  <?= $name ?>Service(const <?= $name ?>Service&);
  <?= $name ?>Service& operator=(const <?= $name ?>Service&);
  // TODO private helper methods...
  // TODO private member variables...
};

}  // namespace vault

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_<?= strtoupper(CamelConv($name)) ?>_SERVICE_H_
