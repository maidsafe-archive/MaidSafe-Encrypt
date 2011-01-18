<?= PrintHeader("Class providing $name services.") ?>

#ifndef MAIDSAFE_COMMON_<?= strtoupper($name) ?>SERVICE_H_
#define MAIDSAFE_COMMON_<?= strtoupper($name) ?>SERVICE_H_

namespace transport {
class Info;
}

namespace maidsafe {

namespace protobuf {
<?php foreach ($funcs as $func): ?>
class <?= $func ?>Request;
class <?= $func ?>Response;
<?php endforeach; ?>
}  // namespace protobuf

namespace vault {

class <?= $name ?>Service {
 public:
  <?= $name ?>Service() {}
<?php foreach ($funcs as $func): ?>
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

#endif  // MAIDSAFE_COMMON_<?= strtoupper($name) ?>SERVICE_H_
