<?= PrintHeader("Class providing $name services.") ?>

#include "maidsafe/vault/<?= strtolower($name) ?>service.h"

#include "maidsafe/common/<?= CamelConv($name) ?>_messages.pb.h"

namespace maidsafe {

namespace vault {

<?php foreach ($funcs as $func): ?>
<?php $ind = (2 * strlen($func) + strlen($name) > 32 ? 4 : strlen($func) + strlen($name) + 15); ?>
void <?= $name ?>Service::<?= $func ?>(<?= $ind == 4 ? "\n    " : '' ?>const transport::Info &info,
<?= str_repeat(' ', $ind) ?>const protobuf::<?= $func ?>Request &request,
<?= str_repeat(' ', $ind) ?>protobuf::<?= $func ?>Response *response) {
  // response->set_result(false);
  // TODO implement <?= $name ?>Service::<?= $func ?> body
}

<?php endforeach; ?>
}

}  // namespace maidsafe
