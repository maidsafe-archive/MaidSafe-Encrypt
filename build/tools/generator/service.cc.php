<?= PrintHeader("Provides a class for %$name services.", $template, $filename) ?>

#include "maidsafe/vault/<?= CamelConv($name) ?>_service.h"
#include "maidsafe/common/<?= CamelConv($name) ?>_messages.pb.h"

namespace maidsafe {

namespace vault {

<?php foreach ($funcs as $func => $desc): ?>
/**
 * Detailed description for <?= $func ?>...
 *
 * @param info Information about the message transfer.
 * @param request Message holding the arguments to the RPC.
 * @param response Pointer to the message holding the result of the RPC.
 */
<?php $ind = (2 * strlen($func) + strlen($name) > 32 ? 4 : strlen($func) + strlen($name) + 15); ?>
void <?= $name ?>Service::<?= $func ?>(<?= $ind == 4 ? "\n    " : '' ?>const transport::Info &info,
<?= str_repeat(' ', $ind) ?>const protobuf::<?= $func ?>Request &request,
<?= str_repeat(' ', $ind) ?>protobuf::<?= $func ?>Response *response) {
  // response->set_result(false);
  // TODO implement <?= $name ?>Service::<?= $func ?> body
}

<?php endforeach; ?>
}  // namespace vault

}  // namespace maidsafe
