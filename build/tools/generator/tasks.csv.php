Story,Labels,Requested By,Description
<?php foreach ($groups as $name => $funcs): foreach ($funcs as $func => $desc): ?>
"Implement *<?= $func ?>* in <?= $name ?>Service",,"Steve Muecklisch","Service functionality: <?= str_replace('%', '', $desc) ?>"
"Test *<?= $func ?>* in <?= $name ?>Service","test","Steve Muecklisch",
"Implement *<?= $func ?>* in <?= $name ?>Rpcs",,"Steve Muecklisch","RPC functionality: <?= str_replace('%', '', $desc) ?>"
"Test *<?= $func ?>* in <?= $name ?>Rpcs","test","Steve Muecklisch",
<?php endforeach; endforeach; ?>