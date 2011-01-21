<html>
<head>
<style type="text/css">
<!--
  body { font-family: Sans-serif; }
  table { margin: 2px 2px 2px 1em; }
  h1 { font-family: Serif; font-size: 140%; text-align: center; }
  h2 { font-family: Serif; font-size: 120%; margin-bottom: 0; }
  th { font-family: Monospace; font-size: 120%; width: 15em; text-align: left; }
-->
</style>
</head>
<body>
<h1>Vault RPCs</h1>
<?php foreach ($groups as $name => $funcs): ?>
<h2><?= $name ?></h2>
<table border="0">
<?php foreach ($funcs as $func => $desc): ?>
  <tr>
    <th><?= $func ?></th>
    <td><?= str_replace('%', '', $desc) ?></td>
  </tr>
<?php endforeach; ?>
</table>
<?php endforeach; ?>
</body>
</html>