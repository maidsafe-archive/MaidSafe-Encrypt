<?php

/**
 * This script generates the code for MessageHandler, RPCs and services.
 *
 * @warning Existing files will be overwritten!
 */

$common_dir = '../../src/maidsafe/common/';
$vault_dir = '../../src/maidsafe/vault/';
$docs_dir = '../../docs/';

$groups = array(
  'Chunk' => array(
    'ArrangeStore' => 'Negotiates a contract to store a chunk.',
    'StoreChunk' => 'Stores a chunk.',
    'GetChunk' => 'Retrieves a chunk.',
    'HasChunk' => 'Checks if a chunk is available.',
    'ValidateChunk' => 'Challenges a vault to prove storage of a chunk.',
    'DeleteChunk' => 'Triggers deletion of a chunk.',
    'DuplicateChunk' => 'Triggers duplication of a chunk.',
    'CacheChunk' => 'Triggers temporary storage of a chunk.'
  ),
  'ChunkInfo' => array(
    'AddToWatchList' => 'Registers interest in a chunk.',
    'RemoveFromWatchList' => 'Unregisters interest in a chunk.',
    'AddToReferenceList' => 'Registers a chunk holder.',
    'GetChunkReferences' => 'Retrieves a list of chunk holders.'
  ),
  'Account' => array(
    'AmendAccount' => 'Executes a transaction on an account.',
    'ExpectAmendment' => 'Advises of incoming transaction requests.',
    'AccountStatus' => 'Retrieves current balances in an account.'
  ),
  'VaultSync' => array(
    'GetSyncData' => 'Retrieves data for vault synchronisation.',
    'GetAccount' => 'Retrieves %Account data for vault synchronisation.',
    'GetChunkInfo' => 'Retrieves %ChunkInfo data for vault synchronisation.',
    'GetBuffer' => 'Retrieves %Buffer data for vault synchronisation.',
  ),
  'Buffer' => array(
    'CreateBuffer' => 'Creates a vault buffer.',
    'ModifyBufferInfo' => 'Changes data contents of a buffer.',
    'GetBufferMessages' => 'Retrieves messages from a buffer.',
    'AddBufferMessage' => 'Adds a message to a buffer.',
    'GetBufferPresence' => 'Retrieves presence data from a buffer.',
    'AddBufferPresence' => 'Adds presence data to a buffer.'
  )
);

$func_count = 0;
foreach ($groups as $name => $funcs)
  $func_count += count($funcs);

// Converts 'HelloWorld' to 'hello_world'
function CamelConv($str) {
  $segs = preg_split('/([A-Z][a-z]+)/', $str, -1, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
  $segs = array_map("strtolower", $segs);
  return implode('_', $segs);
}

function PrintHeader($desc, $template, $filename) {
?>
/**
 * @file  <?= $filename ?>

 * @brief <?= $desc ?>

 * @date  <?= date('Y-m-d') ?>

 *
 * <em>Copyright <?= date('Y') ?> maidsafe.net limited</em>
 *
 * The following source code is property of maidsafe.net limited and is not
 * meant for external use.  The use of this code is governed by the license
 * file LICENSE.TXT found in the root of this directory and also on
 * www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * the explicit written permission of the board of directors of maidsafe.net.
 *
 * @attention This source file was generated automatically!
 *            Until this notice is removed, make changes only to the template:
 *            @c build/tools/<?= $template ?>

 */
<?php
}

function GenExt($filename) {
  // TODO use a fancy regex replace here
  return str_replace('.h', '.gen.h', str_replace('.cc', '.gen.cc', $filename));
}

function GenerateFromTemplate($template, $outdir, $filename, $overwrite_existing = false) {
  global $func_count, $groups, $name, $funcs;
  ob_start();
  include $template;
  $buffer = ob_get_contents();
  ob_end_clean();
  if (!$overwrite_existing && file_exists($outdir . $filename))
    $filename = GenExt($filename);
  else if (file_exists($outdir . GenExt($filename)))
    unlink($outdir . GenExt($filename));
  file_put_contents($outdir . $filename, $buffer);
  print "Generated $filename (in $outdir)\n";
}

print "Generating code for $func_count service functions...\n";

// -----------------------------------------------------------------------------

GenerateFromTemplate('generator/messagehandler.h.php', $common_dir, 'messagehandler.h', true);
GenerateFromTemplate('generator/messagehandler.cc.php', $common_dir, 'messagehandler.cc', true);

foreach ($groups as $name => $funcs) {
  GenerateFromTemplate('generator/rpcs.h.php', $common_dir, strtolower($name) . 'rpcs.h');
  GenerateFromTemplate('generator/rpcs.cc.php', $common_dir, strtolower($name) . 'rpcs.cc');
  GenerateFromTemplate('generator/service.h.php', $vault_dir, strtolower($name) . 'service.h');
  GenerateFromTemplate('generator/service.cc.php', $vault_dir, strtolower($name) . 'service.cc');
}

GenerateFromTemplate('generator/tasks.csv.php', $docs_dir, 'tasks.csv', true);
GenerateFromTemplate('generator/rpcs.html.php', $docs_dir, 'rpcs.html', true);
