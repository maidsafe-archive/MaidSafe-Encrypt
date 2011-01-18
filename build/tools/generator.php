<?php

/**
 * This script generates the code for MessageHandler, RPCs and services.
 *
 * NOTE existing files will be overwritten!
 */

$groups = array(
  'Chunk' => array(
    'ArrangeStore',
    'StoreChunk',
    'GetChunk',
    'HasChunk',
    'ValidateChunk',
    'DeleteChunk',
    'DuplicateChunk',
    'CacheChunk'
  ),
  'ChunkInfo' => array(
    'AddToWatchList',
    'RemoveFromWatchList',
    'AddToReferenceList',
    'GetChunkReferences'
  ),
  'Account' => array(
    'AmendAccount',
    'ExpectAmendment',
    'AccountStatus'
  ),
  'VaultSync' => array(
    'GetSyncData',
    'GetAccount',
    'GetChunkInfo',
    'GetBuffer'
  ),
  'Buffer' => array(
    'CreateBuffer',
    'ModifyBufferInfo',
    'GetBufferMessages',
    'AddBufferMessage',
    'GetBufferPresence',
    'AddBufferPresence'
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

function PrintHeader($desc) {
  print "/*\n"
      . "* ============================================================================\n"
      . "*\n"
      . "* Copyright [2011] maidsafe.net limited\n"
      . "*\n"
      . "* Description:  $desc\n"
      . "* Created:      " . date("Y-m-d") . "\n"
      . "* Company:      maidsafe.net limited\n"
      . "*\n"
      . "* The following source code is property of maidsafe.net limited and is not\n"
      . "* meant for external use.  The use of this code is governed by the license\n"
      . "* file LICENSE.TXT found in the root of this directory and also on\n"
      . "* www.maidsafe.net.\n"
      . "*\n"
      . "* You are not free to copy, amend or otherwise use this source code without\n"
      . "* the explicit written permission of the board of directors of maidsafe.net.\n"
      . "*\n"
      . "* ============================================================================\n"
      ."*/\n";
}

function GenerateFromTemplate($template, $outpath) {
  global $func_count, $groups, $name, $funcs;
  ob_start();
  include $template;
  $buffer = ob_get_contents();
  ob_end_clean();
  file_put_contents($outpath, $buffer);
  print "Generated $outpath\n";
}

print "Generating code for $func_count service functions...\n";

// -----------------------------------------------------------------------------

GenerateFromTemplate('generator/messagehandler.h.php',
                     '../../src/maidsafe/common/messagehandler.h');
GenerateFromTemplate('generator/messagehandler.cc.php',
                     '../../src/maidsafe/common/messagehandler.cc');

foreach ($groups as $name => $funcs) {
//   GenerateFromTemplate('generator/rpc.h.php',
//                        '../../src/maidsafe/common/' . strtolower($name) . 'rpc.h');
//   GenerateFromTemplate('generator/rpc.cc.php',
//                        '../../src/maidsafe/common/' . strtolower($name) . 'rpc.cc');
  GenerateFromTemplate('generator/service.h.php',
                       '../../src/maidsafe/vault/' . strtolower($name) . 'service.h');
  GenerateFromTemplate('generator/service.cc.php',
                       '../../src/maidsafe/vault/' . strtolower($name) . 'service.cc');
}
