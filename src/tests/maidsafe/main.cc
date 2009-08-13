/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  none
* Version:      1.0
* Created:      2009-08-13-01.18.27
* Revision:     none
* Compiler:     gcc
* Author:       Team
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include <boost/cstdint.hpp>
#include "gtest/gtest.h"
#include "maidsafe/vault/vaultdaemon.h"

// TODO(dirvine): we need to set up 10 vaults here in a kademlia network
// where we have k=2 alpha=2 and beta=1
// ideally crashing nodes frequently etc. should be added if time allows

class NetTest {
 public:
  NetTest() :num_nodes_(10), start_port_(5483) {}
  int StartNodes() { return 0; }
  int StopNodes() { return 0; }
  bool num_nodes() { return num_nodes_; }
  void set_num_nodes(int num_nodes) { num_nodes_ = num_nodes; }
 private:
  int num_nodes_;
  boost::uint32_t start_port_;
};

int main(int argc, char **argv) {
  NetTest net_test;
  net_test.set_num_nodes(20);
  net_test.StartNodes();
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}



