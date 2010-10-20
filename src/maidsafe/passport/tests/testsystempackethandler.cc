/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Version:      1.0
* Created:      2009-01-28-10.59.46
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
#include <gtest/gtest.h>

#include "maidsafe/passport/systempackethandler.h"

namespace maidsafe {

namespace passport {

namespace test {

class SystemPacketHandlerTest : public testing::Test {
 public:
  SystemPacketHandlerTest() : packet_handler_() {}
 protected:
  void SetUp() {}
  void TearDown() {}
  SystemPacketHandler packet_handler_;
};

TEST_F(SystemPacketHandlerTest, BEH_PASSPORT_AddKeys) {
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
