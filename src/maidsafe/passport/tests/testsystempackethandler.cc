/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Version:      1.0
* Created:      14/10/2010 11:43:59
* Revision:     none
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
  typedef std::tr1::shared_ptr<MidPacket> MidPtr;
  SystemPacketHandlerTest() : packet_handler_() {}
 protected:
  void SetUp() {}
  void TearDown() {}
  SystemPacketHandler packet_handler_;
};

TEST_F(SystemPacketHandlerTest, BEH_PASSPORT_AddPendingPacket) {
  MidPtr mid1(new MidPacket("User1", "1111", ""));
  MidPtr mid2(new MidPacket("User2", "2222", ""));
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
