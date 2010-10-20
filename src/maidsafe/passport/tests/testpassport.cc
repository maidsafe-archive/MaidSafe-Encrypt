/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Unit tests for Passport class
* Version:      1.0
* Created:      2010-10-19-23.59.27
* Revision:     none
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

#include "maidsafe/passport/passport.h"

namespace maidsafe {

namespace passport {

namespace test {

const boost::uint16_t kRsaKeySize(4096);
const boost::uint8_t kMaxThreadCount(5);

class PassportTest : public testing::Test {
 public:
  PassportTest() : passport_(kRsaKeySize, kMaxThreadCount) {}
 protected:
  void SetUp() {}
  void TearDown() {}
  Passport passport_;
};

TEST_F(PassportTest, BEH_PASSPORT_CreateUserSysPackets) {
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
