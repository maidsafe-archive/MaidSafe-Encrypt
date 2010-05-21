/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Test for AccountStatusManager class.
* Created:      2010-05-19
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
#include "maidsafe/utils.h"
#include "maidsafe/accountstatusmanager.h"

namespace maidsafe {

class AccountStatusManagerTest : public testing::Test {
 public:
  AccountStatusManagerTest() : ahm_() {}
 protected:
  AccountStatusManager ahm_;
};

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_Init) {
  EXPECT_TRUE(ahm_.UpdateRequired());
  EXPECT_TRUE(ahm_.AbleToStore(0));
  EXPECT_FALSE(ahm_.AbleToStore(123));
  ASSERT_EQ(0, ahm_.amendments_since_update_);
  boost::uint64_t offered, given, taken;
  ahm_.AccountStatus(&offered, &given, &taken);
  ASSERT_EQ(boost::uint64_t(0), offered);
  ASSERT_EQ(boost::uint64_t(0), given);
  ASSERT_EQ(boost::uint64_t(0), taken);
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_UpdateRequired) {
  EXPECT_TRUE(ahm_.UpdateRequired());
  ahm_.SetAccountStatus(3, 2, 1);
  EXPECT_FALSE(ahm_.UpdateRequired());
  for (int i = 0; i < ahm_.kMaxAmendments_; ++i)
    ahm_.AdviseAmendment(AmendAccountRequest::kSpaceGivenInc, 5);
  EXPECT_FALSE(ahm_.UpdateRequired());
  ahm_.AdviseAmendment(AmendAccountRequest::kSpaceGivenInc, 5);
  EXPECT_TRUE(ahm_.UpdateRequired());
  ahm_.SetAccountStatus(6, 5, 4);
  EXPECT_FALSE(ahm_.UpdateRequired());
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_SetAccountStatus) {
  boost::uint64_t offered, given, taken;
  ahm_.AccountStatus(&offered, &given, &taken);
  ASSERT_EQ(boost::uint64_t(0), offered);
  ASSERT_EQ(boost::uint64_t(0), given);
  ASSERT_EQ(boost::uint64_t(0), taken);
  ahm_.SetAccountStatus(3, 2, 1);
  ahm_.AccountStatus(&offered, &given, &taken);
  ASSERT_EQ(boost::uint64_t(3), offered);
  ASSERT_EQ(boost::uint64_t(2), given);
  ASSERT_EQ(boost::uint64_t(1), taken);
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_AdviseAmendment) {
  boost::uint64_t offered, given, taken;
  ahm_.AccountStatus(&offered, &given, &taken);
  ASSERT_EQ(boost::uint64_t(0), offered);
  ASSERT_EQ(boost::uint64_t(0), given);
  ASSERT_EQ(boost::uint64_t(0), taken);
  ahm_.AdviseAmendment(AmendAccountRequest::kSpaceOffered, 123);
  ASSERT_EQ(1, ahm_.amendments_since_update_);
  ahm_.AccountStatus(&offered, &given, &taken);
  ASSERT_EQ(boost::uint64_t(123), offered);
  ASSERT_EQ(boost::uint64_t(0), given);
  ASSERT_EQ(boost::uint64_t(0), taken);
  ahm_.AdviseAmendment(AmendAccountRequest::kSpaceGivenInc, 234);
  ahm_.AccountStatus(&offered, &given, &taken);
  ASSERT_EQ(boost::uint64_t(123), offered);
  ASSERT_EQ(boost::uint64_t(234), given);
  ASSERT_EQ(boost::uint64_t(0), taken);
  ahm_.AdviseAmendment(AmendAccountRequest::kSpaceTakenInc, 345);
  ahm_.AccountStatus(&offered, &given, &taken);
  ASSERT_EQ(boost::uint64_t(123), offered);
  ASSERT_EQ(boost::uint64_t(234), given);
  ASSERT_EQ(boost::uint64_t(345), taken);
  ahm_.AdviseAmendment(AmendAccountRequest::kSpaceGivenInc, 67);
  ahm_.AdviseAmendment(AmendAccountRequest::kSpaceTakenInc, 56);
  ahm_.AccountStatus(&offered, &given, &taken);
  ASSERT_EQ(boost::uint64_t(123), offered);
  ASSERT_EQ(boost::uint64_t(301), given);
  ASSERT_EQ(boost::uint64_t(401), taken);
  ahm_.AdviseAmendment(AmendAccountRequest::kSpaceGivenDec, 2);
  ahm_.AdviseAmendment(AmendAccountRequest::kSpaceTakenDec, 22);
  ahm_.AccountStatus(&offered, &given, &taken);
  ASSERT_EQ(boost::uint64_t(123), offered);
  ASSERT_EQ(boost::uint64_t(299), given);
  ASSERT_EQ(boost::uint64_t(379), taken);
  ahm_.AdviseAmendment(AmendAccountRequest::kSpaceGivenDec, 300);
  ahm_.AdviseAmendment(AmendAccountRequest::kSpaceTakenDec, 500);
  ahm_.AccountStatus(&offered, &given, &taken);
  ASSERT_EQ(boost::uint64_t(123), offered);
  ASSERT_EQ(boost::uint64_t(0), given);
  ASSERT_EQ(boost::uint64_t(0), taken);
  ASSERT_EQ(9, ahm_.amendments_since_update_);
}

TEST_F(AccountStatusManagerTest, BEH_MAID_ASM_AbleToStore) {
  EXPECT_TRUE(ahm_.AbleToStore(0));
  EXPECT_FALSE(ahm_.AbleToStore(123));
  ahm_.SetAccountStatus(100, 0, 0);
  EXPECT_TRUE(ahm_.AbleToStore(23));
  EXPECT_TRUE(ahm_.AbleToStore(100));
  EXPECT_FALSE(ahm_.AbleToStore(123));
  ahm_.AdviseAmendment(AmendAccountRequest::kSpaceTakenInc, 42);
  EXPECT_FALSE(ahm_.AbleToStore(100));
  EXPECT_TRUE(ahm_.AbleToStore(50));
}

}  // namespace maidsafe
