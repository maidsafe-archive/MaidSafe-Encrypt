/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Created:      2010-03-10
* Author:       Team www.maidsafe.net
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

#include "tests/maidsafe/mockkadops.h"

namespace maidsafe {

class KadOpsTest : public testing::Test {
 protected:
  KadOpsTest()
    : mko_(boost::shared_ptr<kad::KNode>()),
      crypto_(),
      fail_parse_result_(
        mock_kadops::MakeFindNodesResponse(mock_kadops::kFailParse,
                                           &fail_parse_pmids_)),
      fail_result_(mock_kadops::MakeFindNodesResponse(mock_kadops::kResultFail,
                                                      &fail_pmids_)),
      few_result_(
        mock_kadops::MakeFindNodesResponse(mock_kadops::kTooFewContacts,
                                           &few_pmids_)),
      good_result_(mock_kadops::MakeFindNodesResponse(mock_kadops::kGood,
                                                      &good_pmids_)) {
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);
  }
  MockKadOps mko_;
  crypto::Crypto crypto_;
  std::vector<std::string> fail_parse_pmids_, fail_pmids_, few_pmids_,
                           good_pmids_;
  std::string fail_parse_result_, fail_result_, few_result_, good_result_;
};

TEST_F(KadOpsTest, BEH_MAID_FindCloseNodes) {
  std::vector<kad::Contact> contacts;
  kad::Contact dummy_contact = kad::Contact(crypto_.Hash("Dummy", "",
      crypto::STRING_STRING, false), "192.168.1.0", 4999);

  // Expectations
  EXPECT_CALL(mko_, FindCloseNodes("x",
      testing::An< std::vector<kad::Contact>* >()))
      .WillRepeatedly(testing::Invoke(&mko_, &MockKadOps::FindCloseNodesReal));
  EXPECT_CALL(mko_, FindCloseNodes("x",
      testing::An<const base::callback_func_type&>()))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, fail_parse_result_, _1))))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, fail_result_, _1))))  // Call 3
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, few_result_, _1))))  // Call 4
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result_, _1))))  // Call 5
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback, good_result_, _1))));  //  6

  // Call 1
  ASSERT_EQ(kFindNodesError, mko_.FindCloseNodes("x", NULL));

  // Call 2
  contacts.push_back(dummy_contact);
  ASSERT_EQ(size_t(1), contacts.size());
  ASSERT_EQ(kFindNodesParseError, mko_.FindCloseNodes("x", &contacts));
  ASSERT_EQ(size_t(0), contacts.size());

  // Call 3
  contacts.push_back(dummy_contact);
  ASSERT_EQ(size_t(1), contacts.size());
  ASSERT_EQ(kFindNodesFailure, mko_.FindCloseNodes("x", &contacts));
  ASSERT_EQ(size_t(0), contacts.size());

  // Call 4
  ASSERT_EQ(kSuccess, mko_.FindCloseNodes("x", &contacts));
  ASSERT_EQ(few_pmids_.size(), contacts.size());

  // Call 5
  ASSERT_EQ(kSuccess, mko_.FindCloseNodes("x", &contacts));
  ASSERT_EQ(size_t(kad::K), contacts.size());

  // Call 6
  contacts.push_back(dummy_contact);
  ASSERT_EQ(kSuccess, mko_.FindCloseNodes("x", &contacts));
  ASSERT_EQ(size_t(kad::K), contacts.size());
}

TEST_F(KadOpsTest, DISABLED_BEH_MAID_GetStorePeer) {
  ASSERT_TRUE(false) << "Not implemented.";
}

TEST_F(KadOpsTest, BEH_MAID_ContactWithinClosest) {
  std::vector<kad::Contact> ctc;
  kad::Contact contact1(base::DecodeFromHex("11111111"), "127.0.0.1", 0);
  ctc.push_back(contact1);
  kad::Contact contact2(base::DecodeFromHex("77777777"), "127.0.0.1", 0);
  ctc.push_back(contact2);
  kad::Contact close(base::DecodeFromHex("33333333"), "127.0.0.1", 0);
  kad::Contact not_close(base::DecodeFromHex("ffffffff"), "127.0.0.1", 0);
  std::string key(base::DecodeFromHex("00000000"));

  ASSERT_TRUE(ContactWithinClosest(key, close, ctc));
  ASSERT_FALSE(ContactWithinClosest(key, not_close, ctc));
}

TEST_F(KadOpsTest, BEH_MAID_RemoveKadContact) {
  std::vector<kad::Contact> ctc;
  {
    kad::Contact contact("aaa", "127.0.0.1", 0);
    ctc.push_back(contact);
  }
  {
    kad::Contact contact("bbb", "127.0.0.1", 0);
    ctc.push_back(contact);
  }
  {
    kad::Contact contact("ccc", "127.0.0.1", 0);
    ctc.push_back(contact);
  }
  ASSERT_EQ(size_t(3), ctc.size());
  ASSERT_FALSE(RemoveKadContact("ddd", &ctc));
  ASSERT_EQ(size_t(3), ctc.size());
  ASSERT_TRUE(RemoveKadContact("bbb", &ctc));
  ASSERT_EQ(size_t(2), ctc.size());
}

}  // namespace maidsafe
