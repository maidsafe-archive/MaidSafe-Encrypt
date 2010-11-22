/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Test for ContactCache class.
* Created:      2010-11-11
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
#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/contactcache.h"
#include "maidsafe/common/chunkstore.h"
#include "maidsafe/sharedtest/mockkadops.h"

namespace test_ctc {
static const boost::uint8_t K(4);
}  // namespace test_cc

namespace maidsafe {

namespace test {

class ContactCacheTest : public testing::Test {
 public:
  ContactCacheTest()
      : pmid_(SHA512String(base::RandomString(100))),
        transport_handler_(),
        channel_manager_(&transport_handler_),
        chunkstore_(new ChunkStore("Chunkstore", 9999999, 0)),
        mko_(new MockKadOps(&transport_handler_, &channel_manager_,
                      kad::CLIENT, "", "", false, false, test_ctc::K,
                      chunkstore_)),
        contact_cache_(mko_),
        fail_response_(),
        good_response_() {}
 protected:
  void SetUp() {
    kad::Contact empty_contact, contact(kad::Contact(pmid_, "192.168.1.0", 42));
    std::string ser_contact;
    contact.SerialiseToString(&ser_contact);
    kad::FindNodeResult find_result;
    find_result.set_result(kad::kRpcResultFailure);
    find_result.set_contact("fail");
    fail_response_ = find_result.SerializeAsString();
    find_result.set_result(kad::kRpcResultSuccess);
    find_result.set_contact(ser_contact);
    good_response_ = find_result.SerializeAsString();
  }
  std::string pmid_;
  transport::TransportHandler transport_handler_;
  rpcprotocol::ChannelManager channel_manager_;
  boost::shared_ptr<ChunkStore> chunkstore_;
  boost::shared_ptr<MockKadOps> mko_;
  ContactCache contact_cache_;
  std::string fail_response_, good_response_;
};

TEST_F(ContactCacheTest, BEH_MAID_CTC_Init) {
  // Set up expectation
  EXPECT_CALL(*mko_, GetNodeContactDetails(pmid_,
      testing::An<VoidFuncIntContact>(), false))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&MockKadOps::ThreadedGetNodeContactDetailsCallback,
                      mko_.get(), good_response_, _1))));

  // uninitialised
  ASSERT_TRUE(contact_cache_.pmid().empty());
  ASSERT_FALSE(contact_cache_.active());
  kad::Contact contact;
  ASSERT_FALSE(contact_cache_.GetContact(&contact));
  ASSERT_EQ(kad::kZeroId, contact.node_id().String());

  // empty pmid
  contact_cache_.Init("");
  contact_cache_.WaitForUpdate();
  ASSERT_FALSE(contact_cache_.active());

  // complete init, trigger update
  contact_cache_.Init(pmid_);
  contact_cache_.WaitForUpdate();
  ASSERT_TRUE(contact_cache_.active());
  ASSERT_TRUE(contact_cache_.GetContact(&contact));
  ASSERT_EQ(pmid_, contact.node_id().String());
}

TEST_F(ContactCacheTest, BEH_MAID_CTC_Update) {
  // Set up expectation
  EXPECT_CALL(*mko_, GetNodeContactDetails(pmid_,
      testing::An<VoidFuncIntContact>(), false))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&MockKadOps::ThreadedGetNodeContactDetailsCallback,
                      mko_.get(), fail_response_, _1))))
      .WillOnce(testing::WithArgs<1>(testing::Invoke(
          boost::bind(&MockKadOps::ThreadedGetNodeContactDetailsCallback,
                      mko_.get(), good_response_, _1))));

  ASSERT_TRUE(contact_cache_.last_update_.is_neg_infinity());

  // empty pmid
  contact_cache_.Update();
  contact_cache_.WaitForUpdate();
  ASSERT_FALSE(contact_cache_.active());
  ASSERT_TRUE(contact_cache_.last_update_.is_neg_infinity());

  // RPC fails
  contact_cache_.Init(pmid_);  // implicit update
  contact_cache_.WaitForUpdate();
  ASSERT_FALSE(contact_cache_.active());
  ASSERT_TRUE(contact_cache_.last_update_.is_neg_infinity());

  kad::Contact contact;

  // RPC succeeds
  contact_cache_.Update();
  contact_cache_.WaitForUpdate();
  ASSERT_TRUE(contact_cache_.active());
  ASSERT_TRUE(contact_cache_.GetContact(&contact));
  ASSERT_EQ(pmid_, contact.node_id().String());

  boost::posix_time::ptime last_update = contact_cache_.last_update_;
  ASSERT_FALSE(last_update.is_neg_infinity());

  // repeated call, skip update
  contact_cache_.Update();
  contact_cache_.WaitForUpdate();
  ASSERT_TRUE(contact_cache_.active());
  ASSERT_TRUE(contact_cache_.GetContact(&contact));
  ASSERT_EQ(pmid_, contact.node_id().String());

  ASSERT_EQ(last_update, contact_cache_.last_update_);
}

}  // namespace test

}  // namespace maidsafe
