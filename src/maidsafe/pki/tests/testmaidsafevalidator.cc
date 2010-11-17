/*
 * ============================================================================
 *
 * Copyright [2010] maidsafe.net limited
 *
 * Description:  Test MaidsafeValidator Class
 * Version:      1.0
 * Created:      2010-01-06
 * Revision:     none
 * Compiler:     gcc
 * Author:       Jose Cisnertos
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
#include <maidsafe/base/crypto.h>
#include <maidsafe/base/utils.h>
#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/returncodes.h"
#include "maidsafe/pki/maidsafevalidator.h"
#include "maidsafe/pki/packet.h"

namespace maidsafe {

namespace pki {

namespace test {

class TestMSValidator : public testing::Test {
 public:
  TestMSValidator() : co_(), signed_public_key_(), validator_(), keys_() {}
 protected:
  void SetUp() {
    crypto::RsaKeyPair rsakp;
    keys_.push_back(rsakp);
    keys_.at(0).GenerateKeys(4096);
    keys_.push_back(rsakp);
    keys_.at(1).GenerateKeys(4096);
    signed_public_key_ = co_.AsymSign(keys_.at(0).public_key(), "",
        keys_.at(0).private_key(), crypto::STRING_STRING);
  }
  crypto::Crypto co_;
  std::string signed_public_key_;
  MaidsafeValidator validator_;
  std::vector<crypto::RsaKeyPair> keys_;
};

TEST_F(TestMSValidator, BEH_PKI_TestValidateSignerID) {
  std::string id = co_.Hash((keys_.at(0).public_key() + signed_public_key_), "",
                            crypto::STRING_STRING, false);
  ASSERT_TRUE(validator_.ValidateSignerId(id, keys_.at(0).public_key(),
      signed_public_key_));
  ASSERT_FALSE(validator_.ValidateSignerId(id, keys_.at(1).public_key(),
      signed_public_key_));
  ASSERT_FALSE(validator_.ValidateSignerId("invalid id",
      keys_.at(0).public_key(), signed_public_key_));
}

TEST_F(TestMSValidator, BEH_PKI_TestValidateSignedRequest) {
  std::string rec_id(co_.Hash(base::RandomString(10), "", crypto::STRING_STRING,
                              false));
  validator_.set_id(rec_id);
  std::string key(co_.Hash(base::RandomString(10), "", crypto::STRING_STRING,
                           false));
  std::string signed_request(co_.AsymSign(co_.Hash((
      signed_public_key_ + key + rec_id), "", crypto::STRING_STRING, false), "",
      keys_.at(0).private_key(), crypto::STRING_STRING));
  ASSERT_TRUE(validator_.ValidateRequest(signed_request,
      keys_.at(0).public_key(), signed_public_key_, key));
  ASSERT_FALSE(validator_.ValidateRequest(signed_request,
      keys_.at(1).public_key(), signed_public_key_, key));
  ASSERT_FALSE(validator_.ValidateRequest("invalid signed request",
      keys_.at(1).public_key(), signed_public_key_, key));
  ASSERT_FALSE(validator_.ValidateRequest(signed_request,
      keys_.at(0).public_key(), signed_public_key_, "key"));
}

TEST_F(TestMSValidator, BEH_PKI_TestCreateRequestSignature) {
  std::list<std::string> params;
  std::string signature;
  ASSERT_EQ(kValidatorNoPrivateKey,
            validator_.CreateRequestSignature("", params, &signature));
  ASSERT_EQ(kValidatorNoParameters,
            validator_.CreateRequestSignature(keys_.at(0).private_key(), params,
            &signature));
  crypto::Crypto co_;
  co_.set_hash_algorithm(crypto::SHA_512);
  std::string a("a");
  params.push_back(a);
  ASSERT_EQ(0, validator_.CreateRequestSignature(keys_.at(0).private_key(),
            params, &signature));
  validator_.set_id(a);
  ASSERT_TRUE(validator_.ValidateRequest(signature, keys_.at(0).public_key(),
              "", ""));
  params.push_back("b");
  params.push_back("c");
  ASSERT_EQ(0, validator_.CreateRequestSignature(keys_.at(0).private_key(),
            params, &signature));
  validator_.set_id("c");
  ASSERT_TRUE(validator_.ValidateRequest(signature, keys_.at(0).public_key(),
              "a", "b"));
}

}  // namespace test

}  // namespace pki

}  // namespace maidsafe
