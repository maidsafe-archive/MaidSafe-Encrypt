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
#include <maidsafe/maidsafe-dht_config.h>
#include "maidsafe/maidsafevalidator.h"
#include "maidsafe/returncodes.h"
#include "maidsafe/client/packetfactory.h"
#include "tests/maidsafe/cached_keys.h"

class TestMSValidator : public testing::Test {
 public:
  TestMSValidator() : co(), signed_public_key(), validator(), keys_() {}
 protected:
  void SetUp() {
    cached_keys::MakeKeys(1, &keys_);
    cached_keys::MakeKeys(2, &keys_);
    signed_public_key = co.AsymSign(keys_.at(0).public_key(), "",
        keys_.at(0).private_key(), crypto::STRING_STRING);
  }
  crypto::Crypto co;
  std::string signed_public_key;
  maidsafe::MaidsafeValidator validator;
  std::vector<crypto::RsaKeyPair> keys_;
};

TEST_F(TestMSValidator, BEH_MAID_TestValidateSignerID) {
  std::string id(co.Hash(keys_.at(0).public_key() + signed_public_key, "",
      crypto::STRING_STRING, false));
  printf("key1pub - %s\n", base::EncodeToHex(keys_.at(0).public_key()).c_str());
  printf("key2pub - %s\n", base::EncodeToHex(keys_.at(1).public_key()).c_str());
  ASSERT_TRUE(validator.ValidateSignerId(id, keys_.at(0).public_key(),
      signed_public_key));
  ASSERT_FALSE(validator.ValidateSignerId(id, keys_.at(1).public_key(),
      signed_public_key));
  ASSERT_FALSE(validator.ValidateSignerId("invalid id",
      keys_.at(0).public_key(), signed_public_key));
}

TEST_F(TestMSValidator, BEH_MAID_TestValidateSignedRequest) {
  std::string rec_id(co.Hash(base::RandomString(10), "", crypto::STRING_STRING,
      false));
  validator.set_id(rec_id);
  std::string key(co.Hash(base::RandomString(10), "", crypto::STRING_STRING,
      false));
  std::string signed_request(co.AsymSign(co.Hash(signed_public_key + key +
      rec_id, "", crypto::STRING_STRING, false), "", keys_.at(0).private_key(),
      crypto::STRING_STRING));
  ASSERT_TRUE(validator.ValidateRequest(signed_request,
      keys_.at(0).public_key(), signed_public_key, key));
  ASSERT_FALSE(validator.ValidateRequest(signed_request,
      keys_.at(1).public_key(), signed_public_key, key));
  ASSERT_FALSE(validator.ValidateRequest("invalid signed request",
      keys_.at(1).public_key(), signed_public_key, key));
  ASSERT_FALSE(validator.ValidateRequest(signed_request,
      keys_.at(0).public_key(), signed_public_key, "key"));
}

TEST_F(TestMSValidator, BEH_MAID_TestCreateRequestSignature) {
  std::list<std::string> params;
  std::string signature;
  ASSERT_EQ(maidsafe::kValidatorNoPrivateKey,
            validator.CreateRequestSignature("", params, &signature));
  ASSERT_EQ(maidsafe::kValidatorNoParameters,
            validator.CreateRequestSignature(keys_.at(0).private_key(), params,
            &signature));
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string a("a");
  params.push_back(a);
  ASSERT_EQ(0, validator.CreateRequestSignature(keys_.at(0).private_key(),
            params, &signature));
  validator.set_id(a);
  ASSERT_TRUE(validator.ValidateRequest(signature, keys_.at(0).public_key(), "",
              ""));
  params.push_back("b");
  params.push_back("c");
  ASSERT_EQ(0, validator.CreateRequestSignature(keys_.at(0).private_key(),
            params, &signature));
  validator.set_id("c");
  ASSERT_TRUE(validator.ValidateRequest(signature, keys_.at(0).public_key(),
              "a", "b"));
}
