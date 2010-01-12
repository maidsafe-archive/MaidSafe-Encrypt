/*
 * ============================================================================
 *
 * Copyright [2009] maidsafe.net limited
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

class TestMSValidator : public testing::Test {
 public:
  TestMSValidator() : co(), rsa_keys(), other_keys(), signed_public_key(),
                      validator() {}
 protected:
  void SetUp() {
    rsa_keys.GenerateKeys(4096);
    signed_public_key = co.AsymSign(rsa_keys.public_key(), "",
     rsa_keys.private_key(), crypto::STRING_STRING);
    other_keys.GenerateKeys(4096);
  }
  crypto::Crypto co;
  crypto::RsaKeyPair rsa_keys, other_keys;
  std::string signed_public_key;
  maidsafe::MaidsafeValidator validator;
};

TEST_F(TestMSValidator, BEH_MAID_TestValidateSignerID) {
  std::string id(co.Hash(rsa_keys.public_key() + signed_public_key, "",
    crypto::STRING_STRING, false));
  std::string id1(co.Hash(rsa_keys.public_key() + signed_public_key, "",
    crypto::STRING_STRING, true));
  ASSERT_TRUE(validator.ValidateSignerId(id, rsa_keys.public_key(),
    signed_public_key));
  ASSERT_FALSE(validator.ValidateSignerId(id, other_keys.public_key(),
    signed_public_key));
  ASSERT_FALSE(validator.ValidateSignerId("invalid id", rsa_keys.public_key(),
    signed_public_key));
}

TEST_F(TestMSValidator, BEH_MAID_TestValidateSignedRequest) {
  std::string rec_id(co.Hash(base::RandomString(10), "", crypto::STRING_STRING,
    false));
  validator.set_id(rec_id);
  std::string key(co.Hash(base::RandomString(10), "", crypto::STRING_STRING,
    false));
  std::string signed_request(co.AsymSign(co.Hash(signed_public_key + key +
    rec_id, "", crypto::STRING_STRING, false), "", rsa_keys.private_key(),
    crypto::STRING_STRING));
  ASSERT_TRUE(validator.ValidateRequest(signed_request,
    rsa_keys.public_key(), signed_public_key, key));
  ASSERT_FALSE(validator.ValidateRequest(signed_request,
    other_keys.public_key(), signed_public_key, key));
  ASSERT_FALSE(validator.ValidateRequest("invalid signed request",
    other_keys.public_key(), signed_public_key, key));
  ASSERT_FALSE(validator.ValidateRequest(signed_request,
    rsa_keys.public_key(), signed_public_key, "key"));
}

TEST_F(TestMSValidator, BEH_MAID_TestCreateRequestSignature) {
  std::list<std::string> params;
  std::string signature;
  ASSERT_EQ(maidsafe::kValidatorNoPrivateKey,
            validator.CreateRequestSignature("", params, &signature));
  ASSERT_EQ(maidsafe::kValidatorNoParameters,
            validator.CreateRequestSignature(rsa_keys.private_key(), params,
            &signature));
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string a("a");
  params.push_back(a);
  ASSERT_EQ(0, validator.CreateRequestSignature(rsa_keys.private_key(), params,
            &signature));
  validator.set_id(a);
  ASSERT_TRUE(validator.ValidateRequest(signature, rsa_keys.public_key(), "",
              ""));
  params.push_back("b");
  params.push_back("c");
  ASSERT_EQ(0, validator.CreateRequestSignature(rsa_keys.private_key(), params,
            &signature));
  validator.set_id("c");
  ASSERT_TRUE(validator.ValidateRequest(signature, rsa_keys.public_key(), "a",
              "b"));
}
