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

#include <boost/filesystem.hpp>
#include <boost/scoped_ptr.hpp>

#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/utils.h>
#include "maidsafe/client/keyatlas.h"
#include "maidsafe/client/packetfactory.h"
#include "tests/maidsafe/cached_keys.h"

namespace fs = boost::filesystem;

class KeyAtlasTest : public testing::Test {
 public:
  KeyAtlasTest() : key_ring_(), keys_() {}
 protected:
  void SetUp() {
    key_ring_.ClearKeyRing();
    cached_keys::MakeKeys(12, &keys_);
  }
  void TearDown() {}
  maidsafe::KeyAtlas key_ring_;
  std::vector<crypto::RsaKeyPair> keys_;
};

TEST_F(KeyAtlasTest, BEH_MAID_AddKeys) {
  // add keys
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(0, key_ring_.AddKey(i, package_id, private_key,
              public_key, "")) << "Failed to add key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_GetPackageID) {
  // try to get non-existent package Id
  ASSERT_EQ("", key_ring_.PackageID(0))
        << "Returned package Id for non-existent key.";

  // add keys
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(0, key_ring_.AddKey(i, package_id, private_key,
              public_key, "")) << "Failed to add key " << i << ".";
  }

  // get package Id
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    ASSERT_EQ(package_id, key_ring_.PackageID(i))
              << "Failed to get package ID for key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_GetPrivateKey) {
  // try to get non-existent private key
  ASSERT_EQ("", key_ring_.PrivateKey(0))
            << "Returned private key for non-existent key.";

  // add keys
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(0, key_ring_.AddKey(i, package_id, private_key,
              public_key, "")) << "MI - Failed to add key " << i << ".";
  }

  // get private key
  for (int i = 0; i < 11; i++) {
    std::string private_key = "Private Key " + base::itos(i);
    ASSERT_EQ(private_key, key_ring_.PrivateKey(i))
              << "MI - Failed to get private key for key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_GetPublicKey) {
  // try to get non-existent public key
  ASSERT_EQ("", key_ring_.PrivateKey(0))
            << "Returned public key for non-existent key.";

  // add keys
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(0, key_ring_.AddKey(i, package_id, private_key,
              public_key, "")) << "Failed to add key " << i << ".";
  }

  // get public key
  for (int i = 0; i < 11; i++) {
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(public_key, key_ring_.PublicKey(i))
              << "Failed to get public key for key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_GetSignedPublicKey) {
  // try to get non-existent public key
  ASSERT_EQ("", key_ring_.PrivateKey(0))
            << "Returned public key for non-existent key.";

  // add keys
  std::string pub_keys[11];
  std::string pri_keys[11];
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    pri_keys[i] = keys_.at(i).private_key();
    pub_keys[i] = keys_.at(i).public_key();
    ASSERT_EQ(0, key_ring_.AddKey(i, package_id, pri_keys[i],
              pub_keys[i], "")) << "Failed to add key " << i << ".";
  }

  // get signed public key
  for (int i = 0; i < 11; i++) {
    std::string public_key = pub_keys[i];
    std::string private_key = pri_keys[i];
    crypto::Crypto co;
    ASSERT_TRUE(co.AsymCheckSig(public_key, key_ring_.SignedPublicKey(i),
                public_key, crypto::STRING_STRING));
  }

  // add a package which already has a public key signature
  std::string pub_key, pri_key, pub_key_sig = "Signature";
  std::string package_id = "Package ID 11";
  pri_key = keys_.at(11).private_key();
  pub_key = keys_.at(11).public_key();
  ASSERT_EQ(0, key_ring_.AddKey(11, package_id, pri_key, pub_key, pub_key_sig))
      << "Failed to add key 11.";
  ASSERT_EQ(pub_key_sig, key_ring_.SignedPublicKey(11));
}

TEST_F(KeyAtlasTest, BEH_MAID_RemoveKeys) {
  // add keys
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(0, key_ring_.AddKey(i, package_id, private_key,
              public_key, "")) << "Failed to add key " << i << ".";
  }

  // remove keys
  for (int i = 0; i < 11; i++) {
    ASSERT_EQ(0, key_ring_.RemoveKey(i))
              << "Failed to remove key " << i << ".";
  }

  for (int i = 0; i < 11; i++) {
    // MI ops
    ASSERT_EQ("", key_ring_.PackageID(i))
              << "Failed to remove public key for key " << i << ".";
    ASSERT_EQ("", key_ring_.PackageID(i))
              << "Failed to remove private key for key " << i << ".";
    ASSERT_EQ("", key_ring_.PackageID(i))
              << "Failed to remove package ID for key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_GetKeyRing) {
  // add keys
  for (int i = 0; i < 7; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(0, key_ring_.AddKey(i, package_id, private_key,
              public_key, "")) << "Failed to add key " << i << ".";
  }

  std::list<maidsafe::KeyAtlasRow> keyring;
  key_ring_.GetKeyRing(&keyring);
  ASSERT_EQ(size_t(7), keyring.size())
            << "Keyring list size is not equal to the number of IDs.";
  ASSERT_EQ(key_ring_.KeyRingSize(), keyring.size())
            << "Keyring list size is not equal to the number of IDs.";

  for (int i = 0; i < 7; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    bool found_key = false;
    for (std::list<maidsafe::KeyAtlasRow>::iterator it = keyring.begin();
        it != keyring.end(); it++) {
      if (it->type_ == i) {
        found_key = true;
        ASSERT_EQ(package_id, it->id_) <<
                  "Failed to match package Id of key " << i << ".";
        ASSERT_EQ(private_key, it->private_key_) <<
                  "Failed to match private key of key " << i << ".";
        ASSERT_EQ(public_key, it->public_key_) <<
                  "Failed to match public key of key " << i << ".";
      }
    }
    ASSERT_TRUE(found_key) <<
                "Failed to match package type of key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_AmendKeys) {
  // add keys
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(0, key_ring_.AddKey(i, package_id, private_key,
              public_key, "")) << "MI - Failed to add key " << i << ".";
  }

  // amend keys & check keys were correctly updated
  for (int i = 0; i < 11; i++) {
    std::string updated_package_id = "Updated Package ID " + base::itos(i);
    std::string updated_private_key = "Updated Private Key " + base::itos(i);
    std::string updated_public_key = "Updated Public Key " + base::itos(i);
    ASSERT_EQ(0, key_ring_.AddKey(i, updated_package_id,
              updated_private_key, updated_public_key, "")) <<
              "Failed to update key " << i << ".";
    ASSERT_EQ(updated_package_id, key_ring_.PackageID(i))
              << "Failed to get package ID for key " << i << ".";
    ASSERT_EQ(updated_private_key, key_ring_.PrivateKey(i))
              << "Failed to get private key for key " << i << ".";
    ASSERT_EQ(updated_private_key, key_ring_.PrivateKey(i))
              << "Failed to get private key for key " << i << ".";
  }
}

