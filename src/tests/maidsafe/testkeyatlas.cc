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

#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/utils.h"
#include "maidsafe/client/keyatlas.h"

namespace fs = boost::filesystem;

class KeyAtlasTest : public testing::Test {
 public:
  KeyAtlasTest() : db_name1_(".DbTest/1.db") {}
 protected:
  void SetUp() {
    fs::create_directory(".DbTest");
    db_name1_ = ".DbTest/1.db";
  }
  void TearDown() {
    fs::remove_all(".DbTest");
  }

  std::string db_name1_;
};


TEST_F(KeyAtlasTest, BEH_MAID_CreateKeysDb) {
  ASSERT_FALSE(fs::exists("M:\\"));
  int result = -1;
  boost::scoped_ptr<maidsafe::KeyAtlas> keys_db_(
      new maidsafe::KeyAtlas(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";
}

TEST_F(KeyAtlasTest, BEH_MAID_ConnectKeysDb) {
  //  try to connect to non-existant db
  {
    int result = -1;
    boost::scoped_ptr<maidsafe::KeyAtlas> keys_db_(
        new maidsafe::KeyAtlas("Non-existant db", CONNECT, &result));
    ASSERT_NE(0, result) << "Db creation incorrectly returned result 0";
    ASSERT_FALSE(fs::exists("Non-existant db")) << "Db was not created.";
  }

  //  create db1
  {
    int result = -1;
    boost::scoped_ptr<maidsafe::KeyAtlas> keys_db_(
        new maidsafe::KeyAtlas(db_name1_, CREATE, &result));
    ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
    ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";
  }

  //  try to connect to db1
  {
    int result = -1;
    boost::scoped_ptr<maidsafe::KeyAtlas> keys_db_(
        new maidsafe::KeyAtlas(db_name1_, CONNECT, &result));
    ASSERT_EQ(0, result) << "Db connection returned result " << result << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_AddKeys) {
  //  create db1
  int result = -1;
  boost::scoped_ptr<maidsafe::KeyAtlas> keys_db_(
      new maidsafe::KeyAtlas(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  //  add keys
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), package_id, private_key,
              public_key)) << "Failed to add key " << i << ".";
    ASSERT_EQ(0, keys_db_->MI_AddKeys(i, package_id, private_key,
              public_key)) << "MI - Failed to add key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_GetPackageID) {
  //  create db1
  int result = -1;
  boost::scoped_ptr<maidsafe::KeyAtlas> keys_db_(
      new maidsafe::KeyAtlas(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  //  try to get non-existant package Id
  ASSERT_EQ("", keys_db_->GetPackageID(base::itos(0)))
      << "Returned package Id for non-existant key.";
  ASSERT_EQ("", keys_db_->MI_PackageID(0))
        << "MI - Returned package Id for non-existant key.";

  //  add keys
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), package_id, private_key,
              public_key)) << "Failed to add key " << i << ".";
    ASSERT_EQ(0, keys_db_->MI_AddKeys(i, package_id, private_key,
              public_key)) << "MI - Failed to add key " << i << ".";
  }

  //  get package Id
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    ASSERT_EQ(package_id, keys_db_->GetPackageID(base::itos(i)))
              << "Failed to get package ID for key " << i << ".";
    ASSERT_EQ(package_id, keys_db_->MI_PackageID(i))
              << "MI - Failed to get package ID for key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_GetPrivateKey) {
  //  create db1
  int result = -1;
  boost::scoped_ptr<maidsafe::KeyAtlas> keys_db_(
      new maidsafe::KeyAtlas(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  //  try to get non-existant private key
  ASSERT_EQ("", keys_db_->GetPrivateKey(base::itos(0)))
            << "Returned private key for non-existant key.";
  ASSERT_EQ("", keys_db_->MI_PrivateKey(0))
            << "MI - Returned private key for non-existant key.";

  //  add keys
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), package_id, private_key,
              public_key)) << "Failed to add key " << i << ".";
    ASSERT_EQ(0, keys_db_->MI_AddKeys(i, package_id, private_key,
              public_key)) << "MI - Failed to add key " << i << ".";
  }

  //  get private key
  for (int i = 0; i < 11; i++) {
    std::string private_key = "Private Key " + base::itos(i);
    ASSERT_EQ(private_key, keys_db_->GetPrivateKey(base::itos(i)))
              << "Failed to get private key for key " << i << ".";
    ASSERT_EQ(private_key, keys_db_->MI_PrivateKey(i))
              << "MI - Failed to get private key for key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_GetPublicKey) {
  //  create db1
  int result = -1;
  boost::scoped_ptr<maidsafe::KeyAtlas> keys_db_(
      new maidsafe::KeyAtlas(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  //  try to get non-existant public key
  ASSERT_EQ("", keys_db_->GetPublicKey(base::itos(0)))
            << "Returned public key for non-existant key.";
  ASSERT_EQ("", keys_db_->MI_PrivateKey(0))
            << "MI - Returned public key for non-existant key.";

  //  add keys
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), package_id, private_key,
              public_key)) << "Failed to add key " << i << ".";
    ASSERT_EQ(0, keys_db_->MI_AddKeys(i, package_id, private_key,
              public_key)) << "MI - Failed to add key " << i << ".";
  }

  //  get public key
  for (int i = 0; i < 11; i++) {
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(public_key, keys_db_->GetPublicKey(base::itos(i)))
              << "Failed to get public key for key " << i << ".";
    ASSERT_EQ(public_key, keys_db_->MI_PublicKey(i))
              << "MI - Failed to get public key for key " << i << ".";
    }
}

TEST_F(KeyAtlasTest, BEH_MAID_RemoveKeys) {
  //  create db1
  int result = -1;
  boost::scoped_ptr<maidsafe::KeyAtlas> keys_db_(
      new maidsafe::KeyAtlas(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  //  add keys
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), package_id, private_key,
              public_key)) << "Failed to add key " << i << ".";
    ASSERT_EQ(0, keys_db_->MI_AddKeys(i, package_id, private_key,
              public_key)) << "MI - Failed to add key " << i << ".";
  }

  //  remove keys
  for (int i = 0; i < 11; i++) {
    ASSERT_EQ(0, keys_db_->RemoveKeys(base::itos(i)))
              << "Failed to remove key " << i << ".";
    ASSERT_EQ(0, keys_db_->MI_RemoveKeys(i))
              << "MI - Failed to remove key " << i << ".";
  }

  for (int i = 0; i < 11; i++) {
    ASSERT_EQ("", keys_db_->GetPublicKey(base::itos(i)))
              << "Failed to remove public key for key " << i << ".";
    ASSERT_EQ("", keys_db_->GetPrivateKey(base::itos(i)))
              << "Failed to remove private key for key " << i << ".";
    ASSERT_EQ("", keys_db_->GetPackageID(base::itos(i)))
              << "Failed to remove package ID for key " << i << ".";
    // MI ops
    ASSERT_EQ("", keys_db_->MI_PackageID(i))
              << "MI - Failed to remove public key for key " << i << ".";
    ASSERT_EQ("", keys_db_->MI_PackageID(i))
              << "MI - Failed to remove private key for key " << i << ".";
    ASSERT_EQ("", keys_db_->MI_PackageID(i))
              << "MI - Failed to remove package ID for key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_GetKeyRing) {
  //  create db1
  int result = -1;
  boost::scoped_ptr<maidsafe::KeyAtlas> keys_db_(
      new maidsafe::KeyAtlas(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  //  add keys
  for (int i = 0; i < 7; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), package_id, private_key,
              public_key)) << "Failed to add key " << i << ".";
    ASSERT_EQ(0, keys_db_->MI_AddKeys(i, package_id, private_key,
              public_key)) << "MI - Failed to add key " << i << ".";
  }

  //  get keyring and check keys
  std::list<Key_Type> keyring;
  keys_db_->GetKeyRing(&keyring);
  ASSERT_EQ(static_cast<unsigned int>(7), keyring.size())
            << "Keyring list size is not equal to the number of IDs.";
  std::list<maidsafe::KeyAtlasRow> MI_keyring;
  keys_db_->MI_GetKeyRing(&MI_keyring);
  ASSERT_EQ(static_cast<unsigned int>(7), MI_keyring.size())
            << "Keyring list size is not equal to the number of IDs.";
  ASSERT_EQ(keys_db_->MI_KeyRingSize(), MI_keyring.size())
            << "Keyring list size is not equal to the number of IDs.";

  for (int i = 0; i < 7; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    bool found_key = false;
    for (std::list<maidsafe::KeyAtlasRow>::iterator it = MI_keyring.begin();
        it != MI_keyring.end(); it++) {
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
  //  create db1
  int result = -1;
  boost::scoped_ptr<maidsafe::KeyAtlas> keys_db_(
      new maidsafe::KeyAtlas(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  //  add keys
  for (int i = 0; i < 11; i++) {
    std::string package_id = "Package ID " + base::itos(i);
    std::string private_key = "Private Key " + base::itos(i);
    std::string public_key = "Public Key " + base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), package_id, private_key,
              public_key)) << "Failed to add key " << i << ".";
    ASSERT_EQ(0, keys_db_->MI_AddKeys(i, package_id, private_key,
              public_key)) << "MI - Failed to add key " << i << ".";
  }

  //  amend keys & check keys were correctly updated
  for (int i = 0; i < 11; i++) {
    std::string updated_package_id = "Updated Package ID " + base::itos(i);
    std::string updated_private_key = "Updated Private Key " + base::itos(i);
    std::string updated_public_key = "Updated Public Key " + base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), updated_package_id,
              updated_private_key, updated_public_key)) <<
              "Failed to update key " << i << ".";
    ASSERT_EQ(updated_package_id, keys_db_->GetPackageID(base::itos(i)))
              << "Failed to get package ID for key " << i << ".";
    ASSERT_EQ(updated_private_key, keys_db_->GetPrivateKey(base::itos(i)))
              << "Failed to get private key for key " << i << ".";
    ASSERT_EQ(updated_private_key, keys_db_->GetPrivateKey(base::itos(i)))
              << "Failed to get private key for key " << i << ".";

    ASSERT_EQ(0, keys_db_->MI_AddKeys(i, updated_package_id,
              updated_private_key, updated_public_key)) <<
              "MI - Failed to update key " << i << ".";
    ASSERT_EQ(updated_package_id, keys_db_->MI_PackageID(i))
              << "Failed to get package ID for key " << i << ".";
    ASSERT_EQ(updated_private_key, keys_db_->MI_PrivateKey(i))
              << "Failed to get private key for key " << i << ".";
    ASSERT_EQ(updated_private_key, keys_db_->MI_PrivateKey(i))
              << "Failed to get private key for key " << i << ".";
  }
}

