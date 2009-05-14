#include <gtest/gtest.h>

#include "boost/filesystem.hpp"
#include "boost/scoped_ptr.hpp"

#include "base/utils.h"
#include "maidsafe/client/keyatlas.h"

namespace fs=boost::filesystem;
using namespace maidsafe;

class KeyAtlasTest : public testing::Test {
public:
KeyAtlasTest() : db_name1_(".DbTest/1.db") {}
  protected:
    void SetUp(){
      fs::create_directory(".DbTest");
      db_name1_ = ".DbTest/1.db";
    }
    void TearDown() {
      fs::remove_all(".DbTest");
    }

  std::string db_name1_;
};


TEST_F(KeyAtlasTest, BEH_MAID_CreateKeysDb) {
  int result_ = -1;
  boost::scoped_ptr<KeyAtlas> keys_db_(new KeyAtlas(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";
}

TEST_F(KeyAtlasTest, BEH_MAID_ConnectKeysDb) {
  //  try to connect to non-existant db
  {
    int result_ = -1;
    boost::scoped_ptr<KeyAtlas> keys_db_(new KeyAtlas("Non-existant db", CONNECT, &result_));
    ASSERT_NE(0, result_) << "Db creation incorrectly returned result 0";
    ASSERT_FALSE(fs::exists("Non-existant db")) << "Db was not created.";
  }

  //  create db1
  {
    int result_ = -1;
    boost::scoped_ptr<KeyAtlas> keys_db_(new KeyAtlas(db_name1_, CREATE, &result_));
    ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
    ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";
  }

  //  try to connect to db1
  {
    int result_ = -1;
    boost::scoped_ptr<KeyAtlas> keys_db_(new KeyAtlas(db_name1_, CONNECT, &result_));
    ASSERT_EQ(0, result_) << "Db connection returned result " << result_ << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_AddKeys) {
  //  create db1
  int result_ = -1;
  boost::scoped_ptr<KeyAtlas> keys_db_(new KeyAtlas(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  //  add keys
  for (int i=0; i<11; i++) {
    std::string package_id_ = "Package ID "+base::itos(i);
    std::string private_key_ = "Private Key "+base::itos(i);
    std::string public_key_ = "Public Key "+base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), package_id_, private_key_, public_key_))\
      << "Failed to add key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_GetPackageID) {
  //  create db1
  int result_ = -1;
  boost::scoped_ptr<KeyAtlas> keys_db_(new KeyAtlas(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  //  try to get non-existant package Id
  ASSERT_EQ("", keys_db_->GetPackageID(base::itos(0)))\
    << "Returned package Id for non-existant key.";

  //  add keys
  for (int i=0; i<11; i++) {
    std::string package_id_ = "Package ID "+base::itos(i);
    std::string private_key_ = "Private Key "+base::itos(i);
    std::string public_key_ = "Public Key "+base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), package_id_, private_key_, public_key_))\
      << "Failed to add key " << i << ".";
  }

  //  get package Id
  for (int i=0; i<11; i++) {
    std::string package_id_ = "Package ID "+base::itos(i);
    ASSERT_EQ(package_id_, keys_db_->GetPackageID(base::itos(i)))\
      << "Failed to get package ID for key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_GetPrivateKey) {
  //  create db1
  int result_ = -1;
  boost::scoped_ptr<KeyAtlas> keys_db_(new KeyAtlas(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  //  try to get non-existant private key
  ASSERT_EQ("", keys_db_->GetPrivateKey(base::itos(0)))\
    << "Returned private key for non-existant key.";

  //  add keys
  for (int i=0; i<11; i++) {
    std::string package_id_ = "Package ID "+base::itos(i);
    std::string private_key_ = "Private Key "+base::itos(i);
    std::string public_key_ = "Public Key "+base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), package_id_, private_key_, public_key_))\
      << "Failed to add key " << i << ".";
  }

  //  get private key
  for (int i=0; i<11; i++) {
    std::string private_key_ = "Private Key "+base::itos(i);
    ASSERT_EQ(private_key_, keys_db_->GetPrivateKey(base::itos(i)))\
      << "Failed to get private key for key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_GetPublicKey) {
  //  create db1
  int result_ = -1;
  boost::scoped_ptr<KeyAtlas> keys_db_(new KeyAtlas(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  //  try to get non-existant public key
  ASSERT_EQ("", keys_db_->GetPublicKey(base::itos(0)))\
    << "Returned public key for non-existant key.";

  //  add keys
  for (int i=0; i<11; i++) {
    std::string package_id_ = "Package ID "+base::itos(i);
    std::string private_key_ = "Private Key "+base::itos(i);
    std::string public_key_ = "Public Key "+base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), package_id_, private_key_, public_key_))\
      << "Failed to add key " << i << ".";
  }

  //  get public key
  for (int i=0; i<11; i++) {
    std::string public_key_ = "Public Key "+base::itos(i);
    ASSERT_EQ(public_key_, keys_db_->GetPublicKey(base::itos(i)))\
      << "Failed to get public key for key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_RemoveKeys) {
  //  create db1
  int result_ = -1;
  boost::scoped_ptr<KeyAtlas> keys_db_(new KeyAtlas(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  //  add keys
  for (int i=0; i<11; i++) {
    std::string package_id_ = "Package ID "+base::itos(i);
    std::string private_key_ = "Private Key "+base::itos(i);
    std::string public_key_ = "Public Key "+base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), package_id_, private_key_, public_key_))\
      << "Failed to add key " << i << ".";
  }

  //  remove keys
  for (int i=0; i<11; i++) {
    ASSERT_EQ(0, keys_db_->RemoveKeys(base::itos(i)))\
      << "Failed to remove key " << i << ".";
  }

  for (int i=0; i<11; i++) {
    std::string public_key_ = "Public Key "+base::itos(i);
    std::string private_key_ = "Private Key "+base::itos(i);
    std::string package_id_ = "Package ID "+base::itos(i);
    ASSERT_EQ("", keys_db_->GetPublicKey(base::itos(i)))\
      << "Failed to remove public key for key " << i << ".";
    ASSERT_EQ("", keys_db_->GetPrivateKey(base::itos(i)))\
      << "Failed to remove private key for key " << i << ".";
    ASSERT_EQ("", keys_db_->GetPackageID(base::itos(i)))\
      << "Failed to remove package ID for key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_GetKeyRing) {
  //  create db1
  int result_ = -1;
  boost::scoped_ptr<KeyAtlas> keys_db_(new KeyAtlas(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  //  add keys
  for (int i=0; i<7; i++) {
    std::string package_id_ = "Package ID "+base::itos(i);
    std::string private_key_ = "Private Key "+base::itos(i);
    std::string public_key_ = "Public Key "+base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), package_id_, private_key_, public_key_))\
      << "Failed to add key " << i << ".";
  }

  //  get keyring and check keys
  std::list<Key_Type>keyring_;
  keys_db_->GetKeyRing(&keyring_);
  ASSERT_EQ(static_cast<unsigned int>(7), keyring_.size()) << "Keyring list size is not equal to the number of IDs.";

  for (int i=0; i<7; i++) {
    std::string package_id_ = "Package ID "+base::itos(i);
    std::string private_key_ = "Private Key "+base::itos(i);
    std::string public_key_ = "Public Key "+base::itos(i);
    bool found_key_ = false;
    for (std::list<Key_Type>::iterator it_=keyring_.begin(); it_!=keyring_.end(); it_++) {
      if (it_->package_type == i) {
        found_key_ = true;
        ASSERT_EQ(package_id_, it_->id) << "Failed to match package Id of key " << i << ".";
        ASSERT_EQ(private_key_, it_->private_key) << "Failed to match private key of key " << i << ".";
        ASSERT_EQ(public_key_, it_->public_key) << "Failed to match public key of key " << i << ".";
      }
    }
    ASSERT_TRUE(found_key_) << "Failed to match package type of key " << i << ".";
  }
}

TEST_F(KeyAtlasTest, BEH_MAID_AmendKeys) {
  //  create db1
  int result_ = -1;
  boost::scoped_ptr<KeyAtlas> keys_db_(new KeyAtlas(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  //  add keys
  for (int i=0; i<11; i++) {
    std::string package_id_ = "Package ID "+base::itos(i);
    std::string private_key_ = "Private Key "+base::itos(i);
    std::string public_key_ = "Public Key "+base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), package_id_, private_key_, public_key_))\
      << "Failed to add key " << i << ".";
  }

  //  amend keys & check keys were correctly updated
  for (int i=0; i<11; i++) {
    std::string updated_package_id_ = "Updated Package ID "+base::itos(i);
    std::string updated_private_key_ = "Updated Private Key "+base::itos(i);
    std::string updated_public_key_ = "Updated Public Key "+base::itos(i);
    ASSERT_EQ(0, keys_db_->AddKeys(base::itos(i), updated_package_id_, \
      updated_private_key_, updated_public_key_)) << "Failed to update key " << i << ".";
    ASSERT_EQ(updated_package_id_, keys_db_->GetPackageID(base::itos(i)))\
      << "Failed to get package ID for key " << i << ".";
    ASSERT_EQ(updated_private_key_, keys_db_->GetPrivateKey(base::itos(i)))\
      << "Failed to get private key for key " << i << ".";
    ASSERT_EQ(updated_private_key_, keys_db_->GetPrivateKey(base::itos(i)))\
      << "Failed to get private key for key " << i << ".";
  }
}

