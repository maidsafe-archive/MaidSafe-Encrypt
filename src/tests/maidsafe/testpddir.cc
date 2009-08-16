/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  none
* Version:      1.0
* Created:      2009-08-13-00.35.48
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
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/utils.h>

#include "maidsafe/client/pddir.h"

namespace fs = boost::filesystem;

namespace maidsafe {

class PdDirTest : public testing::Test {
 public:
  PdDirTest() : db_name1_(".DbTest/1.db") {}
 protected:
  void SetUp() {
    if (fs::exists(".DbTest"))
      fs::remove_all(".DbTest");
    fs::create_directory(".DbTest");
    db_name1_ = ".DbTest/1.db";
  }
  void TearDown() {
    fs::remove_all(".DbTest");
  }
  std::string db_name1_;
};

void PrepareMDM(const int32_t id,
                        const std::string &display_name,
                        const itemtype &type,
                        const std::string &file_hash,
                        const std::string &stats,
                        const std::string &tag,
                        const uint32_t &file_size_high,
                        const uint32_t &file_size_low,
                        const uint32_t &creation_time,
                        const uint32_t &last_modified,
                        const uint32_t &last_access,
                        std::string &ser_mdm) {
  MetaDataMap mdm;
  mdm.set_id(id);
  mdm.set_display_name(display_name);
  mdm.set_type(type);
  mdm.add_file_hash(file_hash);
  mdm.set_stats(stats);
  mdm.set_tag(tag);
  mdm.set_file_size_high(file_size_high);
  mdm.set_file_size_low(file_size_low);
  mdm.set_creation_time(creation_time);
  mdm.set_last_modified(last_modified);
  mdm.set_last_access(last_access);
  mdm.SerializeToString(&ser_mdm);
}

void PrepareDMap(const std::string &file_hash, std::string &ser_dm) {
  // Creating DataMap
  DataMap dm;
  dm.set_file_hash(file_hash);
  dm.add_chunk_name(base::RandomString(64));
  dm.add_chunk_name(base::RandomString(64));
  dm.add_chunk_name(base::RandomString(64));
  dm.add_encrypted_chunk_name(base::RandomString(64));
  dm.add_encrypted_chunk_name(base::RandomString(64));
  dm.add_encrypted_chunk_name(base::RandomString(64));
  dm.SerializeToString(&ser_dm);
}


TEST_F(PdDirTest, BEH_MAID_CreateDb) {
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";
}

TEST_F(PdDirTest, BEH_MAID_ConnectDb) {
  // try to connect to non-existant db
  {
    int result_ = -1;
    boost::scoped_ptr<PdDir>
        da_(new PdDir("Non-existant db", CONNECT, &result_));
    ASSERT_NE(0, result_) << "Db creation incorrectly returned result 0";
    ASSERT_FALSE(fs::exists("Non-existant db")) << "Db was not created.";
  }

  // create db1
  {
    int result_ = -1;
    boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
    ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
    ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";
  }

  // try to connect to db1
  {
    int result_ = -1;
    boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CONNECT, &result_));
    ASSERT_EQ(0, result_) << "Db connection returned result " << result_ << ".";
  }
}

TEST_F(PdDirTest, BEH_MAID_AddElement) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name_ = "File.file";
  std::string file_hash_ = "File Hash";
  std::string ser_mdm1_ = "", ser_dm_ = "";
  PrepareMDM(-2, file_name_, REGULAR_FILE, file_hash_, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash_, ser_dm_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm_)) <<
      "File was not added to db1.";

  // add directory
  std::string dir_name_ = "Directory";
  std::string dir_key_ = "Dir Key";
  std::string ser_mdm2_ = "";
  PrepareMDM(-2, dir_name_, DIRECTORY, "", "Stats2", "Tag2", 0, 0, 3, 0,
      0, ser_mdm2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm2_, "", dir_key_)) <<
      "Directory was not added to db1.";
}

TEST_F(PdDirTest, BEH_MAID_GetIdFromName) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file1
  std::string file_name1_ = "File1.file";
  std::string file_hash1_ = "File Hash1";
  std::string ser_mdm1_ = "", ser_dm1_ = "";
  PrepareMDM(-2, file_name1_, REGULAR_FILE, file_hash1_, "Stats1",
      "Tag1", 0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash1_, ser_dm1_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm1_)) <<
      "File1 was not added to db1.";

  // add file2
  std::string file_name2_ = "File2.file";
  std::string file_hash2_ = "File Hash2";
  std::string ser_mdm2_ = "", ser_dm2_ = "";
  PrepareMDM(-2, file_name2_, REGULAR_FILE, file_hash2_, "Stats2",
      "Tag2", 0, 3, 4, 0, 0, ser_mdm2_);
  PrepareDMap(file_hash2_, ser_dm2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm2_, ser_dm2_)) <<
      "File2 was not added to db1.";

  // add file3
  std::string file_name3_ = "File3.file";
  std::string file_hash3_ = "File Hash3";
  std::string ser_mdm3_ = "", ser_dm3_ = "";
  PrepareMDM(-2, file_name3_, REGULAR_FILE, file_hash3_, "Stats3",
      "Tag3", 0, 5, 6, 0, 0, ser_mdm3_);
  PrepareDMap(file_hash3_, ser_dm3_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm3_, ser_dm3_)) <<
      "File3 was not added to db1.";

  // get ids
  ASSERT_EQ(2, da_->GetIdFromName(file_name2_)) <<
      "Returned wrong id for file2.";
  ASSERT_EQ(3, da_->GetIdFromName(file_name3_)) <<
      "Returned wrong id for file3.";
  ASSERT_EQ(1, da_->GetIdFromName(file_name1_)) <<
      "Returned wrong id for file1.";
  ASSERT_LT(da_->GetIdFromName("Non-existant File"), 0) <<
      "Returned ID for file which doesn't exist.";
}

TEST_F(PdDirTest, BEH_MAID_GetDirKey) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add directory1
  std::string dir_name1_ = "Directory1";
  std::string dir_key1_ = "Dir Key1";
  std::string ser_mdm1_ = "";
  PrepareMDM(-2, dir_name1_, DIRECTORY, "", "Stats1", "Tag1", 0, 0, 1,
      0, 0, ser_mdm1_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, "", dir_key1_)) <<
      "Directory1 was not added to db1.";

  // add directory2
  std::string dir_name2_ = "Directory2";
  std::string dir_key2_ = "Dir Key2";
  std::string ser_mdm2_ = "";
  PrepareMDM(-2, dir_name2_, DIRECTORY, "", "Stats2", "Tag2", 0, 0, 2,
      0, 0, ser_mdm2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm2_, "", dir_key2_)) <<
      "Directory2 was not added to db1.";

  // add directory3
  std::string dir_name3_ = "Directory3";
  std::string dir_key3_ = "Dir Key3";
  std::string ser_mdm3_ = "";
  PrepareMDM(-2, dir_name3_, DIRECTORY, "", "Stats3", "Tag3", 0, 0, 3,
      0, 0, ser_mdm3_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm3_, "", dir_key3_)) <<
      "Directory3 was not added to db1.";

  // get dir keys
  std::string dir_key_recovered1_ = "", dir_key_recovered2_ = "",
      dir_key_recovered3_ = "", dir_key_non_existant_ = "";
  ASSERT_EQ(0, da_->GetDirKey(dir_name3_, &dir_key_recovered3_)) <<
      "Failed to recover dir key for dir3.";
  ASSERT_EQ(dir_key3_, dir_key_recovered3_) <<
      "Returned wrong dir key for dir3.";
  ASSERT_EQ(0, da_->GetDirKey(dir_name1_, &dir_key_recovered1_)) <<
      "Failed to recover dir key for dir1.";
  ASSERT_EQ(dir_key1_, dir_key_recovered1_) <<
      "Returned wrong dir key for dir1.";
  ASSERT_EQ(0, da_->GetDirKey(dir_name2_, &dir_key_recovered2_)) <<
      "Failed to recover dir key for dir2.";
  ASSERT_EQ(dir_key2_, dir_key_recovered2_) <<
      "Returned wrong dir key for dir2.";

  ASSERT_NE(0, da_->GetDirKey("Non-existant Directory", &dir_key_non_existant_))
      << "Returned dir key for dir which doesn't exist.";
}

TEST_F(PdDirTest, BEH_MAID_DmExistsFromId) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name_ = "File.file";
  std::string file_hash_ = "File Hash";
  std::string ser_mdm1_ = "", ser_dm_ = "";
  PrepareMDM(-2, file_name_, REGULAR_FILE, file_hash_, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash_, ser_dm_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm_)) <<
      "File was not added to db1.";

  // check for existance of Dm
  int id = da_->GetIdFromName(file_name_);
  ASSERT_TRUE(da_->DataMapExists(id)) << "Didn't find existant Dm.";
  ASSERT_FALSE(da_->DataMapExists(id+1)) << "Found non-existant Dm.";
}

TEST_F(PdDirTest, BEH_MAID_DmExistsFromHash) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name_ = "File.file";
  std::string file_hash_ = "File Hash";
  std::string ser_mdm1_ = "", ser_dm_ = "";
  PrepareMDM(-2, file_name_, REGULAR_FILE, file_hash_, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash_, ser_dm_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm_)) <<
      "File was not added to db1.";

  // check for existance of Dm
  ASSERT_TRUE(da_->DataMapExists(file_hash_)) << "Didn't find existant Dm.";
  ASSERT_FALSE(da_->DataMapExists("Non-existant File Hash")) <<
      "Found non-existant Dm.";
}

TEST_F(PdDirTest, BEH_MAID_RemoveElement) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name_ = "File.file";
  std::string file_hash_ = "File Hash";
  std::string ser_mdm1_ = "", ser_dm_ = "";
  PrepareMDM(-2, file_name_, REGULAR_FILE, file_hash_, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash_, ser_dm_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm_)) <<
      "File was not added to db1.";

  // add directory
  std::string dir_name_ = "Directory";
  std::string dir_key_ = "Dir Key";
  std::string ser_mdm2_ = "";
  PrepareMDM(-2, dir_name_, DIRECTORY, "", "Stats2", "Tag2", 0, 0, 3, 0,
      0, ser_mdm2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm2_, "", dir_key_)) <<
      "Directory was not added to db1.";

  // get the elements' ids.  I mean, they're definitely there, but I'd better
  // just double check.
  int file_id_, dir_id_;
  file_id_ = da_->GetIdFromName(file_name_);
  dir_id_ = da_->GetIdFromName(dir_name_);
  ASSERT_EQ(1, file_id_) << "File returned wrong Id.";
  ASSERT_TRUE(da_->DataMapExists(file_id_)) << "Dm doesn't exist for file.";
  ASSERT_EQ(2, dir_id_) << "Dir returned wrong Id.";

  // remove elements
  ASSERT_EQ(0, da_->RemoveElement(file_name_)) << "Removed file incorrectly.";
  ASSERT_LT(da_->GetIdFromName(file_name_), 0) << "Didn't remove file.";
  ASSERT_FALSE(da_->DataMapExists(file_id_)) << "Dm still exists for file.";
  ASSERT_EQ(0, da_->RemoveElement(dir_name_)) << "Removed dir incorrectly.";
  ASSERT_LT(da_->GetIdFromName(dir_name_), 0) << "Didn't remove dir.";
  ASSERT_NE(0, da_->RemoveElement("Non-existant File")) <<
      "Removed non-existant file.";
}

TEST_F(PdDirTest, BEH_MAID_ListFolder) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file1
  std::string file_name1_ = "File1.file";
  std::string file_hash1_ = "File Hash1";
  std::string ser_mdm1_ = "", ser_dm1_ = "";
  PrepareMDM(-2, file_name1_, REGULAR_FILE, file_hash1_, "Stats1",
      "Tag1", 0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash1_, ser_dm1_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm1_)) <<
      "File1 was not added to db1.";

  // add file2
  std::string file_name2_ = "File2.file";
  std::string file_hash2_ = "File Hash2";
  std::string ser_mdm2_ = "", ser_dm2_ = "";
  PrepareMDM(-2, file_name2_, EMPTY_FILE, file_hash2_, "Stats2", "Tag2",
      0, 3, 4, 0, 0, ser_mdm2_);
  PrepareDMap(file_hash2_, ser_dm2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm2_, ser_dm2_)) <<
      "File2 was not added to db1.";

  // add file3
  std::string file_name3_ = "File3.file";
  std::string file_hash3_ = "File Hash3";
  std::string ser_mdm3_ = "", ser_dm3_ = "";
  PrepareMDM(-2, file_name3_, SMALL_FILE, file_hash3_, "Stats3", "Tag3",
      0, 5, 6, 0, 0, ser_mdm3_);
  PrepareDMap(file_hash3_, ser_dm3_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm3_, ser_dm3_)) <<
      "File3 was not added to db1.";

  // add directory1
  std::string dir_name1_ = "Directory1";
  std::string dir_key1_ = "Dir Key1";
  std::string ser_mdm4_ = "";
  PrepareMDM(-2, dir_name1_, DIRECTORY, "", "Stats1", "Tag1", 0, 0, 1,
      0, 0, ser_mdm4_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm4_, "", dir_key1_)) <<
      "Directory1 was not added to db1.";

  // add directory2
  std::string dir_name2_ = "Directory2";
  std::string dir_key2_ = "Dir Key2";
  std::string ser_mdm5_ = "";
  PrepareMDM(-2, dir_name2_, EMPTY_DIRECTORY, "", "Stats2", "Tag2", 0,
      0, 2, 0, 0, ser_mdm5_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm5_, "", dir_key2_)) <<
      "Directory2 was not added to db1.";

  // add directory3
  std::string dir_name3_ = "Directory3";
  std::string dir_key3_ = "Dir Key3";
  std::string ser_mdm6_ = "";
  PrepareMDM(-2, dir_name3_, DIRECTORY, "", "Stats3", "Tag3", 0, 0, 3,
      0, 0, ser_mdm6_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm6_, "", dir_key3_)) <<
      "Directory3 was not added to db1.";

  // recover list of children
  std::map<std::string, itemtype> children_;
  ASSERT_EQ(0, da_->ListFolder(&children_)) << "Retrieved list incorrectly.";
  ASSERT_EQ(size_t(6), children_.size()) << "List size incorrect.";
  ASSERT_EQ(EMPTY_DIRECTORY, children_[dir_name2_]) <<
      "Error retrieving dir2 type.";
  ASSERT_EQ(SMALL_FILE, children_[file_name3_]) <<
      "Error retrieving file3 type.";
  ASSERT_EQ(REGULAR_FILE, children_[file_name1_]) <<
      "Error retrieving file1 type.";
  ASSERT_EQ(DIRECTORY, children_[dir_name1_]) << "Error retrieving dir1 type.";
  ASSERT_EQ(DIRECTORY, children_[dir_name3_]) << "Error retrieving dir3 type.";
  ASSERT_EQ(EMPTY_FILE, children_[file_name2_]) <<
      "Error retrieving file2 type.";
}

TEST_F(PdDirTest, BEH_MAID_ListSubDirs) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file1
  std::string file_name1_ = "File1.file";
  std::string file_hash1_ = "File Hash1";
  std::string ser_mdm1_ = "", ser_dm1_ = "";
  PrepareMDM(-2, file_name1_, REGULAR_FILE, file_hash1_, "Stats1",
      "Tag1", 0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash1_, ser_dm1_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm1_)) <<
      "File1 was not added to db1.";

  // add file2
  std::string file_name2_ = "File2.file";
  std::string file_hash2_ = "File Hash2";
  std::string ser_mdm2_ = "", ser_dm2_ = "";
  PrepareMDM(-2, file_name2_, EMPTY_FILE, file_hash2_, "Stats2", "Tag2",
      0, 3, 4, 0, 0, ser_mdm2_);
  PrepareDMap(file_hash2_, ser_dm2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm2_, ser_dm2_)) <<
      "File2 was not added to db1.";

  // add file3
  std::string file_name3_ = "File3.file";
  std::string file_hash3_ = "File Hash3";
  std::string ser_mdm3_ = "", ser_dm3_ = "";
  PrepareMDM(-2, file_name3_, SMALL_FILE, file_hash3_, "Stats3", "Tag3",
      0, 5, 6, 0, 0, ser_mdm3_);
  PrepareDMap(file_hash3_, ser_dm3_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm3_, ser_dm3_)) <<
      "File3 was not added to db1.";

  // add directory1
  std::string dir_name1_ = "Directory1";
  std::string dir_key1_ = "Dir Key1";
  std::string ser_mdm4_ = "";
  PrepareMDM(-2, dir_name1_, DIRECTORY, "", "Stats1", "Tag1", 0, 0, 1,
      0, 0, ser_mdm4_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm4_, "", dir_key1_)) <<
      "Directory1 was not added to db1.";

  // add directory2
  std::string dir_name2_ = "Directory2";
  std::string dir_key2_ = "Dir Key2";
  std::string ser_mdm5_ = "";
  PrepareMDM(-2, dir_name2_, EMPTY_DIRECTORY, "", "Stats2", "Tag2", 0,
      0, 2, 0, 0, ser_mdm5_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm5_, "", dir_key2_)) <<
      "Directory2 was not added to db1.";

  // add directory3
  std::string dir_name3_ = "Directory3";
  std::string dir_key3_ = "Dir Key3";
  std::string ser_mdm6_ = "";
  PrepareMDM(-2, dir_name3_, DIRECTORY, "", "Stats3", "Tag3", 0, 0, 3,
      0, 0, ser_mdm6_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm6_, "", dir_key3_)) <<
      "Directory3 was not added to db1.";

  // recover list of subdirs
  std::vector<std::string> subdirs_;
  ASSERT_EQ(0, da_->ListSubDirs(&subdirs_)) << "Retrieved list incorrectly.";
  ASSERT_EQ(size_t(3), subdirs_.size()) << "List size incorrect.";
}

TEST_F(PdDirTest, BEH_MAID_GetDmFromHash) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file1
  std::string file_name1_ = "File1.file";
  std::string file_hash1_ = "File Hash1";
  std::string ser_mdm1_ = "", ser_dm1_ = "";
  PrepareMDM(-2, file_name1_, REGULAR_FILE, file_hash1_, "Stats1",
      "Tag1", 0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash1_, ser_dm1_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm1_)) <<
      "File1 was not added to db1.";

  // add file2
  std::string file_name2_ = "File2.file";
  std::string file_hash2_ = "File Hash2";
  std::string ser_mdm2_ = "", ser_dm2_ = "";
  PrepareMDM(-2, file_name2_, EMPTY_FILE, file_hash2_, "Stats2", "Tag2",
      0, 3, 4, 0, 0, ser_mdm2_);
  PrepareDMap(file_hash2_, ser_dm2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm2_, ser_dm2_)) <<
      "File2 was not added to db1.";

  // add file3
  std::string file_name3_ = "File3.file";
  std::string file_hash3_ = "File Hash3";
  std::string ser_mdm3_ = "", ser_dm3_ = "";
  PrepareMDM(-2, file_name3_, SMALL_FILE, file_hash3_, "Stats3", "Tag3",
      0, 5, 6, 0, 0, ser_mdm3_);
  PrepareDMap(file_hash3_, ser_dm3_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm3_, ser_dm3_)) <<
      "File3 was not added to db1.";

  // get serialised Dms
  std::string ser_dm_recovered1_ = "", ser_dm_recovered2_ = "";
  std::string ser_dm_recovered3_ = "", ser_dm_non_existant_ = "";
  ASSERT_EQ(0, da_->GetDataMapFromHash(file_hash3_, &ser_dm_recovered3_)) <<
      "Retrieved ser_dm for file3 incorrectly.";
  ASSERT_EQ(ser_dm3_, ser_dm_recovered3_) << "Returned wrong ser_dm for file3.";
  ASSERT_EQ(0, da_->GetDataMapFromHash(file_hash1_, &ser_dm_recovered1_)) <<
      "Retrieved ser_dm for file1 incorrectly.";
  ASSERT_EQ(ser_dm1_, ser_dm_recovered1_) << "Returned wrong ser_dm for file1.";
  ASSERT_EQ(0, da_->GetDataMapFromHash(file_hash2_, &ser_dm_recovered2_)) <<
      "Retrieved ser_dm for file2 incorrectly.";
  ASSERT_EQ(ser_dm2_, ser_dm_recovered2_) << "Returned wrong ser_dm for file2.";
  ASSERT_LT(da_->GetDataMapFromHash("Non-existant File Hash",
      &ser_dm_non_existant_), 0) <<
      "Returned ser_dm for file which doesn't exist.";
}

TEST_F(PdDirTest, BEH_MAID_GetDmFromFileName) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file1
  std::string file_name1_ = "File1.file";
  std::string file_hash1_ = "File Hash1";
  std::string ser_mdm1_ = "", ser_dm1_ = "";
  PrepareMDM(-2, file_name1_, REGULAR_FILE, file_hash1_, "Stats1",
      "Tag1", 0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash1_, ser_dm1_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm1_)) <<
      "File1 was not added to db1.";

  // add file2
  std::string file_name2_ = "File2.file";
  std::string file_hash2_ = "File Hash2";
  std::string ser_mdm2_ = "", ser_dm2_ = "";
  PrepareMDM(-2, file_name2_, EMPTY_FILE, file_hash2_, "Stats2", "Tag2",
      0, 3, 4, 0, 0, ser_mdm2_);
  PrepareDMap(file_hash2_, ser_dm2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm2_, ser_dm2_)) <<
      "File2 was not added to db1.";

  // add file3
  std::string file_name3_ = "File3.file";
  std::string file_hash3_ = "File Hash3";
  std::string ser_mdm3_ = "", ser_dm3_ = "";
  PrepareMDM(-2, file_name3_, SMALL_FILE, file_hash3_, "Stats3", "Tag3",
      0, 5, 6, 0, 0, ser_mdm3_);
  PrepareDMap(file_hash3_, ser_dm3_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm3_, ser_dm3_)) <<
      "File3 was not added to db1.";

  // get serialised Dms
  std::string ser_dm_recovered1_ = "", ser_dm_recovered2_ = "";
  std::string ser_dm_recovered3_ = "", ser_dm_non_existant_ = "";
  ASSERT_EQ(0, da_->GetDataMap(file_name1_, &ser_dm_recovered1_)) <<
      "Retrieved ser_dm for file1 incorrectly.";
  ASSERT_EQ(ser_dm1_, ser_dm_recovered1_) << "Returned wrong ser_dm for file1.";
  ASSERT_EQ(0, da_->GetDataMap(file_name3_, &ser_dm_recovered3_)) <<
      "Retrieved ser_dm for file3 incorrectly.";
  ASSERT_EQ(ser_dm3_, ser_dm_recovered3_) << "Returned wrong ser_dm for file3.";
  ASSERT_EQ(0, da_->GetDataMap(file_name2_, &ser_dm_recovered2_)) <<
      "Retrieved ser_dm for file2 incorrectly.";
  ASSERT_EQ(ser_dm2_, ser_dm_recovered2_) << "Returned wrong ser_dm for file2.";
  ASSERT_LT(da_->GetDataMap("Non-existant File", &ser_dm_non_existant_), 0) <<
      "Returned ser_dm for file which doesn't exist.";
}

TEST_F(PdDirTest, BEH_MAID_GetMdm) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file1
  std::string file_name1_ = "File1.file";
  std::string file_hash1_ = "File Hash1";
  std::string ser_mdm1_ = "", ser_dm1_ = "";
  PrepareMDM(-2, file_name1_, REGULAR_FILE, file_hash1_, "Stats1",
      "Tag1", 0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash1_, ser_dm1_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm1_)) <<
      "File1 was not added to db1.";

  // add file2
  std::string file_name2_ = "File2.file";
  std::string file_hash2_ = "File Hash2";
  std::string ser_mdm2_ = "", ser_dm2_ = "";
  PrepareMDM(-2, file_name2_, EMPTY_FILE, file_hash2_, "Stats2", "Tag2",
      0, 3, 4, 0, 0, ser_mdm2_);
  PrepareDMap(file_hash2_, ser_dm2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm2_, ser_dm2_)) <<
      "File2 was not added to db1.";

  // add directory3
  std::string dir_name3_ = "Directory3";
  std::string dir_key3_ = "Dir Key3";
  std::string ser_mdm3_ = "";
  PrepareMDM(-2, dir_name3_, DIRECTORY, "", "Stats3", "Tag3", 0, 0, 5,
      0, 0, ser_mdm3_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm3_, "", dir_key3_)) <<
      "Directory3 was not added to db1.";

  // get serialised Mdms
  std::string ser_mdm_recovered1_ = "", ser_mdm_recovered2_ = "";
  std::string ser_mdm_recovered3_ = "", ser_mdm_non_existant_ = "";
  ASSERT_EQ(0, da_->GetMetaDataMap(file_name1_, &ser_mdm_recovered1_)) <<
      "Retrieved ser_mdm for file1 incorrectly.";
  ASSERT_EQ(0, da_->GetMetaDataMap(file_name2_, &ser_mdm_recovered2_)) <<
      "Retrieved ser_mdm for file2 incorrectly.";
  ASSERT_EQ(0, da_->GetMetaDataMap(dir_name3_, &ser_mdm_recovered3_)) <<
      "Retrieved ser_mdm for dir3 incorrectly.";
  ASSERT_LT(da_->GetMetaDataMap("Non-existant File",
      &ser_mdm_non_existant_), 0) <<
      "Returned ser_mdm for file which doesn't exist.";

  // parse Mdms and check
  MetaDataMap mdm1_, mdm2_, mdm3_, mdm_recovered1_, mdm_recovered2_;
  MetaDataMap mdm_recovered3_;
  ASSERT_TRUE(mdm1_.ParseFromString(ser_mdm1_)) << "Couldn't parse mdm1_.";
  ASSERT_TRUE(mdm2_.ParseFromString(ser_mdm2_)) << "Couldn't parse mdm2_.";
  ASSERT_TRUE(mdm3_.ParseFromString(ser_mdm3_)) << "Couldn't parse mdm3_.";
  ASSERT_TRUE(mdm_recovered1_.ParseFromString(ser_mdm_recovered1_)) <<
      "Couldn't parse mdm_recovered1_.";
  ASSERT_TRUE(mdm_recovered2_.ParseFromString(ser_mdm_recovered2_)) <<
      "Couldn't parse mdm_recovered2_.";
  ASSERT_TRUE(mdm_recovered3_.ParseFromString(ser_mdm_recovered3_)) <<
      "Couldn't parse mdm_recovered3_.";

  std::vector<MetaDataMap> mdm_;
  mdm_.push_back(mdm1_);
  mdm_.push_back(mdm2_);
  mdm_.push_back(mdm3_);
  std::vector<MetaDataMap> mdm_recovered_;
  mdm_recovered_.push_back(mdm_recovered1_);
  mdm_recovered_.push_back(mdm_recovered2_);
  mdm_recovered_.push_back(mdm_recovered3_);

  for (unsigned int i = 0; i < mdm_.size(); ++i) {
    ASSERT_EQ(mdm_[i].display_name(), mdm_recovered_[i].display_name()) <<
        "Display name has changed in mdm" << i << "_.";
    ASSERT_EQ(mdm_[i].type(), mdm_recovered_[i].type()) <<
        "File type has changed in mdm" << i << "_.";
    ASSERT_EQ(mdm_[i].file_hash(0), mdm_recovered_[i].file_hash(0)) <<
        "File hash has changed in mdm" << i << "_.";
    ASSERT_EQ(mdm_[i].stats(), mdm_recovered_[i].stats()) <<
        "Stats have changed in mdm" << i << "_.";
    ASSERT_EQ(mdm_[i].tag(), mdm_recovered_[i].tag()) <<
        "Tag has changed in mdm" << i << "_.";
    ASSERT_EQ(mdm_[i].file_size_high(), mdm_recovered_[i].file_size_high()) <<
        "file_size_high has changed in mdm" << i << "_.";
    ASSERT_EQ(mdm_[i].file_size_low(), mdm_recovered_[i].file_size_low()) <<
        "file_size_low has changed in mdm" << i << "_.";
    ASSERT_EQ(mdm_[i].creation_time(), mdm_recovered_[i].creation_time()) <<
        "Creation time has changed in mdm" << i << "_.";
    ASSERT_NE(mdm_[i].last_modified(), mdm_recovered_[i].last_modified()) <<
        "Last modified time has not changed in mdm" << i << "_.";
    ASSERT_NE(mdm_[i].last_access(), mdm_recovered_[i].last_access()) <<
        "Last access time has not changed in mdm" << i << "_.";
  }
}

TEST_F(PdDirTest, BEH_MAID_ModifyMdm) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file1
  std::string file_name1_ = "File1.file";
  std::string file_hash1_ = "File Hash1";
  std::string ser_mdm1_ = "", ser_dm1_ = "";
  PrepareMDM(-2, file_name1_, REGULAR_FILE, file_hash1_, "Stats1",
      "Tag1", 0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash1_, ser_dm1_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm1_)) <<
      "File1 was not added to db1.";

  // add file2
  std::string file_name2_ = "File2.file";
  std::string file_hash2_ = "File Hash2";
  std::string ser_mdm2_ = "", ser_dm2_ = "";
  PrepareMDM(-2, file_name2_, EMPTY_FILE, file_hash2_, "Stats2", "Tag2",
      0, 3, 4, 0, 0, ser_mdm2_);
  PrepareDMap(file_hash2_, ser_dm2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm2_, ser_dm2_)) <<
      "File2 was not added to db1.";

  // add directory3
  std::string dir_name3_ = "Directory3";
  std::string dir_key3_ = "Dir Key3";
  std::string ser_mdm3_ = "";
  PrepareMDM(-2, dir_name3_, DIRECTORY, "", "Stats3", "Tag3", 0, 0, 5,
      0, 0, ser_mdm3_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm3_, "", dir_key3_)) <<
      "Directory3 was not added to db1.";

  // modify file1
  std::string file_hash_new1_ = "New File Hash1";
  std::string ser_mdm_new1_ = "", ser_dm_new1_ = "";
  PrepareMDM(-2, file_name1_, SMALL_FILE, file_hash_new1_,
    "New Stats1", "New Tag1", 1, 2, 3, 0, 0, ser_mdm_new1_);
  PrepareDMap(file_hash_new1_, ser_dm_new1_);
  ASSERT_EQ(0, da_->ModifyMetaDataMap(ser_mdm_new1_, ser_dm_new1_)) <<
      "File1 Mdm was not updated.";

  // modify file2
  std::string file_hash_new2_ = "New File Hash2";
  std::string ser_mdm_new2_ = "", ser_dm_new2_ = "";
  PrepareMDM(-2, file_name2_, REGULAR_FILE, file_hash_new2_,
    "New Stats2", "New Tag2", 1, 4, 5, 0, 0, ser_mdm_new2_);
  PrepareDMap(file_hash_new2_, ser_dm_new2_);
  ASSERT_EQ(0, da_->ModifyMetaDataMap(ser_mdm_new2_, ser_dm_new2_)) <<
      "File2 Mdm was not updated.";

  // modify directory3
  std::string ser_mdm_new3_ = "";
  PrepareMDM(-2, dir_name3_, EMPTY_DIRECTORY, "", "New Stats3",
    "New Tag3", 0, 0, 5, 0, 0, ser_mdm_new3_);
  ASSERT_NE(0, da_->ModifyMetaDataMap(ser_mdm_new3_, "")) <<
      "Directory3 Mdm was updated.";

  // get serialised Mdms
  std::string ser_mdm_recovered1_ = "", ser_mdm_recovered2_ = "";
  std::string ser_mdm_recovered3_ = "";
  ASSERT_EQ(0, da_->GetMetaDataMap(file_name1_, &ser_mdm_recovered1_)) <<
      "Retrieved ser_mdm for file1 incorrectly.";
  ASSERT_EQ(0, da_->GetMetaDataMap(file_name2_, &ser_mdm_recovered2_)) <<
      "Retrieved ser_mdm for file2 incorrectly.";
  ASSERT_EQ(0, da_->GetMetaDataMap(dir_name3_, &ser_mdm_recovered3_)) <<
      "Retrieved ser_mdm for dir3 incorrectly.";

  // parse Mdms and check
  MetaDataMap mdm1_, mdm2_, mdm3_, mdm_new1_, mdm_new2_, mdm_new3_;
  MetaDataMap mdm_recovered1_, mdm_recovered2_, mdm_recovered3_;
  ASSERT_TRUE(mdm1_.ParseFromString(ser_mdm1_)) << "Couldn't parse mdm1_.";
  ASSERT_TRUE(mdm2_.ParseFromString(ser_mdm2_)) << "Couldn't parse mdm2_.";
  ASSERT_TRUE(mdm3_.ParseFromString(ser_mdm3_)) << "Couldn't parse mdm3_.";
  ASSERT_TRUE(mdm_new1_.ParseFromString(ser_mdm_new1_)) <<
      "Couldn't parse mdm_new1_.";
  ASSERT_TRUE(mdm_new2_.ParseFromString(ser_mdm_new2_)) <<
      "Couldn't parse mdm_new2_.";
  ASSERT_TRUE(mdm_new3_.ParseFromString(ser_mdm_new3_)) <<
      "Couldn't parse mdm_new3_.";
  ASSERT_TRUE(mdm_recovered1_.ParseFromString(ser_mdm_recovered1_)) <<
      "Couldn't parse mdm_recovered1_.";
  ASSERT_TRUE(mdm_recovered2_.ParseFromString(ser_mdm_recovered2_)) <<
      "Couldn't parse mdm_recovered2_.";
  ASSERT_TRUE(mdm_recovered3_.ParseFromString(ser_mdm_recovered3_)) <<
      "Couldn't parse mdm_recovered3_.";

  std::vector<MetaDataMap> mdm_;
  mdm_.push_back(mdm1_);
  mdm_.push_back(mdm2_);
  mdm_.push_back(mdm3_);
  std::vector<MetaDataMap> mdm_new_;
  mdm_new_.push_back(mdm_new1_);
  mdm_new_.push_back(mdm_new2_);
  mdm_new_.push_back(mdm_new3_);
  std::vector<MetaDataMap> mdm_recovered_;
  mdm_recovered_.push_back(mdm_recovered1_);
  mdm_recovered_.push_back(mdm_recovered2_);
  mdm_recovered_.push_back(mdm_recovered3_);

  for (unsigned int i = 0; i < mdm_.size(); ++i) {
    if (mdm_[i].type() <=  2) {  // ie a file, not a dir
      ASSERT_EQ(mdm_[i].display_name(), mdm_recovered_[i].display_name()) <<
          "Display name has changed in mdm" << i << "_.";
      ASSERT_EQ(mdm_new_[i].display_name(), mdm_recovered_[i].display_name()) <<
          "Display name has not updated correctly in mdm" << i << "_.";

      ASSERT_NE(mdm_[i].type(), mdm_recovered_[i].type()) <<
          "File type has not updated in mdm" << i << "_.";
      ASSERT_EQ(mdm_new_[i].type(), mdm_recovered_[i].type()) <<
          "File type has not updated correctly in mdm" << i << "_.";

      ASSERT_NE(mdm_[i].file_hash(0), mdm_recovered_[i].file_hash(0)) <<
          "File hash has not updated in mdm" << i << "_.";
      ASSERT_EQ(mdm_new_[i].file_hash(0), mdm_recovered_[i].file_hash(0)) <<
          "File hash has not updated correctly in mdm" << i << "_.";

      ASSERT_NE(mdm_[i].stats(), mdm_recovered_[i].stats()) <<
          "Stats have not updated in mdm" << i << "_.";
      ASSERT_EQ(mdm_new_[i].stats(), mdm_recovered_[i].stats()) <<
          "Stats have not updated correctly in mdm" << i << "_.";

      ASSERT_NE(mdm_[i].tag(), mdm_recovered_[i].tag()) <<
          "Tag has not updated in mdm" << i << "_.";
      ASSERT_EQ(mdm_new_[i].tag(), mdm_recovered_[i].tag()) <<
          "Tag has not updated correctly in mdm" << i << "_.";

      ASSERT_NE(mdm_[i].file_size_high(), mdm_recovered_[i].file_size_high()) <<
          "file_size_high has not updated in mdm" << i << "_.";
      ASSERT_EQ(mdm_new_[i].file_size_high(),
          mdm_recovered_[i].file_size_high()) <<
          "file_size_high has not updated correctly in mdm" << i << "_.";

      ASSERT_NE(mdm_[i].file_size_low(), mdm_recovered_[i].file_size_low()) <<
          "file_size_low has not updated in mdm" << i << "_.";
      ASSERT_EQ(mdm_new_[i].file_size_low(), mdm_recovered_[i].file_size_low())
          << "file_size_low has not updated correctly in mdm" << i << "_.";

      ASSERT_EQ(mdm_[i].creation_time(), mdm_recovered_[i].creation_time()) <<
          "Creation time has changed in mdm" << i << "_.";
      ASSERT_NE(mdm_new_[i].creation_time(), mdm_recovered_[i].creation_time())
          << "Creation time has not updated correctly in mdm" << i << "_.";
    } else {
    ASSERT_EQ(mdm_[i].display_name(), mdm_recovered_[i].display_name()) <<
        "Display name has changed in mdm" << i << "_.";
    ASSERT_EQ(mdm_[i].type(), mdm_recovered_[i].type()) <<
        "File type has changed in mdm" << i << "_.";
    ASSERT_EQ(mdm_[i].file_hash(0), mdm_recovered_[i].file_hash(0)) <<
        "File hash has changed in mdm" << i << "_.";
    ASSERT_EQ(mdm_[i].stats(), mdm_recovered_[i].stats()) <<
        "Stats have changed in mdm" << i << "_.";
    ASSERT_EQ(mdm_[i].tag(), mdm_recovered_[i].tag()) <<
        "Tag has changed in mdm" << i << "_.";
    ASSERT_EQ(mdm_[i].file_size_high(), mdm_recovered_[i].file_size_high()) <<
        "file_size_high has changed in mdm" << i << "_.";
    ASSERT_EQ(mdm_[i].file_size_low(), mdm_recovered_[i].file_size_low()) <<
        "file_size_low has changed in mdm" << i << "_.";
    ASSERT_EQ(mdm_[i].creation_time(), mdm_recovered_[i].creation_time()) <<
        "Creation time has changed in mdm" << i << "_.";
    ASSERT_NE(mdm_[i].last_modified(), mdm_recovered_[i].last_modified()) <<
        "Last modified time has not changed in mdm" << i << "_.";
    ASSERT_NE(mdm_[i].last_access(), mdm_recovered_[i].last_access()) <<
        "Last access time has not changed in mdm" << i << "_.";
    }
  }
}

TEST_F(PdDirTest, BEH_MAID_ChangeCtime) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name_ = "File.file";
  std::string file_hash_ = "File Hash";
  std::string ser_mdm1_ = "", ser_dm_ = "";
  PrepareMDM(-2, file_name_, REGULAR_FILE, file_hash_, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash_, ser_dm_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm_)) <<
      "File was not added to db1.";

  // add directory
  std::string dir_name_ = "Directory";
  std::string dir_key_ = "Dir Key";
  std::string ser_mdm2_ = "";
  PrepareMDM(-2, dir_name_, DIRECTORY, "", "Stats2", "Tag2", 0, 0, 3, 0,
      0, ser_mdm2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm2_, "", dir_key_)) <<
      "Directory was not added to db1.";

  // get current value for creation times
  std::string ser_mdm_before1_ = "", ser_mdm_before2_ = "";
  std::string ser_mdm_after1_ = "", ser_mdm_after2_ = "";
  MetaDataMap mdm_before1_, mdm_before2_, mdm_after1_, mdm_after2_;
  boost::uint32_t file_time_before_, dir_time_before_, file_time_after_;
  boost::uint32_t dir_time_after_;
  ASSERT_EQ(0, da_->GetMetaDataMap(file_name_, &ser_mdm_before1_)) <<
      "Retrieved ser_mdm for file incorrectly.";
  ASSERT_EQ(0, da_->GetMetaDataMap(dir_name_, &ser_mdm_before2_)) <<
      "Retrieved ser_mdm for dir incorrectly.";
  ASSERT_TRUE(mdm_before1_.ParseFromString(ser_mdm_before1_)) <<
      "Couldn't parse mdm_before1_.";
  ASSERT_TRUE(mdm_before2_.ParseFromString(ser_mdm_before2_)) <<
      "Couldn't parse mdm_before2_.";
  file_time_before_ = mdm_before1_.creation_time();
  dir_time_before_ = mdm_before2_.creation_time();

  // change creation time to current time
  ASSERT_EQ(0, da_->ChangeCtime(file_name_)) <<
      "Failed to change creation time for file.";
  ASSERT_EQ(0, da_->ChangeCtime(dir_name_)) <<
      "Failed to change creation time for dir.";
  ASSERT_NE(0, da_->ChangeCtime("Non-existant File")) <<
      "Changed creation time for non-existant file.";

  // get current value for creation times
  ASSERT_EQ(0, da_->GetMetaDataMap(file_name_, &ser_mdm_after1_)) <<
      "Retrieved ser_mdm for file incorrectly.";
  ASSERT_EQ(0, da_->GetMetaDataMap(dir_name_, &ser_mdm_after2_)) <<
      "Retrieved ser_mdm for dir incorrectly.";
  ASSERT_TRUE(mdm_after1_.ParseFromString(ser_mdm_after1_)) <<
      "Couldn't parse mdm_after1_.";
  ASSERT_TRUE(mdm_after2_.ParseFromString(ser_mdm_after2_)) <<
      "Couldn't parse mdm_after2_.";
  file_time_after_ = mdm_after1_.creation_time();
  dir_time_after_ = mdm_after2_.creation_time();
  ASSERT_NE(file_time_before_, file_time_after_) <<
      "Creation time for file has not updated.";
  ASSERT_NE(dir_time_before_, dir_time_after_) <<
      "Creation time for file has not updated.";
}

TEST_F(PdDirTest, BEH_MAID_ChangeMtime) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name_ = "File.file";
  std::string file_hash_ = "File Hash";
  std::string ser_mdm1_ = "", ser_dm_ = "";
  PrepareMDM(-2, file_name_, REGULAR_FILE, file_hash_, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash_, ser_dm_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm_)) <<
      "File was not added to db1.";

  // add directory
  std::string dir_name_ = "Directory";
  std::string dir_key_ = "Dir Key";
  std::string ser_mdm2_ = "";
  PrepareMDM(-2, dir_name_, DIRECTORY, "", "Stats2", "Tag2", 0, 0, 3, 0,
      0, ser_mdm2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm2_, "", dir_key_)) <<
      "Directory was not added to db1.";

  // get current value for last_modified times
  std::string ser_mdm_before1_ = "", ser_mdm_before2_ = "";
  std::string ser_mdm_after1_ = "", ser_mdm_after2_ = "";
  MetaDataMap mdm_before1_, mdm_before2_, mdm_after1_, mdm_after2_;
  boost::uint32_t file_time_before_, dir_time_before_, file_time_after_;
  boost::uint32_t dir_time_after_;
  ASSERT_EQ(0, da_->GetMetaDataMap(file_name_, &ser_mdm_before1_)) <<
      "Retrieved ser_mdm for file incorrectly.";
  ASSERT_EQ(0, da_->GetMetaDataMap(dir_name_, &ser_mdm_before2_)) <<
      "Retrieved ser_mdm for dir incorrectly.";
  ASSERT_TRUE(mdm_before1_.ParseFromString(ser_mdm_before1_)) <<
      "Couldn't parse mdm_before1_.";
  ASSERT_TRUE(mdm_before2_.ParseFromString(ser_mdm_before2_)) <<
      "Couldn't parse mdm_before2_.";
  file_time_before_ = mdm_before1_.last_modified();
  dir_time_before_ = mdm_before2_.last_modified();

  // std::cout << "File time before: " << file_time_before_ << std::endl;
  // std::cout << "Dir time before: " << dir_time_before_ << std::endl;

  // wait 2 seconds
  // std::cout << "Waiting";
  for (int i = 0; i < 20; ++i) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    // std::cout << ".";
  }
  // std::cout << std::endl;

  // change modified time to current time
  ASSERT_EQ(0, da_->ChangeMtime(file_name_)) <<
      "Failed to change last_modified time for file.";
  ASSERT_EQ(0, da_->ChangeMtime(dir_name_)) <<
      "Failed to change last_modified time for dir.";
  ASSERT_NE(0, da_->ChangeMtime("Non-existant File")) <<
      "Changed last_modified time for non-existant file.";

  // get current value for last_modified times
  ASSERT_EQ(0, da_->GetMetaDataMap(file_name_, &ser_mdm_after1_)) <<
      "Retrieved ser_mdm for file incorrectly.";
  ASSERT_EQ(0, da_->GetMetaDataMap(dir_name_, &ser_mdm_after2_)) <<
      "Retrieved ser_mdm for dir incorrectly.";
  ASSERT_TRUE(mdm_after1_.ParseFromString(ser_mdm_after1_)) <<
      "Couldn't parse mdm_after1_.";
  ASSERT_TRUE(mdm_after2_.ParseFromString(ser_mdm_after2_)) <<
      "Couldn't parse mdm_after2_.";
  file_time_after_ = mdm_after1_.last_modified();
  dir_time_after_ = mdm_after2_.last_modified();

  // std::cout << "File time after: " << file_time_after_ << std::endl;
  // std::cout << "Dir time after: " << dir_time_after_ << std::endl;

  ASSERT_NE(file_time_before_, file_time_after_) <<
      "last_modified time for file has not updated.";
  ASSERT_NE(dir_time_before_, dir_time_after_) <<
      "last_modified time for file has not updated.";
}

TEST_F(PdDirTest, BEH_MAID_ChangeAtime) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name_ = "File.file";
  std::string file_hash_ = "File Hash";
  std::string ser_mdm1_ = "", ser_dm_ = "";
  PrepareMDM(-2, file_name_, REGULAR_FILE, file_hash_, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash_, ser_dm_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm_)) <<
      "File was not added to db1.";

  // add directory
  std::string dir_name_ = "Directory";
  std::string dir_key_ = "Dir Key";
  std::string ser_mdm2_ = "";
  PrepareMDM(-2, dir_name_, DIRECTORY, "", "Stats2", "Tag2", 0, 0, 3, 0,
      0, ser_mdm2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm2_, "", dir_key_)) <<
      "Directory was not added to db1.";

  // get current value for last_access times
  std::string ser_mdm_before1_ = "", ser_mdm_before2_ = "";
  std::string ser_mdm_after1_ = "", ser_mdm_after2_ = "";
  MetaDataMap mdm_before1_, mdm_before2_, mdm_after1_, mdm_after2_;
  boost::uint32_t file_time_before_, dir_time_before_, file_time_after_;
  boost::uint32_t dir_time_after_;
  ASSERT_EQ(0, da_->GetMetaDataMap(file_name_, &ser_mdm_before1_)) <<
      "Retrieved ser_mdm for file incorrectly.";
  ASSERT_EQ(0, da_->GetMetaDataMap(dir_name_, &ser_mdm_before2_)) <<
      "Retrieved ser_mdm for dir incorrectly.";
  ASSERT_TRUE(mdm_before1_.ParseFromString(ser_mdm_before1_)) <<
      "Couldn't parse mdm_before1_.";
  ASSERT_TRUE(mdm_before2_.ParseFromString(ser_mdm_before2_)) <<
      "Couldn't parse mdm_before2_.";
  file_time_before_ = mdm_before1_.last_access();
  dir_time_before_ = mdm_before2_.last_access();

  // std::cout << "File time before: " << file_time_before_ << std::endl;
  // std::cout << "Dir time before: " << dir_time_before_ << std::endl;

  // wait 2 seconds
  // std::cout << "Waiting";
  for (int i = 0; i < 20; ++i) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    // std::cout << ".";
  }
  // std::cout << std::endl;

  // change last_access time to current time
  ASSERT_EQ(0, da_->ChangeAtime(file_name_)) <<
      "Failed to change last_access time for file.";
  ASSERT_EQ(0, da_->ChangeAtime(dir_name_)) <<
      "Failed to change last_access time for dir.";
  ASSERT_NE(0, da_->ChangeAtime("Non-existant File")) <<
      "Changed last_access time for non-existant file.";

  // get current value for last_access times
  ASSERT_EQ(0, da_->GetMetaDataMap(file_name_, &ser_mdm_after1_)) <<
      "Retrieved ser_mdm for file incorrectly.";
  ASSERT_EQ(0, da_->GetMetaDataMap(dir_name_, &ser_mdm_after2_)) <<
      "Retrieved ser_mdm for dir incorrectly.";
  ASSERT_TRUE(mdm_after1_.ParseFromString(ser_mdm_after1_)) <<
      "Couldn't parse mdm_after1_.";
  ASSERT_TRUE(mdm_after2_.ParseFromString(ser_mdm_after2_)) <<
      "Couldn't parse mdm_after2_.";
  file_time_after_ = mdm_after1_.last_access();
  dir_time_after_ = mdm_after2_.last_access();

//   std::cout << "File time after: " << file_time_after_ << std::endl;
//   std::cout << "Dir time after: " << dir_time_after_ << std::endl;

  ASSERT_NE(file_time_before_, file_time_after_) <<
      "last_access time for file has not updated.";
  ASSERT_NE(dir_time_before_, dir_time_after_) <<
      "last_access time for file has not updated.";
}

TEST_F(PdDirTest, BEH_MAID_ModifyViaAddElement) {
  // create db1
  int result_ = -1;
  boost::scoped_ptr<PdDir> da_(new PdDir(db_name1_, CREATE, &result_));
  ASSERT_EQ(0, result_) << "Db creation returned result " << result_ << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name_ = "File.file";
  std::string file_hash_ = "File Hash";
  std::string ser_mdm1_ = "", ser_dm_ = "";
  PrepareMDM(-2, file_name_, REGULAR_FILE, file_hash_, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1_);
  PrepareDMap(file_hash_, ser_dm_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm1_, ser_dm_)) <<
      "File was not added to db1.";

  // add directory
  std::string dir_name_ = "Directory";
  std::string dir_key_ = "Dir Key";
  std::string ser_mdm2_ = "";
  PrepareMDM(-2, dir_name_, EMPTY_DIRECTORY, "", "Stats2", "Tag2", 0, 0,
      3, 0, 0, ser_mdm2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm2_, "", dir_key_)) <<
      "Directory was not added to db1.";

  // modify file
  std::string file_hash_new_ = "New File Hash";
  std::string ser_mdm_new1_ = "", ser_dm_new1_ = "";
  PrepareMDM(-2, file_name_, SMALL_FILE, file_hash_new_,
    "New Stats1", "New Tag1", 1, 4, 5, 0, 0, ser_mdm_new1_);
  PrepareDMap(file_hash_new_, ser_dm_new1_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm_new1_, ser_dm_new1_)) <<
      "File Mdm was not updated.";

  // modify directory
  std::string ser_mdm_new2_ = "";
  PrepareMDM(-2, dir_name_, DIRECTORY, "", "New Stats2",
    "New Tag2", 0, 0, 6, 0, 0, ser_mdm_new2_);
  ASSERT_EQ(0, da_->AddElement(ser_mdm_new2_, "")) <<
      "Directory Mdm was not updated.";

  // get serialised Mdms
  std::string ser_mdm_recovered1_ = "", ser_mdm_recovered2_ = "";
  ASSERT_EQ(0, da_->GetMetaDataMap(file_name_, &ser_mdm_recovered1_)) <<
      "Retrieved ser_mdm for file1 incorrectly.";
  ASSERT_EQ(0, da_->GetMetaDataMap(dir_name_, &ser_mdm_recovered2_)) <<
      "Retrieved ser_mdm for file2 incorrectly.";

  // parse Mdms
  MetaDataMap mdm1_, mdm2_, mdm_new1_, mdm_new2_;
  MetaDataMap mdm_recovered1_, mdm_recovered2_;
  ASSERT_TRUE(mdm1_.ParseFromString(ser_mdm1_)) << "Couldn't parse mdm1_.";
  ASSERT_TRUE(mdm2_.ParseFromString(ser_mdm2_)) << "Couldn't parse mdm2_.";
  ASSERT_TRUE(mdm_new1_.ParseFromString(ser_mdm_new1_)) <<
      "Couldn't parse mdm_new1_.";
  ASSERT_TRUE(mdm_new2_.ParseFromString(ser_mdm_new2_)) <<
      "Couldn't parse mdm_new2_.";
  ASSERT_TRUE(mdm_recovered1_.ParseFromString(ser_mdm_recovered1_)) <<
      "Couldn't parse mdm_recovered1_.";
  ASSERT_TRUE(mdm_recovered2_.ParseFromString(ser_mdm_recovered2_)) <<
      "Couldn't parse mdm_recovered2_.";

  // check file updated
  ASSERT_EQ(mdm1_.display_name(), mdm_recovered1_.display_name()) <<
      "File display name has changed.";
  ASSERT_EQ(mdm_new1_.display_name(), mdm_recovered1_.display_name()) <<
      "File display name has not updated correctly.";

  ASSERT_NE(mdm1_.type(), mdm_recovered1_.type()) <<
      "File type has not updated.";
  ASSERT_EQ(mdm_new1_.type(), mdm_recovered1_.type()) <<
      "File type has not updated correctly.";

  ASSERT_NE(mdm1_.file_hash(0), mdm_recovered1_.file_hash(0)) <<
      "File hash has not updated.";
  ASSERT_EQ(mdm_new1_.file_hash(0), mdm_recovered1_.file_hash(0)) <<
      "File hash has not updated correctly.";

  ASSERT_NE(mdm1_.stats(), mdm_recovered1_.stats()) <<
      "File stats have not updated.";
  ASSERT_EQ(mdm_new1_.stats(), mdm_recovered1_.stats()) <<
      "File stats have not updated correctly.";

  ASSERT_NE(mdm1_.tag(), mdm_recovered1_.tag()) << "File tag has not updated.";
  ASSERT_EQ(mdm_new1_.tag(), mdm_recovered1_.tag()) <<
      "File tag has not updated correctly.";

  ASSERT_NE(mdm1_.file_size_high(), mdm_recovered1_.file_size_high()) <<
      "File file_size_high has not updated.";
  ASSERT_EQ(mdm_new1_.file_size_high(), mdm_recovered1_.file_size_high()) <<
      "File file_size_high has not updated correctly.";

  ASSERT_NE(mdm1_.file_size_low(), mdm_recovered1_.file_size_low()) <<
      "File file_size_low has not updated.";
  ASSERT_EQ(mdm_new1_.file_size_low(), mdm_recovered1_.file_size_low()) <<
      "File file_size_low has not updated correctly.";

  ASSERT_EQ(mdm1_.creation_time(), mdm_recovered1_.creation_time()) <<
      "File creation time has changed.";
  ASSERT_NE(mdm_new1_.creation_time(), mdm_recovered1_.creation_time()) <<
      "File creation time has not updated correctly.";

  // check dir updated
  ASSERT_EQ(mdm2_.display_name(), mdm_recovered2_.display_name()) <<
      "Dir display name has changed.";
  ASSERT_EQ(mdm_new2_.display_name(), mdm_recovered2_.display_name()) <<
      "Dir display name has not updated correctly.";

  ASSERT_NE(mdm2_.type(), mdm_recovered2_.type()) <<
      "Dir type has not updated.";
  ASSERT_EQ(mdm_new2_.type(), mdm_recovered2_.type()) <<
      "Dir type has not updated correctly.";

  ASSERT_NE(mdm2_.stats(), mdm_recovered2_.stats()) <<
      "Dir stats have not updated.";
  ASSERT_EQ(mdm_new2_.stats(), mdm_recovered2_.stats()) <<
      "Dir stats have not updated correctly.";

  ASSERT_NE(mdm2_.tag(), mdm_recovered2_.tag()) << "Dir tag has not updated.";
  ASSERT_EQ(mdm_new2_.tag(), mdm_recovered2_.tag()) <<
      "Dir tag has not updated correctly.";

  ASSERT_EQ(mdm2_.creation_time(), mdm_recovered2_.creation_time()) <<
      "Dir creation time has changed.";
  ASSERT_NE(mdm_new2_.creation_time(), mdm_recovered2_.creation_time()) <<
      "Dir creation time has not updated correctly.";
}
}  // namespace maidsafe
