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
#include <boost/scoped_ptr.hpp>

#include "maidsafe/client/filesystem/pddir.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace test {

class PdDirTest : public testing::Test {
 public:
  PdDirTest() : db_name1_(".DbTest/1.db") {}
 protected:
  void SetUp() {
    try {
      if (fs::exists(".DbTest"))
        fs::remove_all(".DbTest");
      fs::create_directory(".DbTest");
    }
    catch(...) {
      FAIL();
    }
    db_name1_ = ".DbTest/1.db";
  }
  void TearDown() {
    try {
      fs::remove_all(".DbTest");
    }
    catch(...) {}
  }
  std::string db_name1_;
};

void PrepareMDM(const boost::int32_t id,
                const std::string &display_name,
                const ItemType &type,
                const std::string &file_hash,
                const std::string &stats,
                const std::string &tag,
                const boost::uint32_t &file_size_high,
                const boost::uint32_t &file_size_low,
                const boost::uint32_t &creation_time,
                const boost::uint32_t &last_modified,
                const boost::uint32_t &last_access,
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
  encrypt::DataMap dm;
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
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";
}

TEST_F(PdDirTest, BEH_MAID_ConnectDb) {
  // try to connect to non-existent db
  {
    int result = -1;
    boost::scoped_ptr<PdDir>
        da(new PdDir("Non-existent db", CONNECT, &result));
    ASSERT_NE(0, result) << "Db creation incorrectly returned result 0";
    ASSERT_FALSE(fs::exists("Non-existent db")) << "Db was not created.";
  }

  // create db1
  {
    int result = -1;
    boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
    ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
    ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";
  }

  // try to connect to db1
  {
    int result = -1;
    boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CONNECT, &result));
    ASSERT_EQ(0, result) << "Db connection returned result " << result << ".";
  }
}

TEST_F(PdDirTest, BEH_MAID_AddElement) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name = "File.file";
  std::string file_hash = "File Hash";
  std::string ser_mdm1, ser_dm;
  PrepareMDM(-2, file_name, REGULAR_FILE, file_hash, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash, ser_dm);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm, "")) <<
      "File was not added to db1.";

  // add directory
  std::string dir_name = "Directory";
  std::string dir_key = "Dir Key";
  std::string ser_mdm2;
  PrepareMDM(-2, dir_name, DIRECTORY, "", "Stats2", "Tag2", 0, 0, 3, 0,
      0, ser_mdm2);
  ASSERT_EQ(0, da->AddElement(ser_mdm2, "", dir_key)) <<
      "Directory was not added to db1.";
}

TEST_F(PdDirTest, BEH_MAID_GetIdFromName) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file1
  std::string file_name1 = "File1.file";
  std::string file_hash1 = "File Hash1";
  std::string ser_mdm1, ser_dm1;
  PrepareMDM(-2, file_name1, REGULAR_FILE, file_hash1, "Stats1",
      "Tag1", 0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash1, ser_dm1);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm1, "")) <<
      "File1 was not added to db1.";

  // add file2
  std::string file_name2 = "File2.file";
  std::string file_hash2 = "File Hash2";
  std::string ser_mdm2, ser_dm2;
  PrepareMDM(-2, file_name2, REGULAR_FILE, file_hash2, "Stats2",
      "Tag2", 0, 3, 4, 0, 0, ser_mdm2);
  PrepareDMap(file_hash2, ser_dm2);
  ASSERT_EQ(0, da->AddElement(ser_mdm2, ser_dm2, "")) <<
      "File2 was not added to db1.";

  // add file3
  std::string file_name3 = "File3.file";
  std::string file_hash3 = "File Hash3";
  std::string ser_mdm3, ser_dm3;
  PrepareMDM(-2, file_name3, REGULAR_FILE, file_hash3, "Stats3",
      "Tag3", 0, 5, 6, 0, 0, ser_mdm3);
  PrepareDMap(file_hash3, ser_dm3);
  ASSERT_EQ(0, da->AddElement(ser_mdm3, ser_dm3, "")) <<
      "File3 was not added to db1.";

  // get ids
  ASSERT_EQ(2, da->GetIdFromName(file_name2)) <<
      "Returned wrong id for file2.";
  ASSERT_EQ(3, da->GetIdFromName(file_name3)) <<
      "Returned wrong id for file3.";
  ASSERT_EQ(1, da->GetIdFromName(file_name1)) <<
      "Returned wrong id for file1.";
  ASSERT_LT(da->GetIdFromName("Non-existent File"), 0) <<
      "Returned ID for file which doesn't exist.";
}

TEST_F(PdDirTest, BEH_MAID_GetDirKey) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add directory1
  std::string dir_name1 = "Directory1";
  std::string dir_key1 = "Dir Key1";
  std::string ser_mdm1;
  PrepareMDM(-2, dir_name1, DIRECTORY, "", "Stats1", "Tag1", 0, 0, 1,
      0, 0, ser_mdm1);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, "", dir_key1)) <<
      "Directory1 was not added to db1.";

  // add directory2
  std::string dir_name2 = "Directory2";
  std::string dir_key2 = "Dir Key2";
  std::string ser_mdm2;
  PrepareMDM(-2, dir_name2, DIRECTORY, "", "Stats2", "Tag2", 0, 0, 2,
      0, 0, ser_mdm2);
  ASSERT_EQ(0, da->AddElement(ser_mdm2, "", dir_key2)) <<
      "Directory2 was not added to db1.";

  // add directory3
  std::string dir_name3 = "Directory3";
  std::string dir_key3 = "Dir Key3";
  std::string ser_mdm3;
  PrepareMDM(-2, dir_name3, DIRECTORY, "", "Stats3", "Tag3", 0, 0, 3,
      0, 0, ser_mdm3);
  ASSERT_EQ(0, da->AddElement(ser_mdm3, "", dir_key3)) <<
      "Directory3 was not added to db1.";

  // get dir keys
  std::string dir_key_recovered1, dir_key_recovered2,
      dir_key_recovered3, dir_key_non_existent;
  ASSERT_EQ(0, da->GetDirKey(dir_name3, &dir_key_recovered3)) <<
      "Failed to recover dir key for dir3.";
  ASSERT_EQ(dir_key3, dir_key_recovered3) <<
      "Returned wrong dir key for dir3.";
  ASSERT_EQ(0, da->GetDirKey(dir_name1, &dir_key_recovered1)) <<
      "Failed to recover dir key for dir1.";
  ASSERT_EQ(dir_key1, dir_key_recovered1) <<
      "Returned wrong dir key for dir1.";
  ASSERT_EQ(0, da->GetDirKey(dir_name2, &dir_key_recovered2)) <<
      "Failed to recover dir key for dir2.";
  ASSERT_EQ(dir_key2, dir_key_recovered2) <<
      "Returned wrong dir key for dir2.";

  ASSERT_NE(0, da->GetDirKey("Non-existent Directory", &dir_key_non_existent))
      << "Returned dir key for dir which doesn't exist.";
}

TEST_F(PdDirTest, BEH_MAID_DmExistsFromId) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name = "File.file";
  std::string file_hash = "File Hash";
  std::string ser_mdm1, ser_dm;
  PrepareMDM(-2, file_name, REGULAR_FILE, file_hash, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash, ser_dm);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm, "")) <<
      "File was not added to db1.";

  // check for existance of Dm
  int id = da->GetIdFromName(file_name);
  ASSERT_TRUE(da->DataMapExists(id)) << "Didn't find existent Dm.";
  ASSERT_FALSE(da->DataMapExists(id+1)) << "Found non-existent Dm.";
}

TEST_F(PdDirTest, BEH_MAID_DmExistsFromHash) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name = "File.file";
  std::string file_hash = "File Hash";
  std::string ser_mdm1, ser_dm;
  PrepareMDM(-2, file_name, REGULAR_FILE, file_hash, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash, ser_dm);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm, "")) <<
      "File was not added to db1.";

  // check for existance of Dm
  ASSERT_TRUE(da->DataMapExists(file_hash)) << "Didn't find existent Dm.";
  ASSERT_FALSE(da->DataMapExists("Non-existent File Hash")) <<
      "Found non-existent Dm.";
}

TEST_F(PdDirTest, BEH_MAID_RemoveElement) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name = "File.file";
  std::string file_hash = "File Hash";
  std::string ser_mdm1, ser_dm;
  PrepareMDM(-2, file_name, REGULAR_FILE, file_hash, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash, ser_dm);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm, "")) <<
      "File was not added to db1.";

  // add directory
  std::string dir_name = "Directory";
  std::string dir_key = "Dir Key";
  std::string ser_mdm2;
  PrepareMDM(-2, dir_name, DIRECTORY, "", "Stats2", "Tag2", 0, 0, 3, 0,
      0, ser_mdm2);
  ASSERT_EQ(0, da->AddElement(ser_mdm2, "", dir_key)) <<
      "Directory was not added to db1.";

  // get the elements' ids.  I mean, they're definitely there, but I'd better
  // just double check.
  int file_id, dir_id;
  file_id = da->GetIdFromName(file_name);
  dir_id = da->GetIdFromName(dir_name);
  ASSERT_EQ(1, file_id) << "File returned wrong Id.";
  ASSERT_TRUE(da->DataMapExists(file_id)) << "Dm doesn't exist for file.";
  ASSERT_EQ(2, dir_id) << "Dir returned wrong Id.";

  // remove elements
  ASSERT_EQ(0, da->RemoveElement(file_name)) << "Removed file incorrectly.";
  ASSERT_LT(da->GetIdFromName(file_name), 0) << "Didn't remove file.";
  ASSERT_FALSE(da->DataMapExists(file_id)) << "Dm still exists for file.";
  ASSERT_EQ(0, da->RemoveElement(dir_name)) << "Removed dir incorrectly.";
  ASSERT_LT(da->GetIdFromName(dir_name), 0) << "Didn't remove dir.";
  ASSERT_NE(0, da->RemoveElement("Non-existent File")) <<
      "Removed non-existent file.";
}

TEST_F(PdDirTest, BEH_MAID_ListFolder) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file1
  std::string file_name1 = "File1.file";
  std::string file_hash1 = "File Hash1";
  std::string ser_mdm1, ser_dm1;
  PrepareMDM(-2, file_name1, REGULAR_FILE, file_hash1, "Stats1",
      "Tag1", 0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash1, ser_dm1);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm1, "")) <<
      "File1 was not added to db1.";

  // add file2
  std::string file_name2 = "File2.file";
  std::string file_hash2 = "File Hash2";
  std::string ser_mdm2, ser_dm2;
  PrepareMDM(-2, file_name2, EMPTY_FILE, file_hash2, "Stats2", "Tag2",
      0, 3, 4, 0, 0, ser_mdm2);
  PrepareDMap(file_hash2, ser_dm2);
  ASSERT_EQ(0, da->AddElement(ser_mdm2, ser_dm2, "")) <<
      "File2 was not added to db1.";

  // add file3
  std::string file_name3 = "File3.file";
  std::string file_hash3 = "File Hash3";
  std::string ser_mdm3, ser_dm3;
  PrepareMDM(-2, file_name3, SMALL_FILE, file_hash3, "Stats3", "Tag3",
      0, 5, 6, 0, 0, ser_mdm3);
  PrepareDMap(file_hash3, ser_dm3);
  ASSERT_EQ(0, da->AddElement(ser_mdm3, ser_dm3, "")) <<
      "File3 was not added to db1.";

  // add directory1
  std::string dir_name1 = "Directory1";
  std::string dir_key1 = "Dir Key1";
  std::string ser_mdm4;
  PrepareMDM(-2, dir_name1, DIRECTORY, "", "Stats1", "Tag1", 0, 0, 1,
      0, 0, ser_mdm4);
  ASSERT_EQ(0, da->AddElement(ser_mdm4, "", dir_key1)) <<
      "Directory1 was not added to db1.";

  // add directory2
  std::string dir_name2 = "Directory2";
  std::string dir_key2 = "Dir Key2";
  std::string ser_mdm5;
  PrepareMDM(-2, dir_name2, EMPTY_DIRECTORY, "", "Stats2", "Tag2", 0,
      0, 2, 0, 0, ser_mdm5);
  ASSERT_EQ(0, da->AddElement(ser_mdm5, "", dir_key2)) <<
      "Directory2 was not added to db1.";

  // add directory3
  std::string dir_name3 = "Directory3";
  std::string dir_key3 = "Dir Key3";
  std::string ser_mdm6;
  PrepareMDM(-2, dir_name3, DIRECTORY, "", "Stats3", "Tag3", 0, 0, 3,
      0, 0, ser_mdm6);
  ASSERT_EQ(0, da->AddElement(ser_mdm6, "", dir_key3)) <<
      "Directory3 was not added to db1.";

  // recover list of children
  std::map<fs::path, ItemType> children;
  ASSERT_EQ(0, da->ListFolder(&children)) << "Retrieved list incorrectly.";
  ASSERT_EQ(size_t(6), children.size()) << "List size incorrect.";
  ASSERT_EQ(EMPTY_DIRECTORY, children[dir_name2]) <<
      "Error retrieving dir2 type.";
  ASSERT_EQ(SMALL_FILE, children[file_name3]) <<
      "Error retrieving file3 type.";
  ASSERT_EQ(REGULAR_FILE, children[file_name1]) <<
      "Error retrieving file1 type.";
  ASSERT_EQ(DIRECTORY, children[dir_name1]) << "Error retrieving dir1 type.";
  ASSERT_EQ(DIRECTORY, children[dir_name3]) << "Error retrieving dir3 type.";
  ASSERT_EQ(EMPTY_FILE, children[file_name2]) <<
      "Error retrieving file2 type.";
}

TEST_F(PdDirTest, BEH_MAID_ListSubDirs) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file1
  std::string file_name1 = "File1.file";
  std::string file_hash1 = "File Hash1";
  std::string ser_mdm1, ser_dm1;
  PrepareMDM(-2, file_name1, REGULAR_FILE, file_hash1, "Stats1",
      "Tag1", 0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash1, ser_dm1);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm1, "")) <<
      "File1 was not added to db1.";

  // add file2
  std::string file_name2 = "File2.file";
  std::string file_hash2 = "File Hash2";
  std::string ser_mdm2, ser_dm2;
  PrepareMDM(-2, file_name2, EMPTY_FILE, file_hash2, "Stats2", "Tag2",
      0, 3, 4, 0, 0, ser_mdm2);
  PrepareDMap(file_hash2, ser_dm2);
  ASSERT_EQ(0, da->AddElement(ser_mdm2, ser_dm2, "")) <<
      "File2 was not added to db1.";

  // add file3
  std::string file_name3 = "File3.file";
  std::string file_hash3 = "File Hash3";
  std::string ser_mdm3, ser_dm3;
  PrepareMDM(-2, file_name3, SMALL_FILE, file_hash3, "Stats3", "Tag3",
      0, 5, 6, 0, 0, ser_mdm3);
  PrepareDMap(file_hash3, ser_dm3);
  ASSERT_EQ(0, da->AddElement(ser_mdm3, ser_dm3, "")) <<
      "File3 was not added to db1.";

  // add directory1
  std::string dir_name1 = "Directory1";
  std::string dir_key1 = "Dir Key1";
  std::string ser_mdm4;
  PrepareMDM(-2, dir_name1, DIRECTORY, "", "Stats1", "Tag1", 0, 0, 1,
      0, 0, ser_mdm4);
  ASSERT_EQ(0, da->AddElement(ser_mdm4, "", dir_key1)) <<
      "Directory1 was not added to db1.";

  // add directory2
  std::string dir_name2 = "Directory2";
  std::string dir_key2 = "Dir Key2";
  std::string ser_mdm5;
  PrepareMDM(-2, dir_name2, EMPTY_DIRECTORY, "", "Stats2", "Tag2", 0,
      0, 2, 0, 0, ser_mdm5);
  ASSERT_EQ(0, da->AddElement(ser_mdm5, "", dir_key2)) <<
      "Directory2 was not added to db1.";

  // add directory3
  std::string dir_name3 = "Directory3";
  std::string dir_key3 = "Dir Key3";
  std::string ser_mdm6;
  PrepareMDM(-2, dir_name3, DIRECTORY, "", "Stats3", "Tag3", 0, 0, 3,
      0, 0, ser_mdm6);
  ASSERT_EQ(0, da->AddElement(ser_mdm6, "", dir_key3)) <<
      "Directory3 was not added to db1.";

  // recover list of subdirs
  std::vector<fs::path> subdirs;
  ASSERT_EQ(0, da->ListSubDirs(&subdirs)) << "Retrieved list incorrectly.";
  ASSERT_EQ(size_t(3), subdirs.size()) << "List size incorrect.";
}

TEST_F(PdDirTest, BEH_MAID_GetDmFromHash) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file1
  std::string file_name1 = "File1.file";
  std::string file_hash1 = "File Hash1";
  std::string ser_mdm1, ser_dm1;
  PrepareMDM(-2, file_name1, REGULAR_FILE, file_hash1, "Stats1",
      "Tag1", 0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash1, ser_dm1);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm1, "")) <<
      "File1 was not added to db1.";

  // add file2
  std::string file_name2 = "File2.file";
  std::string file_hash2 = "File Hash2";
  std::string ser_mdm2, ser_dm2;
  PrepareMDM(-2, file_name2, EMPTY_FILE, file_hash2, "Stats2", "Tag2",
      0, 3, 4, 0, 0, ser_mdm2);
  PrepareDMap(file_hash2, ser_dm2);
  ASSERT_EQ(0, da->AddElement(ser_mdm2, ser_dm2, "")) <<
      "File2 was not added to db1.";

  // add file3
  std::string file_name3 = "File3.file";
  std::string file_hash3 = "File Hash3";
  std::string ser_mdm3, ser_dm3;
  PrepareMDM(-2, file_name3, SMALL_FILE, file_hash3, "Stats3", "Tag3",
      0, 5, 6, 0, 0, ser_mdm3);
  PrepareDMap(file_hash3, ser_dm3);
  ASSERT_EQ(0, da->AddElement(ser_mdm3, ser_dm3, "")) <<
      "File3 was not added to db1.";

  // get serialised Dms
  std::string ser_dm_recovered1, ser_dm_recovered2;
  std::string ser_dm_recovered3, ser_dm_non_existent;
  ASSERT_EQ(0, da->GetDataMapFromHash(file_hash3, &ser_dm_recovered3)) <<
      "Retrieved ser_dm for file3 incorrectly.";
  ASSERT_EQ(ser_dm3, ser_dm_recovered3) << "Returned wrong ser_dm for file3.";
  ASSERT_EQ(0, da->GetDataMapFromHash(file_hash1, &ser_dm_recovered1)) <<
      "Retrieved ser_dm for file1 incorrectly.";
  ASSERT_EQ(ser_dm1, ser_dm_recovered1) << "Returned wrong ser_dm for file1.";
  ASSERT_EQ(0, da->GetDataMapFromHash(file_hash2, &ser_dm_recovered2)) <<
      "Retrieved ser_dm for file2 incorrectly.";
  ASSERT_EQ(ser_dm2, ser_dm_recovered2) << "Returned wrong ser_dm for file2.";
  ASSERT_LT(da->GetDataMapFromHash("Non-existent File Hash",
      &ser_dm_non_existent), 0) <<
      "Returned ser_dm for file which doesn't exist.";
}

TEST_F(PdDirTest, BEH_MAID_GetDmFromFileName) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file1
  std::string file_name1 = "File1.file";
  std::string file_hash1 = "File Hash1";
  std::string ser_mdm1, ser_dm1;
  PrepareMDM(-2, file_name1, REGULAR_FILE, file_hash1, "Stats1",
      "Tag1", 0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash1, ser_dm1);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm1, "")) <<
      "File1 was not added to db1.";

  // add file2
  std::string file_name2 = "File2.file";
  std::string file_hash2 = "File Hash2";
  std::string ser_mdm2, ser_dm2;
  PrepareMDM(-2, file_name2, EMPTY_FILE, file_hash2, "Stats2", "Tag2",
      0, 3, 4, 0, 0, ser_mdm2);
  PrepareDMap(file_hash2, ser_dm2);
  ASSERT_EQ(0, da->AddElement(ser_mdm2, ser_dm2, "")) <<
      "File2 was not added to db1.";

  // add file3
  std::string file_name3 = "File3.file";
  std::string file_hash3 = "File Hash3";
  std::string ser_mdm3, ser_dm3;
  PrepareMDM(-2, file_name3, SMALL_FILE, file_hash3, "Stats3", "Tag3",
      0, 5, 6, 0, 0, ser_mdm3);
  PrepareDMap(file_hash3, ser_dm3);
  ASSERT_EQ(0, da->AddElement(ser_mdm3, ser_dm3, "")) <<
      "File3 was not added to db1.";

  // get serialised Dms
  std::string ser_dm_recovered1, ser_dm_recovered2;
  std::string ser_dm_recovered3, ser_dm_non_existent;
  ASSERT_EQ(0, da->GetDataMap(file_name1, &ser_dm_recovered1)) <<
      "Retrieved ser_dm for file1 incorrectly.";
  ASSERT_EQ(ser_dm1, ser_dm_recovered1) << "Returned wrong ser_dm for file1.";
  ASSERT_EQ(0, da->GetDataMap(file_name3, &ser_dm_recovered3)) <<
      "Retrieved ser_dm for file3 incorrectly.";
  ASSERT_EQ(ser_dm3, ser_dm_recovered3) << "Returned wrong ser_dm for file3.";
  ASSERT_EQ(0, da->GetDataMap(file_name2, &ser_dm_recovered2)) <<
      "Retrieved ser_dm for file2 incorrectly.";
  ASSERT_EQ(ser_dm2, ser_dm_recovered2) << "Returned wrong ser_dm for file2.";
  ASSERT_LT(da->GetDataMap("Non-existent File", &ser_dm_non_existent), 0) <<
      "Returned ser_dm for file which doesn't exist.";
}

TEST_F(PdDirTest, BEH_MAID_GetMdm) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file1
  std::string file_name1 = "File1.file";
  std::string file_hash1 = "File Hash1";
  std::string ser_mdm1, ser_dm1;
  PrepareMDM(-2, file_name1, REGULAR_FILE, file_hash1, "Stats1",
      "Tag1", 0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash1, ser_dm1);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm1, "")) <<
      "File1 was not added to db1.";

  // add file2
  std::string file_name2 = "File2.file";
  std::string file_hash2 = "File Hash2";
  std::string ser_mdm2, ser_dm2;
  PrepareMDM(-2, file_name2, EMPTY_FILE, file_hash2, "Stats2", "Tag2",
      0, 3, 4, 0, 0, ser_mdm2);
  PrepareDMap(file_hash2, ser_dm2);
  ASSERT_EQ(0, da->AddElement(ser_mdm2, ser_dm2, "")) <<
      "File2 was not added to db1.";

  // add directory3
  std::string dir_name3 = "Directory3";
  std::string dir_key3 = "Dir Key3";
  std::string ser_mdm3;
  PrepareMDM(-2, dir_name3, DIRECTORY, "", "Stats3", "Tag3", 0, 0, 5,
      0, 0, ser_mdm3);
  ASSERT_EQ(0, da->AddElement(ser_mdm3, "", dir_key3)) <<
      "Directory3 was not added to db1.";

  // get serialised Mdms
  std::string ser_mdm_recovered1, ser_mdm_recovered2;
  std::string ser_mdm_recovered3, ser_mdm_non_existent;
  ASSERT_EQ(0, da->GetMetaDataMap(file_name1, &ser_mdm_recovered1)) <<
      "Retrieved ser_mdm for file1 incorrectly.";
  ASSERT_EQ(0, da->GetMetaDataMap(file_name2, &ser_mdm_recovered2)) <<
      "Retrieved ser_mdm for file2 incorrectly.";
  ASSERT_EQ(0, da->GetMetaDataMap(dir_name3, &ser_mdm_recovered3)) <<
      "Retrieved ser_mdm for dir3 incorrectly.";
  ASSERT_LT(da->GetMetaDataMap("Non-existent File",
      &ser_mdm_non_existent), 0) <<
      "Returned ser_mdm for file which doesn't exist.";

  // parse Mdms and check
  MetaDataMap mdm1, mdm2, mdm3, mdm_recovered1, mdm_recovered2;
  MetaDataMap mdm_recovered3;
  ASSERT_TRUE(mdm1.ParseFromString(ser_mdm1)) << "Couldn't parse mdm1.";
  ASSERT_TRUE(mdm2.ParseFromString(ser_mdm2)) << "Couldn't parse mdm2.";
  ASSERT_TRUE(mdm3.ParseFromString(ser_mdm3)) << "Couldn't parse mdm3.";
  ASSERT_TRUE(mdm_recovered1.ParseFromString(ser_mdm_recovered1)) <<
      "Couldn't parse mdm_recovered1.";
  ASSERT_TRUE(mdm_recovered2.ParseFromString(ser_mdm_recovered2)) <<
      "Couldn't parse mdm_recovered2.";
  ASSERT_TRUE(mdm_recovered3.ParseFromString(ser_mdm_recovered3)) <<
      "Couldn't parse mdm_recovered3.";

  std::vector<MetaDataMap> mdm;
  mdm.push_back(mdm1);
  mdm.push_back(mdm2);
  mdm.push_back(mdm3);
  std::vector<MetaDataMap> mdm_recovered;
  mdm_recovered.push_back(mdm_recovered1);
  mdm_recovered.push_back(mdm_recovered2);
  mdm_recovered.push_back(mdm_recovered3);

  for (unsigned int i = 0; i < mdm.size(); ++i) {
    ASSERT_EQ(mdm[i].display_name(), mdm_recovered[i].display_name()) <<
        "Display name has changed in mdm" << i << ".";
    ASSERT_EQ(mdm[i].type(), mdm_recovered[i].type()) <<
        "File type has changed in mdm" << i << ".";
    ASSERT_EQ(mdm[i].file_hash(0), mdm_recovered[i].file_hash(0)) <<
        "File hash has changed in mdm" << i << ".";
    ASSERT_EQ(mdm[i].stats(), mdm_recovered[i].stats()) <<
        "Stats have changed in mdm" << i << ".";
    ASSERT_EQ(mdm[i].tag(), mdm_recovered[i].tag()) <<
        "Tag has changed in mdm" << i << ".";
    ASSERT_EQ(mdm[i].file_size_high(), mdm_recovered[i].file_size_high()) <<
        "file_size_high has changed in mdm" << i << ".";
    ASSERT_EQ(mdm[i].file_size_low(), mdm_recovered[i].file_size_low()) <<
        "file_size_low has changed in mdm" << i << ".";
    ASSERT_EQ(mdm[i].creation_time(), mdm_recovered[i].creation_time()) <<
        "Creation time has changed in mdm" << i << ".";
    ASSERT_NE(mdm[i].last_modified(), mdm_recovered[i].last_modified()) <<
        "Last modified time has not changed in mdm" << i << ".";
    ASSERT_NE(mdm[i].last_access(), mdm_recovered[i].last_access()) <<
        "Last access time has not changed in mdm" << i << ".";
  }
}

TEST_F(PdDirTest, BEH_MAID_ModifyMdm) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file1
  std::string file_name1 = "File1.file";
  std::string file_hash1 = "File Hash1";
  std::string ser_mdm1, ser_dm1;
  PrepareMDM(-2, file_name1, REGULAR_FILE, file_hash1, "Stats1",
      "Tag1", 0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash1, ser_dm1);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm1, "")) <<
      "File1 was not added to db1.";

  // add file2
  std::string file_name2 = "File2.file";
  std::string file_hash2 = "File Hash2";
  std::string ser_mdm2, ser_dm2;
  PrepareMDM(-2, file_name2, EMPTY_FILE, file_hash2, "Stats2", "Tag2",
      0, 3, 4, 0, 0, ser_mdm2);
  PrepareDMap(file_hash2, ser_dm2);
  ASSERT_EQ(0, da->AddElement(ser_mdm2, ser_dm2, "")) <<
      "File2 was not added to db1.";

  // add directory3
  std::string dir_name3 = "Directory3";
  std::string dir_key3 = "Dir Key3";
  std::string ser_mdm3;
  PrepareMDM(-2, dir_name3, DIRECTORY, "", "Stats3", "Tag3", 0, 0, 5,
      0, 0, ser_mdm3);
  ASSERT_EQ(0, da->AddElement(ser_mdm3, "", dir_key3)) <<
      "Directory3 was not added to db1.";

  // modify file1
  std::string file_hash_new1 = "New File Hash1";
  std::string ser_mdm_new1, ser_dm_new1;
  PrepareMDM(-2, file_name1, SMALL_FILE, file_hash_new1,
    "New Stats1", "New Tag1", 1, 2, 3, 0, 0, ser_mdm_new1);
  PrepareDMap(file_hash_new1, ser_dm_new1);
  ASSERT_EQ(0, da->ModifyMetaDataMap(ser_mdm_new1, ser_dm_new1)) <<
      "File1 Mdm was not updated.";

  // modify file2
  std::string file_hash_new2 = "New File Hash2";
  std::string ser_mdm_new2, ser_dm_new2;
  PrepareMDM(-2, file_name2, REGULAR_FILE, file_hash_new2,
    "New Stats2", "New Tag2", 1, 4, 5, 0, 0, ser_mdm_new2);
  PrepareDMap(file_hash_new2, ser_dm_new2);
  ASSERT_EQ(0, da->ModifyMetaDataMap(ser_mdm_new2, ser_dm_new2)) <<
      "File2 Mdm was not updated.";

  // modify directory3
  std::string ser_mdm_new3;
  PrepareMDM(-2, dir_name3, EMPTY_DIRECTORY, "", "New Stats3",
    "New Tag3", 0, 0, 5, 0, 0, ser_mdm_new3);
  ASSERT_NE(0, da->ModifyMetaDataMap(ser_mdm_new3, "")) <<
      "Directory3 Mdm was updated.";

  // get serialised Mdms
  std::string ser_mdm_recovered1, ser_mdm_recovered2;
  std::string ser_mdm_recovered3;
  ASSERT_EQ(0, da->GetMetaDataMap(file_name1, &ser_mdm_recovered1)) <<
      "Retrieved ser_mdm for file1 incorrectly.";
  ASSERT_EQ(0, da->GetMetaDataMap(file_name2, &ser_mdm_recovered2)) <<
      "Retrieved ser_mdm for file2 incorrectly.";
  ASSERT_EQ(0, da->GetMetaDataMap(dir_name3, &ser_mdm_recovered3)) <<
      "Retrieved ser_mdm for dir3 incorrectly.";

  // parse Mdms and check
  MetaDataMap mdm1, mdm2, mdm3, mdm_new1, mdm_new2, mdm_new3;
  MetaDataMap mdm_recovered1, mdm_recovered2, mdm_recovered3;
  ASSERT_TRUE(mdm1.ParseFromString(ser_mdm1)) << "Couldn't parse mdm1.";
  ASSERT_TRUE(mdm2.ParseFromString(ser_mdm2)) << "Couldn't parse mdm2.";
  ASSERT_TRUE(mdm3.ParseFromString(ser_mdm3)) << "Couldn't parse mdm3.";
  ASSERT_TRUE(mdm_new1.ParseFromString(ser_mdm_new1)) <<
      "Couldn't parse mdm_new1.";
  ASSERT_TRUE(mdm_new2.ParseFromString(ser_mdm_new2)) <<
      "Couldn't parse mdm_new2.";
  ASSERT_TRUE(mdm_new3.ParseFromString(ser_mdm_new3)) <<
      "Couldn't parse mdm_new3.";
  ASSERT_TRUE(mdm_recovered1.ParseFromString(ser_mdm_recovered1)) <<
      "Couldn't parse mdm_recovered1.";
  ASSERT_TRUE(mdm_recovered2.ParseFromString(ser_mdm_recovered2)) <<
      "Couldn't parse mdm_recovered2.";
  ASSERT_TRUE(mdm_recovered3.ParseFromString(ser_mdm_recovered3)) <<
      "Couldn't parse mdm_recovered3.";

  std::vector<MetaDataMap> mdm;
  mdm.push_back(mdm1);
  mdm.push_back(mdm2);
  mdm.push_back(mdm3);
  std::vector<MetaDataMap> mdm_new;
  mdm_new.push_back(mdm_new1);
  mdm_new.push_back(mdm_new2);
  mdm_new.push_back(mdm_new3);
  std::vector<MetaDataMap> mdm_recovered;
  mdm_recovered.push_back(mdm_recovered1);
  mdm_recovered.push_back(mdm_recovered2);
  mdm_recovered.push_back(mdm_recovered3);

  for (unsigned int i = 0; i < mdm.size(); ++i) {
    if (mdm[i].type() <=  2) {  // ie a file, not a dir
      ASSERT_EQ(mdm[i].display_name(), mdm_recovered[i].display_name()) <<
          "Display name has changed in mdm" << i << ".";
      ASSERT_EQ(mdm_new[i].display_name(), mdm_recovered[i].display_name()) <<
          "Display name has not updated correctly in mdm" << i << ".";

      ASSERT_NE(mdm[i].type(), mdm_recovered[i].type()) <<
          "File type has not updated in mdm" << i << ".";
      ASSERT_EQ(mdm_new[i].type(), mdm_recovered[i].type()) <<
          "File type has not updated correctly in mdm" << i << ".";

      ASSERT_NE(mdm[i].file_hash(0), mdm_recovered[i].file_hash(0)) <<
          "File hash has not updated in mdm" << i << ".";
      ASSERT_EQ(mdm_new[i].file_hash(0), mdm_recovered[i].file_hash(0)) <<
          "File hash has not updated correctly in mdm" << i << ".";

      ASSERT_NE(mdm[i].stats(), mdm_recovered[i].stats()) <<
          "Stats have not updated in mdm" << i << ".";
      ASSERT_EQ(mdm_new[i].stats(), mdm_recovered[i].stats()) <<
          "Stats have not updated correctly in mdm" << i << ".";

      ASSERT_NE(mdm[i].tag(), mdm_recovered[i].tag()) <<
          "Tag has not updated in mdm" << i << ".";
      ASSERT_EQ(mdm_new[i].tag(), mdm_recovered[i].tag()) <<
          "Tag has not updated correctly in mdm" << i << ".";

      ASSERT_NE(mdm[i].file_size_high(), mdm_recovered[i].file_size_high()) <<
          "file_size_high has not updated in mdm" << i << ".";
      ASSERT_EQ(mdm_new[i].file_size_high(),
          mdm_recovered[i].file_size_high()) <<
          "file_size_high has not updated correctly in mdm" << i << ".";

      ASSERT_NE(mdm[i].file_size_low(), mdm_recovered[i].file_size_low()) <<
          "file_size_low has not updated in mdm" << i << ".";
      ASSERT_EQ(mdm_new[i].file_size_low(), mdm_recovered[i].file_size_low())
          << "file_size_low has not updated correctly in mdm" << i << ".";

      ASSERT_EQ(mdm[i].creation_time(), mdm_recovered[i].creation_time()) <<
          "Creation time has changed in mdm" << i << ".";
      ASSERT_NE(mdm_new[i].creation_time(), mdm_recovered[i].creation_time())
          << "Creation time has not updated correctly in mdm" << i << ".";
    } else {
    ASSERT_EQ(mdm[i].display_name(), mdm_recovered[i].display_name()) <<
        "Display name has changed in mdm" << i << ".";
    ASSERT_EQ(mdm[i].type(), mdm_recovered[i].type()) <<
        "File type has changed in mdm" << i << ".";
    ASSERT_EQ(mdm[i].file_hash(0), mdm_recovered[i].file_hash(0)) <<
        "File hash has changed in mdm" << i << ".";
    ASSERT_EQ(mdm[i].stats(), mdm_recovered[i].stats()) <<
        "Stats have changed in mdm" << i << ".";
    ASSERT_EQ(mdm[i].tag(), mdm_recovered[i].tag()) <<
        "Tag has changed in mdm" << i << ".";
    ASSERT_EQ(mdm[i].file_size_high(), mdm_recovered[i].file_size_high()) <<
        "file_size_high has changed in mdm" << i << ".";
    ASSERT_EQ(mdm[i].file_size_low(), mdm_recovered[i].file_size_low()) <<
        "file_size_low has changed in mdm" << i << ".";
    ASSERT_EQ(mdm[i].creation_time(), mdm_recovered[i].creation_time()) <<
        "Creation time has changed in mdm" << i << ".";
    ASSERT_NE(mdm[i].last_modified(), mdm_recovered[i].last_modified()) <<
        "Last modified time has not changed in mdm" << i << ".";
    ASSERT_NE(mdm[i].last_access(), mdm_recovered[i].last_access()) <<
        "Last access time has not changed in mdm" << i << ".";
    }
  }
}

TEST_F(PdDirTest, BEH_MAID_ChangeCtime) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name = "File.file";
  std::string file_hash = "File Hash";
  std::string ser_mdm1, ser_dm;
  PrepareMDM(-2, file_name, REGULAR_FILE, file_hash, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash, ser_dm);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm, "")) <<
      "File was not added to db1.";

  // add directory
  std::string dir_name = "Directory";
  std::string dir_key = "Dir Key";
  std::string ser_mdm2;
  PrepareMDM(-2, dir_name, DIRECTORY, "", "Stats2", "Tag2", 0, 0, 3, 0,
      0, ser_mdm2);
  ASSERT_EQ(0, da->AddElement(ser_mdm2, "", dir_key)) <<
      "Directory was not added to db1.";

  // get current value for creation times
  std::string ser_mdm_before1, ser_mdm_before2;
  std::string ser_mdm_after1, ser_mdm_after2;
  MetaDataMap mdm_before1, mdm_before2, mdm_after1, mdm_after2;
  boost::uint32_t file_time_before, dir_time_before, file_time_after;
  boost::uint32_t dir_time_after;
  ASSERT_EQ(0, da->GetMetaDataMap(file_name, &ser_mdm_before1)) <<
      "Retrieved ser_mdm for file incorrectly.";
  ASSERT_EQ(0, da->GetMetaDataMap(dir_name, &ser_mdm_before2)) <<
      "Retrieved ser_mdm for dir incorrectly.";
  ASSERT_TRUE(mdm_before1.ParseFromString(ser_mdm_before1)) <<
      "Couldn't parse mdm_before1.";
  ASSERT_TRUE(mdm_before2.ParseFromString(ser_mdm_before2)) <<
      "Couldn't parse mdm_before2.";
  file_time_before = mdm_before1.creation_time();
  dir_time_before = mdm_before2.creation_time();

  // change creation time to current time
  ASSERT_EQ(0, da->ChangeCtime(file_name)) <<
      "Failed to change creation time for file.";
  ASSERT_EQ(0, da->ChangeCtime(dir_name)) <<
      "Failed to change creation time for dir.";
  ASSERT_NE(0, da->ChangeCtime("Non-existent File")) <<
      "Changed creation time for non-existent file.";

  // get current value for creation times
  ASSERT_EQ(0, da->GetMetaDataMap(file_name, &ser_mdm_after1)) <<
      "Retrieved ser_mdm for file incorrectly.";
  ASSERT_EQ(0, da->GetMetaDataMap(dir_name, &ser_mdm_after2)) <<
      "Retrieved ser_mdm for dir incorrectly.";
  ASSERT_TRUE(mdm_after1.ParseFromString(ser_mdm_after1)) <<
      "Couldn't parse mdm_after1.";
  ASSERT_TRUE(mdm_after2.ParseFromString(ser_mdm_after2)) <<
      "Couldn't parse mdm_after2.";
  file_time_after = mdm_after1.creation_time();
  dir_time_after = mdm_after2.creation_time();
  ASSERT_NE(file_time_before, file_time_after) <<
      "Creation time for file has not updated.";
  ASSERT_NE(dir_time_before, dir_time_after) <<
      "Creation time for file has not updated.";
}

TEST_F(PdDirTest, BEH_MAID_ChangeMtime) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name = "File.file";
  std::string file_hash = "File Hash";
  std::string ser_mdm1, ser_dm;
  PrepareMDM(-2, file_name, REGULAR_FILE, file_hash, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash, ser_dm);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm, "")) <<
      "File was not added to db1.";

  // add directory
  std::string dir_name = "Directory";
  std::string dir_key = "Dir Key";
  std::string ser_mdm2;
  PrepareMDM(-2, dir_name, DIRECTORY, "", "Stats2", "Tag2", 0, 0, 3, 0,
      0, ser_mdm2);
  ASSERT_EQ(0, da->AddElement(ser_mdm2, "", dir_key)) <<
      "Directory was not added to db1.";

  // get current value for last_modified times
  std::string ser_mdm_before1, ser_mdm_before2;
  std::string ser_mdm_after1, ser_mdm_after2;
  MetaDataMap mdm_before1, mdm_before2, mdm_after1, mdm_after2;
  boost::uint32_t file_time_before, dir_time_before, file_time_after;
  boost::uint32_t dir_time_after;
  ASSERT_EQ(0, da->GetMetaDataMap(file_name, &ser_mdm_before1)) <<
      "Retrieved ser_mdm for file incorrectly.";
  ASSERT_EQ(0, da->GetMetaDataMap(dir_name, &ser_mdm_before2)) <<
      "Retrieved ser_mdm for dir incorrectly.";
  ASSERT_TRUE(mdm_before1.ParseFromString(ser_mdm_before1)) <<
      "Couldn't parse mdm_before1.";
  ASSERT_TRUE(mdm_before2.ParseFromString(ser_mdm_before2)) <<
      "Couldn't parse mdm_before2.";
  file_time_before = mdm_before1.last_modified();
  dir_time_before = mdm_before2.last_modified();

  // std::cout << "File time before: " << file_time_before << std::endl;
  // std::cout << "Dir time before: " << dir_time_before << std::endl;

  // wait 2 seconds
  // std::cout << "Waiting";
  for (int i = 0; i < 20; ++i) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    // std::cout << ".";
  }
  // std::cout << std::endl;

  // change modified time to current time
  ASSERT_EQ(0, da->ChangeMtime(file_name)) <<
      "Failed to change last_modified time for file.";
  ASSERT_EQ(0, da->ChangeMtime(dir_name)) <<
      "Failed to change last_modified time for dir.";
  ASSERT_NE(0, da->ChangeMtime("Non-existent File")) <<
      "Changed last_modified time for non-existent file.";

  // get current value for last_modified times
  ASSERT_EQ(0, da->GetMetaDataMap(file_name, &ser_mdm_after1)) <<
      "Retrieved ser_mdm for file incorrectly.";
  ASSERT_EQ(0, da->GetMetaDataMap(dir_name, &ser_mdm_after2)) <<
      "Retrieved ser_mdm for dir incorrectly.";
  ASSERT_TRUE(mdm_after1.ParseFromString(ser_mdm_after1)) <<
      "Couldn't parse mdm_after1.";
  ASSERT_TRUE(mdm_after2.ParseFromString(ser_mdm_after2)) <<
      "Couldn't parse mdm_after2.";
  file_time_after = mdm_after1.last_modified();
  dir_time_after = mdm_after2.last_modified();

  // std::cout << "File time after: " << file_time_after << std::endl;
  // std::cout << "Dir time after: " << dir_time_after << std::endl;

  ASSERT_NE(file_time_before, file_time_after) <<
      "last_modified time for file has not updated.";
  ASSERT_NE(dir_time_before, dir_time_after) <<
      "last_modified time for file has not updated.";
}

TEST_F(PdDirTest, BEH_MAID_ChangeAtime) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name = "File.file";
  std::string file_hash = "File Hash";
  std::string ser_mdm1, ser_dm;
  PrepareMDM(-2, file_name, REGULAR_FILE, file_hash, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash, ser_dm);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm, "")) <<
      "File was not added to db1.";

  // add directory
  std::string dir_name = "Directory";
  std::string dir_key = "Dir Key";
  std::string ser_mdm2;
  PrepareMDM(-2, dir_name, DIRECTORY, "", "Stats2", "Tag2", 0, 0, 3, 0,
      0, ser_mdm2);
  ASSERT_EQ(0, da->AddElement(ser_mdm2, "", dir_key)) <<
      "Directory was not added to db1.";

  // get current value for last_access times
  std::string ser_mdm_before1, ser_mdm_before2;
  std::string ser_mdm_after1, ser_mdm_after2;
  MetaDataMap mdm_before1, mdm_before2, mdm_after1, mdm_after2;
  boost::uint32_t file_time_before, dir_time_before, file_time_after;
  boost::uint32_t dir_time_after;
  ASSERT_EQ(0, da->GetMetaDataMap(file_name, &ser_mdm_before1)) <<
      "Retrieved ser_mdm for file incorrectly.";
  ASSERT_EQ(0, da->GetMetaDataMap(dir_name, &ser_mdm_before2)) <<
      "Retrieved ser_mdm for dir incorrectly.";
  ASSERT_TRUE(mdm_before1.ParseFromString(ser_mdm_before1)) <<
      "Couldn't parse mdm_before1.";
  ASSERT_TRUE(mdm_before2.ParseFromString(ser_mdm_before2)) <<
      "Couldn't parse mdm_before2.";
  file_time_before = mdm_before1.last_access();
  dir_time_before = mdm_before2.last_access();

  // std::cout << "File time before: " << file_time_before << std::endl;
  // std::cout << "Dir time before: " << dir_time_before << std::endl;

  // wait 2 seconds
  // std::cout << "Waiting";
  for (int i = 0; i < 20; ++i) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    // std::cout << ".";
  }
  // std::cout << std::endl;

  // change last_access time to current time
  ASSERT_EQ(0, da->ChangeAtime(file_name)) <<
      "Failed to change last_access time for file.";
  ASSERT_EQ(0, da->ChangeAtime(dir_name)) <<
      "Failed to change last_access time for dir.";
  ASSERT_NE(0, da->ChangeAtime("Non-existent File")) <<
      "Changed last_access time for non-existent file.";

  // get current value for last_access times
  ASSERT_EQ(0, da->GetMetaDataMap(file_name, &ser_mdm_after1)) <<
      "Retrieved ser_mdm for file incorrectly.";
  ASSERT_EQ(0, da->GetMetaDataMap(dir_name, &ser_mdm_after2)) <<
      "Retrieved ser_mdm for dir incorrectly.";
  ASSERT_TRUE(mdm_after1.ParseFromString(ser_mdm_after1)) <<
      "Couldn't parse mdm_after1.";
  ASSERT_TRUE(mdm_after2.ParseFromString(ser_mdm_after2)) <<
      "Couldn't parse mdm_after2.";
  file_time_after = mdm_after1.last_access();
  dir_time_after = mdm_after2.last_access();

//   std::cout << "File time after: " << file_time_after << std::endl;
//   std::cout << "Dir time after: " << dir_time_after << std::endl;

  ASSERT_NE(file_time_before, file_time_after) <<
      "last_access time for file has not updated.";
  ASSERT_NE(dir_time_before, dir_time_after) <<
      "last_access time for file has not updated.";
}

TEST_F(PdDirTest, BEH_MAID_ModifyViaAddElement) {
  // create db1
  int result = -1;
  boost::scoped_ptr<PdDir> da(new PdDir(db_name1_, CREATE, &result));
  ASSERT_EQ(0, result) << "Db creation returned result " << result << ".";
  ASSERT_TRUE(fs::exists(db_name1_)) << "Db was not created.";

  // add file
  std::string file_name = "File.file";
  std::string file_hash = "File Hash";
  std::string ser_mdm1, ser_dm;
  PrepareMDM(-2, file_name, REGULAR_FILE, file_hash, "Stats1", "Tag1",
      0, 1, 2, 0, 0, ser_mdm1);
  PrepareDMap(file_hash, ser_dm);
  ASSERT_EQ(0, da->AddElement(ser_mdm1, ser_dm, "")) <<
      "File was not added to db1.";

  // add directory
  std::string dir_name = "Directory";
  std::string dir_key = "Dir Key";
  std::string ser_mdm2;
  PrepareMDM(-2, dir_name, EMPTY_DIRECTORY, "", "Stats2", "Tag2", 0, 0,
      3, 0, 0, ser_mdm2);
  ASSERT_EQ(0, da->AddElement(ser_mdm2, "", dir_key)) <<
      "Directory was not added to db1.";

  // modify file
  std::string file_hash_new = "New File Hash";
  std::string ser_mdm_new1, ser_dm_new1;
  PrepareMDM(-2, file_name, SMALL_FILE, file_hash_new,
    "New Stats1", "New Tag1", 1, 4, 5, 0, 0, ser_mdm_new1);
  PrepareDMap(file_hash_new, ser_dm_new1);
  ASSERT_EQ(0, da->AddElement(ser_mdm_new1, ser_dm_new1, "")) <<
      "File Mdm was not updated.";

  // modify directory
  std::string ser_mdm_new2;
  PrepareMDM(-2, dir_name, DIRECTORY, "", "New Stats2",
    "New Tag2", 0, 0, 6, 0, 0, ser_mdm_new2);
  ASSERT_EQ(0, da->AddElement(ser_mdm_new2, "", "")) <<
      "Directory Mdm was not updated.";

  // get serialised Mdms
  std::string ser_mdm_recovered1, ser_mdm_recovered2;
  ASSERT_EQ(0, da->GetMetaDataMap(file_name, &ser_mdm_recovered1)) <<
      "Retrieved ser_mdm for file1 incorrectly.";
  ASSERT_EQ(0, da->GetMetaDataMap(dir_name, &ser_mdm_recovered2)) <<
      "Retrieved ser_mdm for file2 incorrectly.";

  // parse Mdms
  MetaDataMap mdm1, mdm2, mdm_new1, mdm_new2;
  MetaDataMap mdm_recovered1, mdm_recovered2;
  ASSERT_TRUE(mdm1.ParseFromString(ser_mdm1)) << "Couldn't parse mdm1.";
  ASSERT_TRUE(mdm2.ParseFromString(ser_mdm2)) << "Couldn't parse mdm2.";
  ASSERT_TRUE(mdm_new1.ParseFromString(ser_mdm_new1)) <<
      "Couldn't parse mdm_new1.";
  ASSERT_TRUE(mdm_new2.ParseFromString(ser_mdm_new2)) <<
      "Couldn't parse mdm_new2.";
  ASSERT_TRUE(mdm_recovered1.ParseFromString(ser_mdm_recovered1)) <<
      "Couldn't parse mdm_recovered1.";
  ASSERT_TRUE(mdm_recovered2.ParseFromString(ser_mdm_recovered2)) <<
      "Couldn't parse mdm_recovered2.";

  // check file updated
  ASSERT_EQ(mdm1.display_name(), mdm_recovered1.display_name()) <<
      "File display name has changed.";
  ASSERT_EQ(mdm_new1.display_name(), mdm_recovered1.display_name()) <<
      "File display name has not updated correctly.";

  ASSERT_NE(mdm1.type(), mdm_recovered1.type()) <<
      "File type has not updated.";
  ASSERT_EQ(mdm_new1.type(), mdm_recovered1.type()) <<
      "File type has not updated correctly.";

  ASSERT_NE(mdm1.file_hash(0), mdm_recovered1.file_hash(0)) <<
      "File hash has not updated.";
  ASSERT_EQ(mdm_new1.file_hash(0), mdm_recovered1.file_hash(0)) <<
      "File hash has not updated correctly.";

  ASSERT_NE(mdm1.stats(), mdm_recovered1.stats()) <<
      "File stats have not updated.";
  ASSERT_EQ(mdm_new1.stats(), mdm_recovered1.stats()) <<
      "File stats have not updated correctly.";

  ASSERT_NE(mdm1.tag(), mdm_recovered1.tag()) << "File tag has not updated.";
  ASSERT_EQ(mdm_new1.tag(), mdm_recovered1.tag()) <<
      "File tag has not updated correctly.";

  ASSERT_NE(mdm1.file_size_high(), mdm_recovered1.file_size_high()) <<
      "File file_size_high has not updated.";
  ASSERT_EQ(mdm_new1.file_size_high(), mdm_recovered1.file_size_high()) <<
      "File file_size_high has not updated correctly.";

  ASSERT_NE(mdm1.file_size_low(), mdm_recovered1.file_size_low()) <<
      "File file_size_low has not updated.";
  ASSERT_EQ(mdm_new1.file_size_low(), mdm_recovered1.file_size_low()) <<
      "File file_size_low has not updated correctly.";

  ASSERT_EQ(mdm1.creation_time(), mdm_recovered1.creation_time()) <<
      "File creation time has changed.";
  ASSERT_NE(mdm_new1.creation_time(), mdm_recovered1.creation_time()) <<
      "File creation time has not updated correctly.";

  // check dir updated
  ASSERT_EQ(mdm2.display_name(), mdm_recovered2.display_name()) <<
      "Dir display name has changed.";
  ASSERT_EQ(mdm_new2.display_name(), mdm_recovered2.display_name()) <<
      "Dir display name has not updated correctly.";

  ASSERT_NE(mdm2.type(), mdm_recovered2.type()) <<
      "Dir type has not updated.";
  ASSERT_EQ(mdm_new2.type(), mdm_recovered2.type()) <<
      "Dir type has not updated correctly.";

  ASSERT_NE(mdm2.stats(), mdm_recovered2.stats()) <<
      "Dir stats have not updated.";
  ASSERT_EQ(mdm_new2.stats(), mdm_recovered2.stats()) <<
      "Dir stats have not updated correctly.";

  ASSERT_NE(mdm2.tag(), mdm_recovered2.tag()) << "Dir tag has not updated.";
  ASSERT_EQ(mdm_new2.tag(), mdm_recovered2.tag()) <<
      "Dir tag has not updated correctly.";

  ASSERT_EQ(mdm2.creation_time(), mdm_recovered2.creation_time()) <<
      "Dir creation time has changed.";
  ASSERT_NE(mdm_new2.creation_time(), mdm_recovered2.creation_time()) <<
      "Dir creation time has not updated correctly.";
}

}  // namespace test

}  // namespace maidsafe
