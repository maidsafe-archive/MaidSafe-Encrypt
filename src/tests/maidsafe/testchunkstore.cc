/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in teh root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Oct 14, 2008
 *      Author: Jose, Haiyang
 */


#include <boost/filesystem/fstream.hpp>
#include <gtest/gtest.h>
#include "maidsafe/utils.h"
#include "maidsafe/crypto.h"
#include "maidsafe/vault/chunkstore.h"

namespace test_chunkstore {

void WaitForInitialisation(
    boost::shared_ptr<maidsafe_vault::ChunkStore> chunkstore,
    const boost::uint64_t &timeout) {
  boost::uint64_t count(0);
  while (count < timeout && !chunkstore->is_initialised()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
}

// Makes (num_chunks) chunks of length between 3 and 32000 bytes.  If hashable
// is true, Hash(value) == name for each chunk.
bool MakeChunks(const boost::uint32_t &num_chunks,
                boost::shared_ptr<crypto::Crypto> cry_obj,
                bool hashable,
                std::vector<boost::uint64_t> *chunksize,
                std::vector<std::string> *value,
                std::vector<std::string> *name) {
  chunksize->clear();
  value->clear();
  name->clear();
  for (boost::uint32_t i = 0; i < num_chunks; ++i) {
    // set chunk sizes between 3 and 32000
    chunksize->push_back(3 + (rand() % 31997));  // NOLINT (Fraser)
    value->push_back(base::RandomString(chunksize->at(i)));
    if (hashable) {
      name->push_back(cry_obj->Hash(value->at(i), "", crypto::STRING_STRING,
                                    false));
    } else {
      name->push_back(cry_obj->Hash(base::itos(i), "", crypto::STRING_STRING,
                                    false));
    }
  }
  return (chunksize->size() == num_chunks && value->size() == num_chunks &&
          name->size() == num_chunks);
}

// Checks for the existance of non_hex_filename's stored chunk in root_dir_path
// and if found, modifies path_found to location of file otherwise path_found
// is set to an empty path.
bool FindFile(const fs::path &root_dir_path,
              const std::string &non_hex_filename,
              fs::path *path_found) {
  if (!fs::exists(root_dir_path)) {
    *path_found = fs::path("");
    return false;
  }
  std::string hex_filename("");
  base::encode_to_hex(non_hex_filename, &hex_filename);
  fs::directory_iterator end_itr;
  for (fs::directory_iterator itr(root_dir_path); itr != end_itr; ++itr) {
//    printf("Iter at %s\n", itr->path().filename().c_str());
    if (fs::is_directory(itr->status())) {
      if (FindFile(itr->path(), non_hex_filename, path_found))
        return true;
    } else if (itr->filename() == hex_filename) {
      *path_found = itr->path();
      return true;
    }
  }
  *path_found = fs::path("");
  return false;
}

// This checks that the file is in "./TESTSTORAGE/parent/branch" where the path
// is expected to be of form eg "./TESTSTORAGE/Hashable/Normal/0/c/5/0c56c76..."
bool CheckFilePath(const fs::path &file_path,
                   const std::string &parent,
                   const std::string &branch) {
  fs::path root_path(file_path);
  // need a remove_filename for each of the 4 subdirs and 4 trailing slashes
  for (int i = 0; i < 8; ++i)
    root_path.remove_filename();
  if (root_path.filename() != branch) {
#ifdef DEBUG
    printf("In CheckFilePath (branch), %s != %s\n",
           root_path.filename().c_str(), branch.c_str());
#endif
    return false;
  }
  root_path.remove_filename();
  root_path.remove_filename();
  if (root_path.filename() != parent) {
#ifdef DEBUG
    printf("In CheckFilePath (branch), %s != %s\n",
           root_path.filename().c_str(), parent.c_str());
#endif
    return false;
  }
  return true;
}

}  // namespace test_chunkstore

namespace maidsafe_vault {

class TestChunkstore : public testing::Test {
 protected:
  TestChunkstore()
      : storedir("./TESTSTORAGE", fs::native),
        cry_obj(new crypto::Crypto),
        h_size(),
        nh_size(),
        h_value(),
        nh_value(),
        h_name(),
        nh_name() {}
  void SetUp() {
    cry_obj->set_symm_algorithm(crypto::AES_256);
    cry_obj->set_hash_algorithm(crypto::SHA_512);
    try {
      fs::remove_all(storedir);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
  void TearDown() {
    try {
      fs::remove_all(storedir);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
  fs::path storedir;
  boost::shared_ptr<crypto::Crypto> cry_obj;
  std::vector<boost::uint64_t> h_size, nh_size;
  std::vector<std::string> h_value, nh_value, h_name, nh_name;
};

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreInit) {
  std::string invalid_path_length(257, ' ');
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(invalid_path_length));
  ASSERT_FALSE(chunkstore->is_initialised());
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, true, &h_size, &h_value,
              &h_name));
  ASSERT_FALSE(chunkstore->HasChunk(h_name.at(0)));
  ASSERT_FALSE(chunkstore->StoreChunk(h_name.at(0), h_value.at(0)));
  ASSERT_FALSE(chunkstore->DeleteChunk(h_name.at(0)));
  ASSERT_FALSE(chunkstore->UpdateChunk(h_name.at(0), h_value.at(0)));
  std::string value("value");
  ASSERT_FALSE(chunkstore->LoadChunk(h_name.at(0), &value));
  ASSERT_EQ("", value);
  std::string key("key");
  value = "value";
  ASSERT_FALSE(chunkstore->LoadRandomChunk(&key, &value));
  ASSERT_EQ("", key);
  ASSERT_EQ("", value);
  std::list<std::string> chunk_names, failed_keys;
  chunk_names.push_back("name");
  ASSERT_NE(static_cast<unsigned int>(0), chunk_names.size());
  chunkstore->GetAllChunks(&chunk_names);
  ASSERT_EQ(static_cast<unsigned int>(0), chunk_names.size());
  ASSERT_NE(0, chunkstore->HashCheckChunk(h_name.at(0)));
  failed_keys.push_back("key");
  ASSERT_NE(static_cast<unsigned int>(0), failed_keys.size());
  ASSERT_NE(0, chunkstore->HashCheckAllChunks(true, &failed_keys));
  ASSERT_EQ(static_cast<unsigned int>(0), failed_keys.size());
  ChunkType type = kHashable | kNormal;
  ASSERT_NE(0, chunkstore->ChangeChunkType(h_name.at(0), type));
  boost::shared_ptr<ChunkStore> chunkstore1(new ChunkStore(storedir.string()));
  test_chunkstore::WaitForInitialisation(chunkstore1, 60000);
  ASSERT_TRUE(chunkstore1->is_initialised());
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreStoreChunk) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string()));
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  ASSERT_EQ(static_cast<unsigned int>(0), chunkstore->chunkstore_set_.size());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, true, &h_size, &h_value,
              &h_name));
  int test_chunk = 0;
  ASSERT_TRUE(chunkstore->StoreChunk(h_name.at(test_chunk),
                                     h_value.at(test_chunk)));
  ASSERT_EQ(static_cast<unsigned int>(1), chunkstore->chunkstore_set_.size());
  fs::path found("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  // check contents of file
  ASSERT_NE(found.filename(), "");
  boost::uint64_t chunk_size = fs::file_size(found);
  ASSERT_EQ(h_size.at(test_chunk), chunk_size);
  boost::scoped_ptr<char> temp1(new char[chunk_size]);
  fs::ifstream fstr1;
  fstr1.open(found, std::ios_base::binary);
  fstr1.read(temp1.get(), chunk_size);
  fstr1.close();
  std::string stored_value1(static_cast<const char*>(temp1.get()), chunk_size);
  ASSERT_EQ(h_value.at(test_chunk), stored_value1);
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, false, &nh_size,
              &nh_value, &nh_name));
  ASSERT_TRUE(chunkstore->StoreChunk(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  ASSERT_EQ(static_cast<unsigned int>(2), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, nh_name.at(test_chunk),
                                        &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found,
      chunkstore->kNonHashableLeaf_, chunkstore->kNormalLeaf_));
  // check contents of file
  ASSERT_NE(found.filename(), "");
  chunk_size = fs::file_size(found);
  ASSERT_EQ(nh_size.at(test_chunk), chunk_size);
  boost::scoped_ptr<char> temp2(new char[chunk_size]);
  fs::ifstream fstr2;
  fstr2.open(found, std::ios_base::binary);
  fstr2.read(temp2.get(), chunk_size);
  fstr2.close();
  std::string stored_value2(static_cast<const char*>(temp2.get()), chunk_size);
  ASSERT_EQ(nh_value.at(test_chunk), stored_value2);
  // check values can't be stored under keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_FALSE(chunkstore->StoreChunk(wrong_length_key, h_value.at(0)));
  ASSERT_EQ(static_cast<unsigned int>(2), chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(test_chunkstore::FindFile(storedir, wrong_length_key, &found));
  ASSERT_FALSE(chunkstore->HasChunk(wrong_length_key));
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreLoadChunk) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string()));
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, true, &h_size, &h_value,
              &h_name));
  int test_chunk = 0;
  ASSERT_TRUE(chunkstore->StoreChunk(h_name.at(test_chunk),
                                     h_value.at(test_chunk)));
  std::string rec_value("Value");
  ASSERT_TRUE(chunkstore->LoadChunk(h_name.at(test_chunk), &rec_value));
  ASSERT_EQ(h_value.at(test_chunk), rec_value);
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, false, &nh_size,
              &nh_value, &nh_name));
  ASSERT_TRUE(chunkstore->StoreChunk(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  rec_value = "Value";
  ASSERT_TRUE(chunkstore->LoadChunk(nh_name.at(test_chunk), &rec_value));
  ASSERT_EQ(nh_value.at(test_chunk), rec_value);
  // check using non-existant chunk
  std::string othername = cry_obj->Hash("otherfile", "", crypto::STRING_STRING,
                                        false);
  ASSERT_FALSE(chunkstore->LoadChunk(othername, &rec_value));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_FALSE(chunkstore->LoadChunk(wrong_length_key, &rec_value));
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreHasChunk) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string()));
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, true, &h_size, &h_value,
              &h_name));
  int test_chunk = 0;
  ASSERT_TRUE(chunkstore->StoreChunk(h_name.at(test_chunk),
                                     h_value.at(test_chunk)));
  ASSERT_TRUE(chunkstore->HasChunk(h_name.at(test_chunk)));
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, false, &nh_size,
              &nh_value, &nh_name));
  ASSERT_TRUE(chunkstore->StoreChunk(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  ASSERT_TRUE(chunkstore->HasChunk(nh_name.at(test_chunk)));
  // check using non-existant chunk
  std::string othername = cry_obj->Hash("otherfile", "", crypto::STRING_STRING,
                                        false);
  ASSERT_FALSE(chunkstore->HasChunk(othername));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_FALSE(chunkstore->HasChunk(wrong_length_key));
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreDeleteChunk) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string()));
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  ASSERT_EQ(static_cast<unsigned int>(0), chunkstore->chunkstore_set_.size());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, true, &h_size, &h_value,
              &h_name));
  int test_chunk = 0;
  ASSERT_TRUE(chunkstore->StoreChunk(h_name.at(test_chunk),
                                     h_value.at(test_chunk)));
  ASSERT_EQ(static_cast<unsigned int>(1), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(chunkstore->HasChunk(h_name.at(test_chunk)));
  fs::path found("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_NE(found.filename(), "");
  ASSERT_TRUE(fs::exists(found));
  ASSERT_TRUE(chunkstore->DeleteChunk(h_name.at(test_chunk)));
  ASSERT_EQ(static_cast<unsigned int>(0), chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(chunkstore->HasChunk(h_name.at(test_chunk)));
  ASSERT_FALSE(fs::exists(found));
  ASSERT_TRUE(chunkstore->DeleteChunk(h_name.at(test_chunk)));
  ASSERT_EQ(static_cast<unsigned int>(0), chunkstore->chunkstore_set_.size());
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, false, &nh_size,
              &nh_value, &nh_name));
  ASSERT_TRUE(chunkstore->StoreChunk(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  ASSERT_EQ(static_cast<unsigned int>(1), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(chunkstore->HasChunk(nh_name.at(test_chunk)));
  found = fs::path("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, nh_name.at(test_chunk),
                                        &found));
  ASSERT_NE(found.filename(), "");
  ASSERT_TRUE(fs::exists(found));
  ASSERT_TRUE(chunkstore->DeleteChunk(nh_name.at(test_chunk)));
  ASSERT_EQ(static_cast<unsigned int>(0), chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(chunkstore->HasChunk(nh_name.at(test_chunk)));
  ASSERT_FALSE(fs::exists(found));
  ASSERT_TRUE(chunkstore->DeleteChunk(nh_name.at(test_chunk)));
  ASSERT_EQ(static_cast<unsigned int>(0), chunkstore->chunkstore_set_.size());
  // check using non-existant chunk
  std::string othername = cry_obj->Hash("otherfile", "", crypto::STRING_STRING,
                                        false);
  ASSERT_TRUE(chunkstore->DeleteChunk(othername));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_FALSE(chunkstore->DeleteChunk(wrong_length_key));
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreLoadRandomChunk) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string()));
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // test when chunkstore is empty
  std::string key("key"), val("val");
  ASSERT_FALSE(chunkstore->LoadRandomChunk(&key, &val));
  ASSERT_EQ(key, std::string(""));
  ASSERT_EQ(val, std::string(""));
  int kNumberOfChunks = 10;
  // test with no hashable chunks (shouldn't return any)
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, false,
                                          &nh_size, &nh_value, &nh_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_TRUE(chunkstore->StoreChunk(nh_name.at(i), nh_value.at(i)));
  ASSERT_EQ(static_cast<unsigned int>(kNumberOfChunks),
            chunkstore->chunkstore_set_.size());
  key = "key";
  val = "val";
  ASSERT_FALSE(chunkstore->LoadRandomChunk(&key, &val));
  ASSERT_EQ("", key);
  ASSERT_EQ("", val);
  // test with hashable chunks
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true,
                                          &h_size, &h_value, &h_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_TRUE(chunkstore->StoreChunk(h_name.at(i), h_value.at(i)));
  ASSERT_EQ(static_cast<unsigned int>(2 * kNumberOfChunks),
            chunkstore->chunkstore_set_.size());
  key = "key";
  val = "val";
  ASSERT_TRUE(chunkstore->LoadRandomChunk(&key, &val));
  ASSERT_EQ(key, cry_obj->Hash(val, "", crypto::STRING_STRING, false));
  fs::path found("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, key, &found));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  ASSERT_NE(found.filename(), "");
  ASSERT_TRUE(fs::exists(found));
  boost::uint64_t final_size = fs::file_size(found);
  boost::uint64_t original_size = 0;
  int attempt = 0;
  while (!original_size && attempt < kNumberOfChunks) {
    if (h_name.at(attempt) == key)
      original_size = h_size.at(attempt);
    ++attempt;
  }
  ASSERT_EQ(original_size, final_size);
  char *temp;
  temp = new char[final_size];
  fs::ifstream fstr;
  fstr.open(found, std::ios_base::binary);
  fstr.read(temp, final_size);
  fstr.close();
  std::string stored_value(static_cast<const char*>(temp), final_size);
  ASSERT_EQ(val, stored_value);
  stored_value = "val";
  ASSERT_TRUE(chunkstore->LoadChunk(key, &stored_value));
  ASSERT_EQ(val, stored_value);
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreUpdateChunk) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string()));
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(2, cry_obj, true, &h_size, &h_value,
                                          &h_name));
  ASSERT_NE(h_value.at(0), h_value.at(1));
  ASSERT_TRUE(chunkstore->StoreChunk(h_name.at(0), h_value.at(0)));
  ASSERT_TRUE(chunkstore->UpdateChunk(h_name.at(0), h_value.at(1)));
  std::string rec_value("Value");
  ASSERT_TRUE(chunkstore->LoadChunk(h_name.at(0), &rec_value));
  ASSERT_EQ(h_value.at(1), rec_value);
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(2, cry_obj, true, &nh_size, &nh_value,
                                          &nh_name));
  ASSERT_NE(nh_value.at(0), nh_value.at(1));
  ASSERT_TRUE(chunkstore->StoreChunk(nh_name.at(0), nh_value.at(0)));
  ASSERT_TRUE(chunkstore->UpdateChunk(nh_name.at(0), nh_value.at(1)));
  rec_value = "Value";
  ASSERT_TRUE(chunkstore->LoadChunk(nh_name.at(0), &rec_value));
  ASSERT_EQ(nh_value.at(1), rec_value);
  // check using non-existant chunk
  std::string othername = cry_obj->Hash("otherfile", "", crypto::STRING_STRING,
                                        false);
  ASSERT_FALSE(chunkstore->UpdateChunk(othername, h_value.at(0)));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_FALSE(chunkstore->UpdateChunk(wrong_length_key, h_value.at(0)));
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreHashCheckChunk) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string()));
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, true, &h_size, &h_value,
                                          &h_name));
  int test_chunk = 0;
  ASSERT_TRUE(chunkstore->StoreChunk(h_name.at(test_chunk),
                                     h_value.at(test_chunk)));
  boost::posix_time::ptime original_check_time;
  {
    boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
    chunk_set_by_non_hex_name::iterator itr = chunkstore->
        chunkstore_set_.get<non_hex_name>().find(h_name.at(test_chunk));
    original_check_time = (*itr).last_checked_;
  }
  ASSERT_EQ(0, chunkstore->HashCheckChunk(h_name.at(test_chunk)));
  boost::posix_time::ptime later_check_time;
  {
    boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
    chunk_set_by_non_hex_name::iterator itr = chunkstore->
        chunkstore_set_.get<non_hex_name>().find(h_name.at(test_chunk));
    later_check_time = (*itr).last_checked_;
  }
  ASSERT_GT(later_check_time - original_check_time,
            boost::posix_time::milliseconds(0));
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, false, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_TRUE(chunkstore->StoreChunk(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  ASSERT_NE(0, chunkstore->HashCheckChunk(nh_name.at(test_chunk)));
  // check using non-existant chunk
  std::string othername = cry_obj->Hash("otherfile", "", crypto::STRING_STRING,
                                        false);
  ASSERT_NE(0, chunkstore->HashCheckChunk(othername));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_NE(0, chunkstore->HashCheckChunk(wrong_length_key));
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreChangeChunkType) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string()));
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  int kNumberOfChunks = chunkstore->path_map_.size();  // 8
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true,
                                          &h_size, &h_value, &h_name));
  ASSERT_TRUE(test_chunkstore::MakeChunks(2, cry_obj, false, &nh_size,
                                          &nh_value, &nh_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_TRUE(chunkstore->StoreChunk(h_name.at(i), h_value.at(i)));
  ASSERT_TRUE(chunkstore->StoreChunk(nh_name.at(0), nh_value.at(0)));
  ASSERT_TRUE(chunkstore->StoreChunk(nh_name.at(1), nh_value.at(1)));
  // Move a chunk to each of the different types and the single chunk to the
  // original type of all the others.
  path_map_iterator path_map_itr;
  int i = 0;
  std::vector<fs::path> found;
  for (path_map_itr = chunkstore->path_map_.begin();
       path_map_itr != chunkstore->path_map_.end();
       ++path_map_itr) {
    ASSERT_EQ(0, chunkstore->ChangeChunkType(h_name.at(i),
                                             (*path_map_itr).first));
    fs::path found_path("");
    ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(i), &found_path));
    found.push_back(found_path);
    ++i;
  }
  path_map_itr = chunkstore->path_map_.begin();
  ASSERT_EQ(0, chunkstore->ChangeChunkType(nh_name.at(0),
                                           (*path_map_itr).first));
  fs::path found_path("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, nh_name.at(0), &found_path));
  // Check each chunk has the correct type
  i = 0;
  for (path_map_itr = chunkstore->path_map_.begin();
       path_map_itr != chunkstore->path_map_.end();
       ++path_map_itr) {
    {
      boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
      chunk_set_by_non_hex_name::iterator itr = chunkstore->
          chunkstore_set_.get<non_hex_name>().find(h_name.at(i));
      ASSERT_EQ((*path_map_itr).first, (*itr).type_);
    }
    ++i;
  }
  path_map_itr = chunkstore->path_map_.begin();
  {
    boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
    chunk_set_by_non_hex_name::iterator itr = chunkstore->
        chunkstore_set_.get<non_hex_name>().find(nh_name.at(0));
    ASSERT_EQ((*path_map_itr).first, (*itr).type_);
  }
  // Check each has been moved to the correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(0),
                                             chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(1),
                                             chunkstore->kHashableLeaf_,
                                             chunkstore->kCacheLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(2),
                                             chunkstore->kHashableLeaf_,
                                             chunkstore->kOutgoingLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(3),
                                             chunkstore->kHashableLeaf_,
                                             chunkstore->kTempCacheLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(4),
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(5),
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kCacheLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(6),
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kOutgoingLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found.at(7),
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kTempCacheLeaf_));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found_path,
                                             chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  // check using invalid type
  ChunkType type = 3;
  ASSERT_NE(0, chunkstore->ChangeChunkType(nh_name.at(1), type));
  type = (kNonHashable | kNormal);
  {
    boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
    chunk_set_by_non_hex_name::iterator itr = chunkstore->
        chunkstore_set_.get<non_hex_name>().find(nh_name.at(1));
    ASSERT_EQ(type, (*itr).type_);
  }
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, nh_name.at(1), &found_path));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found_path,
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  // check using non-existant chunk
  std::string othername = cry_obj->Hash("otherfile", "", crypto::STRING_STRING,
                                        false);
  ASSERT_NE(0, chunkstore->ChangeChunkType(othername, (kHashable | kNormal)));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_NE(0, chunkstore->ChangeChunkType(wrong_length_key,
                                           (kHashable | kNormal)));
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreReuseDirectory) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string()));
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  int kNumberOfChunks = 5 * chunkstore->path_map_.size();  // 40
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true,
                                          &h_size, &h_value, &h_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_TRUE(chunkstore->StoreChunk(h_name.at(i), h_value.at(i)));
  // Move 5 chunks to each of the different types.
  path_map_iterator path_map_itr;
  int i = 0;
  std::vector<fs::path> found;
  for (path_map_itr = chunkstore->path_map_.begin();
       path_map_itr != chunkstore->path_map_.end();
       ++path_map_itr) {
    for (int j = 0; j < 5; ++j) {
      ASSERT_EQ(0, chunkstore->ChangeChunkType(h_name.at(i),
                                               (*path_map_itr).first));
      fs::path found_path("");
      ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(i),
                                            &found_path));
      found.push_back(found_path);
      ++i;
    }
  }
  // Create a new chunkstore that has same root dir
  boost::shared_ptr<ChunkStore> chunkstore1(new ChunkStore(storedir.string()));
  test_chunkstore::WaitForInitialisation(chunkstore1, 60000);
  ASSERT_TRUE(chunkstore1->is_initialised());
  ASSERT_EQ(static_cast<unsigned int>(kNumberOfChunks),
            chunkstore1->chunkstore_set_.size());
  for (int k = 0; k < kNumberOfChunks; k++) {
    ASSERT_TRUE(chunkstore1->HasChunk(h_name.at(k)));
    std::string rec_value("Value");
    ASSERT_TRUE(chunkstore1->LoadChunk(h_name.at(k), &rec_value));
  }
  // creating a new chunkstore that has same root dir but with one of the
  // hashable chunks modified to fail hash check
  ASSERT_TRUE(chunkstore->UpdateChunk(h_name.at(0), "modified content"));
  boost::shared_ptr<ChunkStore> chunkstore2(new ChunkStore(storedir.string()));
  test_chunkstore::WaitForInitialisation(chunkstore2, 60000);
  ASSERT_TRUE(chunkstore2->is_initialised());
  ASSERT_EQ(static_cast<unsigned int>(kNumberOfChunks - 1),
            chunkstore2->chunkstore_set_.size());
  ASSERT_FALSE(chunkstore2->HasChunk(h_name.at(0)));
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreGetAllChunks) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string()));
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // Check with empty chunkstore.
  std::list<std::string> ret_chunk_names;
  chunkstore->GetAllChunks(&ret_chunk_names);
  ASSERT_EQ(static_cast<unsigned int>(0), ret_chunk_names.size());
  // Put 50 hashable and 50 non-hashable chunks in and check again.
  int kNumberOfChunks = 50;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true,
                                          &h_size, &h_value, &h_name));
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, false,
                                          &nh_size, &nh_value, &nh_name));
  for (int i = 0; i < kNumberOfChunks; ++i) {
    ASSERT_TRUE(chunkstore->StoreChunk(h_name.at(i), h_value.at(i)));
    ASSERT_TRUE(chunkstore->StoreChunk(nh_name.at(i), nh_value.at(i)));
  }
  chunkstore->GetAllChunks(&ret_chunk_names);
  ASSERT_EQ(static_cast<unsigned int>(2 * kNumberOfChunks),
            ret_chunk_names.size());
  for (int i = 0; i < kNumberOfChunks; ++i) {
    ret_chunk_names.remove(h_name.at(i));
    ret_chunk_names.remove(nh_name.at(i));
  }
  ASSERT_EQ(static_cast<unsigned int>(0), ret_chunk_names.size());
}

TEST_F(TestChunkstore, BEH_MAID_ChunkstoreCheckAllChunks) {
  boost::shared_ptr<ChunkStore> chunkstore(new ChunkStore(storedir.string()));
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  int kNumberOfChunks = 5 * chunkstore->path_map_.size();  // 40
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true,
                                          &h_size, &h_value, &h_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_TRUE(chunkstore->StoreChunk(h_name.at(i), h_value.at(i)));
  // Move 5 chunks to each of the different types.
  path_map_iterator path_map_itr;
  int i = 0;
  std::vector<fs::path> found;
  for (path_map_itr = chunkstore->path_map_.begin();
       path_map_itr != chunkstore->path_map_.end();
       ++path_map_itr) {
    for (int j = 0; j < 5; ++j) {
      ASSERT_EQ(0, chunkstore->ChangeChunkType(h_name.at(i),
                                               (*path_map_itr).first));
      fs::path found_path("");
      ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(i),
                                            &found_path));
      found.push_back(found_path);
      ++i;
    }
  }
  // All files are hashable, half are in directories that should be checked.
  std::list<std::string> failed_chunk_names;
  ASSERT_EQ(0, chunkstore->HashCheckAllChunks(false, &failed_chunk_names));
  ASSERT_EQ(static_cast<unsigned int>(0), failed_chunk_names.size());
  ASSERT_EQ(0, chunkstore->HashCheckAllChunks(true, &failed_chunk_names));
  ASSERT_EQ(static_cast<unsigned int>(0), failed_chunk_names.size());
  // Modify four of the hashable files (one in each subdirectory).
  std::string modified_content("modified content");
  ASSERT_TRUE(chunkstore->UpdateChunk(h_name.at(0), modified_content));
  ASSERT_TRUE(chunkstore->UpdateChunk(h_name.at(5), modified_content));
  ASSERT_TRUE(chunkstore->UpdateChunk(h_name.at(10), modified_content));
  ASSERT_TRUE(chunkstore->UpdateChunk(h_name.at(15), modified_content));
  // Check failed files don't get removed
  ASSERT_EQ(0, chunkstore->HashCheckAllChunks(false, &failed_chunk_names));
  ASSERT_TRUE(chunkstore->HasChunk(h_name.at(0)));
  ASSERT_TRUE(chunkstore->HasChunk(h_name.at(5)));
  ASSERT_TRUE(chunkstore->HasChunk(h_name.at(10)));
  ASSERT_TRUE(chunkstore->HasChunk(h_name.at(15)));
  std::string rec_value("Value");
  ASSERT_TRUE(chunkstore->LoadChunk(h_name.at(0), &rec_value));
  ASSERT_EQ(modified_content, rec_value);
  rec_value = "Value";
  ASSERT_TRUE(chunkstore->LoadChunk(h_name.at(5), &rec_value));
  ASSERT_EQ(modified_content, rec_value);
  rec_value = "Value";
  ASSERT_TRUE(chunkstore->LoadChunk(h_name.at(10), &rec_value));
  ASSERT_EQ(modified_content, rec_value);
  rec_value = "Value";
  ASSERT_TRUE(chunkstore->LoadChunk(h_name.at(15), &rec_value));
  ASSERT_EQ(modified_content, rec_value);
  ASSERT_EQ(static_cast<unsigned int>(4), failed_chunk_names.size());
  failed_chunk_names.remove(h_name.at(0));
  failed_chunk_names.remove(h_name.at(5));
  failed_chunk_names.remove(h_name.at(10));
  failed_chunk_names.remove(h_name.at(15));
  ASSERT_EQ(static_cast<unsigned int>(0), failed_chunk_names.size());
  // Check failed files do get removed
  ASSERT_EQ(0, chunkstore->HashCheckAllChunks(true, &failed_chunk_names));
  ASSERT_FALSE(chunkstore->HasChunk(h_name.at(0)));
  ASSERT_FALSE(chunkstore->HasChunk(h_name.at(5)));
  ASSERT_FALSE(chunkstore->HasChunk(h_name.at(10)));
  ASSERT_FALSE(chunkstore->HasChunk(h_name.at(15)));
  rec_value = "Value";
  ASSERT_FALSE(chunkstore->LoadChunk(h_name.at(0), &rec_value));
  ASSERT_NE(modified_content, rec_value);
  rec_value = "Value";
  ASSERT_FALSE(chunkstore->LoadChunk(h_name.at(5), &rec_value));
  ASSERT_NE(modified_content, rec_value);
  rec_value = "Value";
  ASSERT_FALSE(chunkstore->LoadChunk(h_name.at(10), &rec_value));
  ASSERT_NE(modified_content, rec_value);
  rec_value = "Value";
  ASSERT_FALSE(chunkstore->LoadChunk(h_name.at(15), &rec_value));
  ASSERT_NE(modified_content, rec_value);
  ASSERT_EQ(static_cast<unsigned int>(4), failed_chunk_names.size());
  failed_chunk_names.remove(h_name.at(0));
  failed_chunk_names.remove(h_name.at(5));
  failed_chunk_names.remove(h_name.at(10));
  failed_chunk_names.remove(h_name.at(15));
  ASSERT_EQ(static_cast<unsigned int>(0), failed_chunk_names.size());
}

}  // namespace maidsafe_vault
