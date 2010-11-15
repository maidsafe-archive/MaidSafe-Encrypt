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
#include <boost/scoped_ptr.hpp>
#include <boost/thread.hpp>
#include <gtest/gtest.h>
#include <maidsafe/base/utils.h>

#include "maidsafe/common/commonutils.h"
#include "maidsafe/common/filesystem.h"
#include "maidsafe/common/maidsafe.h"
#include "maidsafe/common/packet.pb.h"
#include "maidsafe/vault/vaultconfig.h"
#include "maidsafe/vault/vaultchunkstore.h"
#include "maidsafe/sharedtest/chunkstoreops.h"

namespace test_chunkstore {

class ThreadedVaultTest : public ThreadedTest {
 public:
  explicit ThreadedVaultTest(
      boost::shared_ptr<maidsafe::vault::VaultChunkStore> chunkstore)
          : ThreadedTest(boost::shared_static_cast<maidsafe::ChunkStore>(
                  chunkstore)) {}
  virtual ~ThreadedVaultTest() {}
  void LoadRandomChunk(const boost::posix_time::milliseconds &delay,
                       boost::shared_ptr<std::string> name,
                       boost::shared_ptr<std::string> value,
                       boost::shared_ptr<int> result) {
    boost::this_thread::sleep(delay);
    std::string key = *name;
    std::string val = *value;
    int res = boost::shared_static_cast<maidsafe::vault::VaultChunkStore>(
        chunkstore_)->LoadRandomChunk(&key, &val);
    *name = key;
    *value = val;
    *result = res;
  }
  void HashCheckAllChunks(const boost::posix_time::milliseconds &delay,
                          bool delete_failures,
                          boost::shared_ptr< std::list<std::string> > failed,
                          boost::shared_ptr<int> result) {
    boost::this_thread::sleep(delay);
    std::list<std::string> failed_names = *failed;
    int res = boost::shared_static_cast<maidsafe::vault::VaultChunkStore>(
        chunkstore_)->HashCheckAllChunks(delete_failures, &failed_names);
    *failed = failed_names;
    *result = res;
  }
};

}  // namespace test_chunkstore

namespace maidsafe {

namespace vault {

namespace test {

TEST_F(VaultChunkstoreTest, BEH_MAID_Init) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  std::string key("key"), value("value");
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, true, 3, 32000, &h_size, &h_value,
                                          &h_name));
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->LoadRandomChunk(&key, &value));
  ASSERT_EQ("", key);
  ASSERT_EQ("", value);
  std::list<std::string> chunk_names, failed_keys;
  chunk_names.push_back("name");
  ASSERT_NE(size_t(0), chunk_names.size());
  chunkstore->GetAllChunks(&chunk_names);
  ASSERT_EQ(size_t(0), chunk_names.size());
  ASSERT_EQ(size_t(0), chunkstore->GetChunkSize(h_name.at(0)));
  failed_keys.push_back("key");
  ASSERT_NE(size_t(0), failed_keys.size());
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->HashCheckAllChunks(true, &failed_keys));
  ASSERT_EQ(size_t(0), failed_keys.size());
  ChunkType type = kHashable | kNormal;

}

TEST_F(VaultChunkstoreTest, BEH_MAID_LoadRandomChunk) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  for (int i = 0; i < kDefaultChunkCount; ++i) {
    std::string key = base::DecodeFromHex(kDefaultChunks[i][0]);
    ASSERT_EQ(0, chunkstore->DeleteChunk(key));
  }
  // test when chunkstore is empty
  std::string key("key"), val("val");
  ASSERT_EQ(kChunkstoreError, chunkstore->LoadRandomChunk(&key, &val));
  ASSERT_EQ(key, std::string(""));
  ASSERT_EQ(val, std::string(""));
  const int kNumberOfChunks = 10;
  // test with no hashable chunks (shouldn't return any)
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, false, 3, 32000,
                                          &nh_size, &nh_value, &nh_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_EQ(0, chunkstore->Store(nh_name.at(i), nh_value.at(i)));
  ASSERT_EQ(size_t(kNumberOfChunks), chunkstore->chunkstore_set_.size());
  key = "key";
  val = "val";
  ASSERT_EQ(kChunkstoreError, chunkstore->LoadRandomChunk(&key, &val));
  ASSERT_EQ("", key);
  ASSERT_EQ("", val);
  // test with hashable chunks
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, true, 3, 32000,
                                          &h_size, &h_value, &h_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_EQ(0, chunkstore->Store(h_name.at(i), h_value.at(i)));
  ASSERT_EQ(size_t(2 * kNumberOfChunks), chunkstore->chunkstore_set_.size());
  key = "key";
  val = "val";
  ASSERT_EQ(0, chunkstore->LoadRandomChunk(&key, &val));
  ASSERT_EQ(key, SHA512String(val));
  fs::path found("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, key, &found));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  ASSERT_FALSE(found.filename().empty());
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
  ASSERT_EQ(0, chunkstore->Load(key, &stored_value));
  ASSERT_EQ(val, stored_value);
}

TEST_F(VaultChunkstoreTest, BEH_MAID_HashCheckChunk) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, true, 3, 32000, &h_size, &h_value,
                                          &h_name));
  int test_chunk = 0;
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                     h_value.at(test_chunk)));
  boost::posix_time::ptime original_check_time;
  {
    boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
    chunk_set_by_non_hex_name::iterator itr = chunkstore->
        chunkstore_set_.get<non_hex_name>().find(h_name.at(test_chunk));
    original_check_time = (*itr).last_checked_;
  }
  // Allow thread to sleep to ensure different check times.
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
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
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  ASSERT_EQ(kHashCheckFailure,
            chunkstore->HashCheckChunk(nh_name.at(test_chunk)));
  // check using non-existent chunk
  std::string othername = SHA512String("otherfile");
  ASSERT_EQ(kInvalidChunkType, chunkstore->HashCheckChunk(othername));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_EQ(kIncorrectKeySize, chunkstore->HashCheckChunk(wrong_length_key));
}

TEST_F(VaultChunkstoreTest, BEH_MAID_Space) {
  const int kStartingAvailableSpace(100000);
  const int kStartingUsedSpace(250);
  const int kStartingFreeSpace(kStartingAvailableSpace - kStartingUsedSpace);
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), kStartingAvailableSpace, kStartingUsedSpace));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount),
            chunkstore->chunkstore_set_.size());
  // check space
  ASSERT_EQ(boost::uint64_t(kStartingAvailableSpace),
            chunkstore->available_space());
  ASSERT_EQ(boost::uint64_t(kStartingUsedSpace), chunkstore->used_space());
  ASSERT_EQ(boost::uint64_t(kStartingFreeSpace), chunkstore->FreeSpace());
  // store a chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, true, 1000, 10000, &h_size,
                                          &h_value, &h_name));
  ASSERT_EQ(0, chunkstore->Store(h_name.at(0), h_value.at(0)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount) + 1,
            chunkstore->chunkstore_set_.size());
  // check space has been amended correctly
  ASSERT_EQ(boost::uint64_t(kStartingAvailableSpace),
            chunkstore->available_space());
  ASSERT_EQ(boost::uint64_t(kStartingUsedSpace + h_size.at(0)),
            chunkstore->used_space());
  ASSERT_EQ(boost::uint64_t(kStartingFreeSpace - h_size.at(0)),
            chunkstore->FreeSpace());
  // delete the chunk
  ASSERT_EQ(0, chunkstore->DeleteChunk(h_name.at(0)));
  ASSERT_EQ(static_cast<size_t>(kDefaultChunkCount),
            chunkstore->chunkstore_set_.size());
  // check space has been amended correctly
  ASSERT_EQ(boost::uint64_t(kStartingAvailableSpace),
            chunkstore->available_space());
  ASSERT_EQ(boost::uint64_t(kStartingUsedSpace), chunkstore->used_space());
  ASSERT_EQ(boost::uint64_t(kStartingFreeSpace), chunkstore->FreeSpace());
  // check space can be amended
  chunkstore->set_available_space(kStartingAvailableSpace - 1);
  ASSERT_EQ(boost::uint64_t(kStartingAvailableSpace - 1),
            chunkstore->available_space());
  ASSERT_EQ(boost::uint64_t(kStartingUsedSpace), chunkstore->used_space());
  ASSERT_EQ(boost::uint64_t(kStartingFreeSpace - 1), chunkstore->FreeSpace());
}

TEST_F(VaultChunkstoreTest, BEH_MAID_ThreadedRandLoad) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 50;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, true, 10000, 32000,
                                          &h_size, &h_value, &h_name));
  test_chunkstore::ThreadedVaultTest tester(chunkstore);
  // Store chunks
  boost::posix_time::milliseconds store_delay(0);
  std::vector<boost::shared_ptr<int> > store_result;
  boost::thread_group store_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    store_result.push_back(res);
    store_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::Store, tester, store_delay,
        h_name.at(i), h_value.at(i), store_result.at(i)));
  }
  while (!chunkstore->Has(h_name.at(0)))
    boost::this_thread::yield();
  // Load random chunks
  const int kRandomLoads = 33;
  boost::posix_time::milliseconds rand_load_delay(0);
  std::vector<boost::shared_ptr<std::string> > rand_load_name;
  std::vector<boost::shared_ptr<std::string> > rand_load_value;
  std::vector<boost::shared_ptr<int> > rand_load_result;
  boost::thread_group rand_load_thread_group;
  for (int i = 0; i < kRandomLoads; ++i) {
    boost::shared_ptr<std::string> key(new std::string("Key"));
    rand_load_name.push_back(key);
    boost::shared_ptr<std::string> val(new std::string("Value"));
    rand_load_value.push_back(val);
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    rand_load_result.push_back(res);
    rand_load_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedVaultTest::LoadRandomChunk, tester,
        rand_load_delay, rand_load_name.at(i), rand_load_value.at(i),
        rand_load_result.at(i)));
  }
  rand_load_thread_group.join_all();
  store_thread_group.join_all();
  // Check all stores returned 0
  bool result(true);
  for (int i = 0; i < kNumberOfChunks; ++i) {
    if (*store_result.at(i) != 0) {
      for (int n = 0; n < i; n++) {
        if (h_name[i] == h_name[n]) {
          if (h_value[i] == h_value[n]) {
#ifdef DEBUG
            printf("Found a repeated chunk.\n");
#endif
          }
          break;
        }
      }
    }
    result = result && (*store_result.at(i) == 0);
  }
  ASSERT_TRUE(result);
  // Check all random loads returned true
  for (int i = 0; i < kRandomLoads; ++i)
    result = result && (*rand_load_result.at(i) == kSuccess);
  ASSERT_TRUE(result);
}

TEST_F(VaultChunkstoreTest, BEH_MAID_ThreadedCheckAll) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 50;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, true, 1000, 32000,
                                          &h_size, &h_value, &h_name));
  test_chunkstore::ThreadedVaultTest tester(chunkstore);
  // Store chunks
  boost::posix_time::milliseconds store_delay(0);
  std::vector<boost::shared_ptr<int> > store_result;
  boost::thread_group store_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    store_result.push_back(res);
    store_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::Store, tester, store_delay,
        h_name.at(i), h_value.at(i), store_result.at(i)));
  }
  while (!chunkstore->Has(h_name.at(0)))
    boost::this_thread::yield();
  // Check all chunks
  boost::posix_time::milliseconds check_all_delay(0);
  boost::shared_ptr<int> check_all_result(new int(5318008));  // NOLINT (Fraser) - Incorrect interpretation by lint.
  boost::shared_ptr< std::list<std::string> >
      failed_chunks(new std::list<std::string>);
  boost::thread check_all_thread(
      &test_chunkstore::ThreadedVaultTest::HashCheckAllChunks, tester,
      check_all_delay, false, failed_chunks, check_all_result);
  check_all_thread.join();
  store_thread_group.join_all();
  // Check all stores returned 0
  bool result(true);
  for (int i = 0; i < kNumberOfChunks; ++i)
    result = result && (*store_result.at(i) == 0);
  ASSERT_TRUE(result);
  ASSERT_EQ(size_t(0), (*failed_chunks).size());
}

TEST_F(VaultChunkstoreTest, BEH_MAID_CacheChunk) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1000, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  ASSERT_EQ(boost::uint64_t(0), chunkstore->space_used_by_cache());

  std::string content(base::RandomAlphaNumericString(1001));
  std::string chunkname(SHA512String(content));
  ASSERT_EQ(kNoSpaceForCaching, chunkstore->CacheChunk(chunkname, content));
  ASSERT_FALSE(chunkstore->Has(chunkname));
  ASSERT_EQ(fs::path(""),
            chunkstore->GetChunkPath(chunkname, (kHashable | kCache), false));
  ASSERT_EQ(boost::uint64_t(0), chunkstore->space_used_by_cache());
  ASSERT_EQ(boost::uint64_t(1000), chunkstore->FreeSpace());

  content = base::RandomAlphaNumericString(999);
  chunkname = SHA512String(content);
  ASSERT_EQ(kSuccess, chunkstore->CacheChunk(chunkname, content));
  ASSERT_TRUE(chunkstore->Has(chunkname));
  ASSERT_TRUE(fs::exists(chunkstore->GetChunkPath(chunkname,
                         (kHashable | kCache), false)));
  ASSERT_EQ(boost::uint64_t(999), chunkstore->space_used_by_cache());
  ASSERT_EQ(boost::uint64_t(1), chunkstore->FreeSpace());

  content = base::RandomAlphaNumericString(999);
  chunkname = SHA512String(content);
  ASSERT_EQ(kNoSpaceForCaching, chunkstore->CacheChunk(chunkname, content));
  ASSERT_FALSE(chunkstore->Has(chunkname));
  ASSERT_EQ(fs::path(""),
            chunkstore->GetChunkPath(chunkname, (kHashable | maidsafe::kCache),
                                     false));
  ASSERT_EQ(boost::uint64_t(999), chunkstore->space_used_by_cache());
  ASSERT_EQ(boost::uint64_t(1), chunkstore->FreeSpace());
}

TEST_F(VaultChunkstoreTest, BEH_MAID_FreeCacheSpace) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 20000, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  for (int i = 0; i < kDefaultChunkCount; ++i) {
    std::string key = base::DecodeFromHex(kDefaultChunks[i][0]);
    ASSERT_EQ(0, chunkstore->DeleteChunk(key));
  }
  ASSERT_EQ(boost::uint64_t(0), chunkstore->space_used_by_cache());
  ASSERT_EQ(kNoCacheSpaceToClear, chunkstore->FreeCacheSpace(1));

  int chunks_to_test(10);
  std::vector<std::string> chunknames;
  for (int n = 0; n < chunks_to_test; ++n) {
    std::string content(base::RandomAlphaNumericString(1000));
    std::string chunkname(SHA512String(content));
    ASSERT_EQ(kSuccess, chunkstore->CacheChunk(chunkname, content));
    chunknames.push_back(chunkname);
  }
  ASSERT_EQ(boost::uint64_t(1000) * chunks_to_test,
            chunkstore->space_used_by_cache());

  for (int a = 0; a < chunks_to_test; ++a) {
    ASSERT_EQ(boost::uint64_t(1000) * (chunks_to_test - a),
              chunkstore->space_used_by_cache());
    ASSERT_TRUE(chunkstore->Has(chunknames[a]));
    ASSERT_EQ(static_cast<size_t>(0) + chunks_to_test - a,
              chunkstore->chunkstore_set_.size());
    ASSERT_EQ(kSuccess, chunkstore->FreeCacheSpace(1000));
    ASSERT_FALSE(chunkstore->Has(chunknames[a]));
    ASSERT_EQ(boost::uint64_t(1000) * (chunks_to_test - a - 1),
              chunkstore->space_used_by_cache());
    ASSERT_EQ(static_cast<size_t>(0) + chunks_to_test - a - 1,
              chunkstore->chunkstore_set_.size());
  }
  ASSERT_EQ(boost::uint64_t(0), chunkstore->space_used_by_cache());
  ASSERT_EQ(kNoCacheSpaceToClear, chunkstore->FreeCacheSpace(1));

  chunknames.clear();
  for (int y = 0; y < chunks_to_test; ++y) {
    std::string content(base::RandomAlphaNumericString(1000));
    std::string chunkname(SHA512String(content));
    ASSERT_EQ(kSuccess, chunkstore->CacheChunk(chunkname, content));
    chunknames.push_back(chunkname);
  }
  ASSERT_EQ(boost::uint64_t(1000) * chunks_to_test,
            chunkstore->space_used_by_cache());

  ASSERT_TRUE(chunkstore->Has(chunknames[0]));
  ASSERT_TRUE(chunkstore->Has(chunknames[1]));
  ASSERT_EQ(static_cast<size_t>(0) + chunks_to_test,
            chunkstore->chunkstore_set_.size());
  ASSERT_EQ(kSuccess, chunkstore->FreeCacheSpace(1500));
  ASSERT_FALSE(chunkstore->Has(chunknames[0]));
  ASSERT_FALSE(chunkstore->Has(chunknames[1]));
  ASSERT_EQ(static_cast<size_t>(0) + chunks_to_test - 2,
            chunkstore->chunkstore_set_.size());
  ASSERT_EQ(size_t(1000 * (chunks_to_test - 2)),
            chunkstore->space_used_by_cache());
}

}  // namespace test

}  // namespace vault

}  // namespace maidsafe
