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
#include <maidsafe/crypto.h>
#include <maidsafe/utils.h>
#include "fs/filesystem.h"
#include "maidsafe/returncodes.h"
#include "maidsafe/vault/vaultchunkstore.h"
#include "protobuf/packet.pb.h"

namespace test_chunkstore {

void WaitForInitialisation(
    boost::shared_ptr<maidsafe_vault::VaultChunkStore> chunkstore,
    const boost::uint64_t &timeout) {
  boost::uint64_t count(0);
  while (count < timeout && !chunkstore->is_initialised()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
}

// Makes (num_chunks) chunks of length between min_chunk_size and max_chunk_size
// bytes.  min_chunk_size will be resized to 3 if too small and max_chunk_size
// will be resized to 1048576 (1 Mb) if too large.  If hashable is true,
// Hash(value) == name for each chunk.
bool MakeChunks(const boost::uint32_t &num_chunks,
                boost::shared_ptr<crypto::Crypto> cry_obj,
                bool hashable,
                const boost::uint64_t &min_chunk_size,
                const boost::uint64_t &max_chunk_size,
                std::vector<boost::uint64_t> *chunksize,
                std::vector<std::string> *value,
                std::vector<std::string> *name) {
  chunksize->clear();
  value->clear();
  name->clear();
  boost::uint64_t lower = min_chunk_size;
  boost::uint64_t upper = max_chunk_size;
  if (lower < 3)
    lower = 3;
  if (upper > 1048576)
    upper = 1048576;
  if (lower >= upper) {
    lower = 3;
    upper = 32000;
  }
  for (boost::uint32_t i = 0; i < num_chunks; ++i) {
    double factor = static_cast<double>(upper - lower) / RAND_MAX;
    boost::uint64_t chunk_size(lower + (rand() * factor));  // NOLINT (Fraser)
    // just in case!
    while (chunk_size > upper)
      chunk_size = chunk_size / 2;
    chunksize->push_back(chunk_size);
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

bool MakeKeys(const boost::uint32_t &num_keys,
              std::vector<std::string> *private_key,
              std::vector<std::string> *public_key) {
  for (boost::uint32_t i = 0; i < num_keys; ++i) {
    crypto::RsaKeyPair kp;
    kp.GenerateKeys(4096);
    private_key->push_back(kp.private_key());
    public_key->push_back(kp.public_key());
//    printf("Key pair %i :- pri: %s pub: %s\n", i,
//           base::EncodeToHex(kp.private_key()).substr(100, 110).c_str(),
//           base::EncodeToHex(kp.public_key()).substr(0, 60).c_str());
  }
  return true;
}

// Makes (num_packets) packets of length between min_packet_size and
// max_packet_size bytes.  min_packet_size will be resized to 3 if too small and
// max_packet_size will be resized to 1024 if too large.
bool MakePackets(const boost::uint32_t &num_packets,
                 boost::shared_ptr<crypto::Crypto> cry_obj,
                 const boost::uint64_t &min_packet_size,
                 const boost::uint64_t &max_packet_size,
                 std::vector<std::string> private_key,
                 std::vector<boost::uint64_t> *packetsize,
                 std::vector<maidsafe::GenericPacket> *value,
                 std::vector<std::string> *name) {
  packetsize->clear();
  value->clear();
  name->clear();
  if (private_key.size() != num_packets) {
    printf("private_key.size() (%u) != num_packets (%u)\n", private_key.size(),
           num_packets);
    return false;
  }
  boost::uint64_t lower = min_packet_size;
  boost::uint64_t upper = max_packet_size;
  if (lower < 3)
    lower = 3;
  if (upper > 1048576)
    upper = 1048576;
  if (lower >= upper) {
    lower = 3;
    upper = 32000;
  }
  for (boost::uint32_t i = 0; i < num_packets; ++i) {
    double factor = static_cast<double>(upper - lower) / RAND_MAX;
    boost::uint64_t packet_size(lower + (rand() * factor));  // NOLINT (Fraser)
    // just in case!
    while (packet_size > upper)
      packet_size = packet_size / 2;
    packetsize->push_back(packet_size);
    std::string data = base::RandomString(packetsize->at(i));
    maidsafe::GenericPacket gp;
    gp.set_data(data);
    gp.set_signature(cry_obj->AsymSign(data, "", private_key.at(i),
                     crypto::STRING_STRING));
    value->push_back(gp);
    name->push_back(cry_obj->Hash(base::itos(i), "", crypto::STRING_STRING,
                                  false));
  }
  return (packetsize->size() == num_packets && value->size() == num_packets &&
          name->size() == num_packets);
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
  std::string hex_filename = base::EncodeToHex(non_hex_filename);
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

class ThreadedTest {
 public:
  explicit ThreadedTest(boost::shared_ptr<maidsafe_vault::VaultChunkStore>
      chunkstore) : chunkstore_(chunkstore) {}
  void Has(const boost::posix_time::milliseconds &delay,
                const std::string &name,
                boost::shared_ptr<bool> result) {
    boost::this_thread::sleep(delay);
    *result = chunkstore_->Has(name);
  }
  void Store(const boost::posix_time::milliseconds &delay,
                  const std::string &name,
                  const std::string &value,
                  boost::shared_ptr<int> result) {
    boost::this_thread::sleep(delay);
    *result = chunkstore_->Store(name, value);
  }
  void DeleteChunk(const boost::posix_time::milliseconds &delay,
                   const std::string &name,
                   boost::shared_ptr<int> result) {
    boost::this_thread::sleep(delay);
    *result = chunkstore_->DeleteChunk(name);
  }
  void UpdateChunk(const boost::posix_time::milliseconds &delay,
                   const std::string &name,
                   const std::string &value,
                   boost::shared_ptr<int> result) {
    boost::this_thread::sleep(delay);
    *result = chunkstore_->UpdateChunk(name, value);
  }
  void Load(const boost::posix_time::milliseconds &delay,
                 const std::string &name,
                 boost::shared_ptr<std::string> value,
                 boost::shared_ptr<int> result) {
    boost::this_thread::sleep(delay);
    std::string val = *value;
    int res = chunkstore_->Load(name, &val);
    *value = val;
    *result = res;
  }
  void LoadRandomChunk(const boost::posix_time::milliseconds &delay,
                       boost::shared_ptr<std::string> name,
                       boost::shared_ptr<std::string> value,
                       boost::shared_ptr<int> result) {
    boost::this_thread::sleep(delay);
    std::string key = *name;
    std::string val = *value;
    int res = chunkstore_->LoadRandomChunk(&key, &val);
    *name = key;
    *value = val;
    *result = res;
  }
  void HashCheckChunk(const boost::posix_time::milliseconds &delay,
                      const std::string &name,
                      boost::shared_ptr<int> result) {
    boost::this_thread::sleep(delay);
    *result = chunkstore_->HashCheckChunk(name);
  }
  void HashCheckAllChunks(const boost::posix_time::milliseconds &delay,
                          bool delete_failures,
                          boost::shared_ptr< std::list<std::string> > failed,
                          boost::shared_ptr<int> result) {
    boost::this_thread::sleep(delay);
    std::list<std::string> failed_names = *failed;
    bool res = chunkstore_->HashCheckAllChunks(delete_failures, &failed_names);
    *failed = failed_names;
    *result = res;
  }
  void ChangeChunkType(const boost::posix_time::milliseconds &delay,
                       const std::string &name,
                       maidsafe::ChunkType type,
                       boost::shared_ptr<int> result) {
    boost::this_thread::sleep(delay);
    *result = chunkstore_->ChangeChunkType(name, type);
  }
 private:
  boost::shared_ptr<maidsafe_vault::VaultChunkStore> chunkstore_;
};

}  // namespace test_chunkstore

namespace maidsafe_vault {

class ChunkstoreTest : public testing::Test {
 protected:
  ChunkstoreTest()
      : storedir(file_system::FileSystem::TempDir() + "/maidsafe_TestChunkstore"
                 + base::itos_ul(base::random_32bit_uinteger()), fs::native),
        file_path("chunk.txt", fs::native),
        file_content("ABC"),
        hash_file_content(""),
        other_hash(""),
        cry_obj(new crypto::Crypto),
        h_size(),
        nh_size(),
        p_size(),
        h_value(),
        nh_value(),
        h_name(),
        nh_name(),
        p_name(),
        private_key(),
        public_key(),
        p_value() {}
  void SetUp() {
    cry_obj->set_symm_algorithm(crypto::AES_256);
    cry_obj->set_hash_algorithm(crypto::SHA_512);
    try {
      fs::remove_all(storedir);
      fs::remove(file_path);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    fs::ofstream ofs;
    ofs.open(file_path);
    ofs << "ABC";
    ofs.close();
    hash_file_content = cry_obj->Hash(file_content, "", crypto::STRING_STRING,
        false);
    other_hash = cry_obj->Hash("CBA", "", crypto::STRING_STRING, false);
  }
  void TearDown() {
    try {
      fs::remove_all(storedir);
      fs::remove(file_path);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
  fs::path storedir, file_path;
  std::string file_content, hash_file_content, other_hash;
  boost::shared_ptr<crypto::Crypto> cry_obj;
  std::vector<boost::uint64_t> h_size, nh_size, p_size;
  std::vector<std::string> h_value, nh_value, h_name, nh_name, p_name;
  std::vector<std::string> private_key, public_key;
  std::vector<maidsafe::GenericPacket> p_value;
};

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreInit) {
  std::string invalid_path_length(257, ' ');
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      invalid_path_length, 1073741824, 0));
  ASSERT_FALSE(chunkstore->Init());
  ASSERT_FALSE(chunkstore->is_initialised());
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, true, 3, 32000, &h_size,
                                          &h_value, &h_name));
  ASSERT_FALSE(chunkstore->Has(h_name.at(0)));
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->Store(h_name.at(0), h_value.at(0)));
  ASSERT_TRUE(fs::exists(file_path));
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->Store(h_name.at(0), file_path));
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->AddChunkToOutgoing(h_name.at(0), h_value.at(0)));
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->DeleteChunk(h_name.at(0)));
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->UpdateChunk(h_name.at(0), h_value.at(0)));
  std::string value("value");
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->Load(h_name.at(0), &value));
  ASSERT_EQ("", value);
  std::string key("key");
  value = "value";
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
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->HashCheckChunk(h_name.at(0)));
  failed_keys.push_back("key");
  ASSERT_NE(size_t(0), failed_keys.size());
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->HashCheckAllChunks(true, &failed_keys));
  ASSERT_EQ(size_t(0), failed_keys.size());
  maidsafe::ChunkType type = maidsafe::kHashable | maidsafe::kNormal;
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->ChangeChunkType(h_name.at(0), type));
  ASSERT_TRUE(test_chunkstore::MakeKeys(1, &private_key, &public_key));
  ASSERT_TRUE(test_chunkstore::MakePackets(1, cry_obj, 3, 1024, private_key,
      &p_size, &p_value, &p_name));
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->StorePacket(p_name.at(0), p_value.at(0)));
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->AppendToPacket(p_name.at(0), p_value.at(0),
            public_key.at(0)));
  std::vector<maidsafe::GenericPacket> gps;
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->DeletePacket(p_name.at(0), gps, public_key.at(0)));
  gps.push_back(p_value.at(0));
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->OverwritePacket(p_name.at(0), gps, public_key.at(0)));
  ASSERT_EQ(kChunkstoreUninitialised,
            chunkstore->LoadPacket(p_name.at(0), &gps));
  boost::shared_ptr<VaultChunkStore> chunkstore1(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore1->Init());
  test_chunkstore::WaitForInitialisation(chunkstore1, 60000);
  ASSERT_TRUE(chunkstore1->is_initialised());
  ASSERT_TRUE(chunkstore1->Init());
  ASSERT_TRUE(chunkstore1->is_initialised());
  ASSERT_EQ(storedir.string(), chunkstore1->ChunkStoreDir());
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreGetChunkPath) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  std::string test_chunk_name = cry_obj->Hash("test", "", crypto::STRING_STRING,
                                              false);
  fs::path test_chunk_path(storedir);
  test_chunk_path /= "Hashable";
  test_chunk_path /= "Normal";
  test_chunk_path /= "e";
  test_chunk_path /= "e";
  test_chunk_path /= "2";
  test_chunk_path /= base::EncodeToHex(test_chunk_name);
  // Chunk name empty
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath("",
            (maidsafe::kHashable | maidsafe::kNormal), false));
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath("",
            (maidsafe::kHashable | maidsafe::kNormal), true));
  // Chunk name not kKeySize in length
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath("A",
            (maidsafe::kHashable | maidsafe::kNormal), false));
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath("A",
            (maidsafe::kHashable | maidsafe::kNormal), true));
  // Invalid chunk type
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath(test_chunk_name, 3, false));
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath(test_chunk_name, 3, true));
  // Valid name, but chunk doesn't exist and create_path == false
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath(test_chunk_name,
            (maidsafe::kHashable | maidsafe::kNormal), false));
  // All valid - if this fails, check permissions to create dir in /temp
  ASSERT_EQ(test_chunk_path, chunkstore->GetChunkPath(test_chunk_name,
            (maidsafe::kHashable | maidsafe::kNormal), true));
  // OK now - chunk exists
  ASSERT_EQ(test_chunk_path, chunkstore->GetChunkPath(test_chunk_name,
            (maidsafe::kHashable | maidsafe::kNormal), false));
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreStoreChunk) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  ASSERT_EQ(size_t(0), chunkstore->chunkstore_set_.size());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, true, 3, 32000, &h_size,
                                          &h_value, &h_name));
  int test_chunk = 0;
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                 h_value.at(test_chunk)));
  ASSERT_EQ(size_t(1), chunkstore->chunkstore_set_.size());
  fs::path found("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  // check we can't overwrite existing value using Store
  ASSERT_TRUE(fs::exists(file_path));
  ASSERT_EQ(kInvalidChunkType,
            chunkstore->Store(h_name.at(test_chunk), file_path));
  ASSERT_EQ(kInvalidChunkType,
            chunkstore->Store(h_name.at(test_chunk), std::string("New value")));
  ASSERT_EQ(size_t(1), chunkstore->chunkstore_set_.size());
  // check contents of file
  ASSERT_NE(found.filename(), "");
  boost::uint64_t chunk_size = fs::file_size(found);
  ASSERT_EQ(h_size.at(test_chunk), chunk_size);
  ASSERT_EQ(chunk_size, chunkstore->GetChunkSize(h_name.at(test_chunk)));
  boost::scoped_ptr<char> temp1(new char[chunk_size]);
  fs::ifstream fstr1;
  fstr1.open(found, std::ios_base::binary);
  fstr1.read(temp1.get(), chunk_size);
  fstr1.close();
  std::string stored_value1(static_cast<const char*>(temp1.get()), chunk_size);
  ASSERT_EQ(h_value.at(test_chunk), stored_value1);
  // move to Outgoing and check we can store again
  ASSERT_EQ(0, chunkstore->ChangeChunkType(h_name.at(test_chunk),
            maidsafe::kHashable | maidsafe::kOutgoing));
  ASSERT_EQ(size_t(1), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kOutgoingLeaf_));
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                 h_value.at(test_chunk)));
  ASSERT_EQ(size_t(1), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kOutgoingLeaf_));
  // check a hashable chunk which is already cached can be stored
  ASSERT_EQ(0, chunkstore->ChangeChunkType(h_name.at(test_chunk),
            maidsafe::kHashable | maidsafe::kCache));
  ASSERT_EQ(size_t(1), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kCacheLeaf_));
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                 h_value.at(test_chunk)));
  ASSERT_EQ(size_t(1), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  ASSERT_EQ(0, chunkstore->ChangeChunkType(h_name.at(test_chunk),
            maidsafe::kHashable | maidsafe::kTempCache));
  ASSERT_EQ(size_t(1), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kTempCacheLeaf_));
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                 h_value.at(test_chunk)));
  ASSERT_EQ(size_t(1), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  // check we can add a chunk which is stored as a file
  ASSERT_EQ(0, chunkstore->Store(hash_file_content, file_path));
  ASSERT_EQ(size_t(2), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, hash_file_content, &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  ASSERT_EQ(size_t(3), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, nh_name.at(test_chunk),
                                        &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found,
      chunkstore->kNonHashableLeaf_, chunkstore->kNormalLeaf_));
  // check contents of file
  ASSERT_NE(found.filename(), "");
  chunk_size = fs::file_size(found);
  ASSERT_EQ(nh_size.at(test_chunk), chunk_size);
  ASSERT_EQ(chunk_size, chunkstore->GetChunkSize(nh_name.at(test_chunk)));
  boost::scoped_ptr<char> temp2(new char[chunk_size]);
  fs::ifstream fstr2;
  fstr2.open(found, std::ios_base::binary);
  fstr2.read(temp2.get(), chunk_size);
  fstr2.close();
  std::string stored_value2(static_cast<const char*>(temp2.get()), chunk_size);
  ASSERT_EQ(nh_value.at(test_chunk), stored_value2);
  // check we can add a chunk which is stored as a file
  ASSERT_EQ(0, chunkstore->Store(other_hash, file_path));
  ASSERT_EQ(size_t(4), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, other_hash, &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found,
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  // check values can't be stored under keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_EQ(maidsafe::kIncorrectKeySize,
      chunkstore->Store(wrong_length_key, h_value.at(0)));
  ASSERT_EQ(size_t(4), chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(test_chunkstore::FindFile(storedir, wrong_length_key, &found));
  ASSERT_FALSE(chunkstore->Has(wrong_length_key));
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreAddChunkToOutgoing) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  ASSERT_EQ(size_t(0), chunkstore->chunkstore_set_.size());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, true, 3, 32000, &h_size,
                                          &h_value, &h_name));
  int test_chunk = 0;
  ASSERT_EQ(0, chunkstore->AddChunkToOutgoing(h_name.at(test_chunk),
                                              h_value.at(test_chunk)));
  ASSERT_EQ(size_t(1), chunkstore->chunkstore_set_.size());
  fs::path found("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kOutgoingLeaf_));
  // try to add file again (should return kChunkExistsInChunkstore as file now
  // stored)
  ASSERT_EQ(maidsafe::kChunkExistsInChunkstore,
            chunkstore->AddChunkToOutgoing(h_name.at(test_chunk),
                                           h_value.at(test_chunk)));

  // TODO(Team#5#): 2009-04-06 - Decide when to overwrite file using Store
  //  std::string new_val("New value");
  //  ASSERT_NE(0, chunkstore->Store(h_name.at(test_chunk), new_val));
  //  ASSERT_EQ(size_t(1), chunkstore->chunkstore_set_.size());

  // check contents of file
  ASSERT_NE(found.filename(), "");
  boost::uint64_t chunk_size = fs::file_size(found);
  ASSERT_EQ(h_size.at(test_chunk), chunk_size);
  ASSERT_EQ(chunk_size, chunkstore->GetChunkSize(h_name.at(test_chunk)));
  boost::scoped_ptr<char> temp1(new char[chunk_size]);
  fs::ifstream fstr1;
  fstr1.open(found, std::ios_base::binary);
  fstr1.read(temp1.get(), chunk_size);
  fstr1.close();
  std::string stored_value1(static_cast<const char*>(temp1.get()), chunk_size);
  ASSERT_EQ(h_value.at(test_chunk), stored_value1);
  // check we can add a chunk which is stored as a file
  ASSERT_EQ(0, chunkstore->AddChunkToOutgoing(hash_file_content, file_path));
  ASSERT_EQ(size_t(2), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, hash_file_content, &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found, chunkstore->kHashableLeaf_,
                                             chunkstore->kOutgoingLeaf_));
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_EQ(0, chunkstore->AddChunkToOutgoing(nh_name.at(test_chunk),
                                              nh_value.at(test_chunk)));
  ASSERT_EQ(size_t(3), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, nh_name.at(test_chunk),
                                        &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found,
      chunkstore->kNonHashableLeaf_, chunkstore->kOutgoingLeaf_));
  // try to add file again (should return kChunkExistsInChunkstore as file now
  // stored)
  ASSERT_EQ(maidsafe::kChunkExistsInChunkstore,
            chunkstore->AddChunkToOutgoing(h_name.at(test_chunk),
                                           h_value.at(test_chunk)));
  // check contents of file
  ASSERT_NE(found.filename(), "");
  chunk_size = fs::file_size(found);
  ASSERT_EQ(nh_size.at(test_chunk), chunk_size);
  ASSERT_EQ(chunk_size, chunkstore->GetChunkSize(nh_name.at(test_chunk)));
  boost::scoped_ptr<char> temp2(new char[chunk_size]);
  fs::ifstream fstr2;
  fstr2.open(found, std::ios_base::binary);
  fstr2.read(temp2.get(), chunk_size);
  fstr2.close();
  std::string stored_value2(static_cast<const char*>(temp2.get()), chunk_size);
  ASSERT_EQ(nh_value.at(test_chunk), stored_value2);
  // check we can add a chunk which is stored as a file
  ASSERT_EQ(0, chunkstore->AddChunkToOutgoing(other_hash, file_path));
  ASSERT_EQ(size_t(4), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, other_hash, &found));
  // check file has been added to correct directory
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found,
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kOutgoingLeaf_));
  // check values can't be stored under keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_EQ(kIncorrectKeySize,
            chunkstore->Store(wrong_length_key, h_value.at(0)));
  ASSERT_EQ(size_t(4), chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(test_chunkstore::FindFile(storedir, wrong_length_key, &found));
  ASSERT_FALSE(chunkstore->Has(wrong_length_key));
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreLoadChunk) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, true, 3, 32000, &h_size,
                                          &h_value, &h_name));
  int test_chunk = 0;
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                     h_value.at(test_chunk)));
  std::string rec_value("Value");
  ASSERT_EQ(0, chunkstore->Load(h_name.at(test_chunk), &rec_value));
  ASSERT_EQ(h_value.at(test_chunk), rec_value);
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  rec_value = "Value";
  ASSERT_EQ(0, chunkstore->Load(nh_name.at(test_chunk), &rec_value));
  ASSERT_EQ(nh_value.at(test_chunk), rec_value);
  // check using non-existent chunk
  std::string othername = cry_obj->Hash("otherfile", "", crypto::STRING_STRING,
                                        false);
  ASSERT_EQ(kInvalidChunkType, chunkstore->Load(othername, &rec_value));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_EQ(kIncorrectKeySize, chunkstore->Load(wrong_length_key, &rec_value));
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreHasChunk) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, true, 3, 32000, &h_size,
                                          &h_value, &h_name));
  int test_chunk = 0;
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                 h_value.at(test_chunk)));
  ASSERT_TRUE(chunkstore->Has(h_name.at(test_chunk)));
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  ASSERT_TRUE(chunkstore->Has(nh_name.at(test_chunk)));
  // check using non-existent chunk
  std::string othername = cry_obj->Hash("otherfile", "", crypto::STRING_STRING,
                                        false);
  ASSERT_FALSE(chunkstore->Has(othername));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_FALSE(chunkstore->Has(wrong_length_key));
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreDeleteChunk) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  ASSERT_EQ(size_t(0), chunkstore->chunkstore_set_.size());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, true, 3, 32000, &h_size,
                                          &h_value, &h_name));
  int test_chunk = 0;
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                     h_value.at(test_chunk)));
  ASSERT_EQ(size_t(1), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(chunkstore->Has(h_name.at(test_chunk)));
  fs::path found("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, h_name.at(test_chunk),
                                        &found));
  ASSERT_NE(found.filename(), "");
  ASSERT_TRUE(fs::exists(found));
  ASSERT_EQ(0, chunkstore->DeleteChunk(h_name.at(test_chunk)));
  ASSERT_EQ(size_t(0), chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(chunkstore->Has(h_name.at(test_chunk)));
  ASSERT_FALSE(fs::exists(found));
  ASSERT_EQ(0, chunkstore->DeleteChunk(h_name.at(test_chunk)));
  ASSERT_EQ(size_t(0), chunkstore->chunkstore_set_.size());
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  ASSERT_EQ(size_t(1), chunkstore->chunkstore_set_.size());
  ASSERT_TRUE(chunkstore->Has(nh_name.at(test_chunk)));
  found = fs::path("");
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, nh_name.at(test_chunk),
                                        &found));
  ASSERT_NE(found.filename(), "");
  ASSERT_TRUE(fs::exists(found));
  ASSERT_EQ(0, chunkstore->DeleteChunk(nh_name.at(test_chunk)));
  ASSERT_EQ(size_t(0), chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(chunkstore->Has(nh_name.at(test_chunk)));
  ASSERT_FALSE(fs::exists(found));
  ASSERT_EQ(0, chunkstore->DeleteChunk(nh_name.at(test_chunk)));
  ASSERT_EQ(size_t(0), chunkstore->chunkstore_set_.size());
  // check using non-existent chunk
  std::string othername = cry_obj->Hash("otherfile", "", crypto::STRING_STRING,
                                        false);
  ASSERT_EQ(0, chunkstore->DeleteChunk(othername));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_EQ(kIncorrectKeySize, chunkstore->DeleteChunk(wrong_length_key));
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreLoadRandomChunk) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // test when chunkstore is empty
  std::string key("key"), val("val");
  ASSERT_EQ(kChunkstoreError, chunkstore->LoadRandomChunk(&key, &val));
  ASSERT_EQ(key, std::string(""));
  ASSERT_EQ(val, std::string(""));
  const int kNumberOfChunks = 10;
  // test with no hashable chunks (shouldn't return any)
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, false, 3,
                                         32000, &nh_size, &nh_value, &nh_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_EQ(0, chunkstore->Store(nh_name.at(i), nh_value.at(i)));
  ASSERT_EQ(size_t(kNumberOfChunks), chunkstore->chunkstore_set_.size());
  key = "key";
  val = "val";
  ASSERT_EQ(kChunkstoreError, chunkstore->LoadRandomChunk(&key, &val));
  ASSERT_EQ("", key);
  ASSERT_EQ("", val);
  // test with hashable chunks
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true, 3,
                                          32000, &h_size, &h_value, &h_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_EQ(0, chunkstore->Store(h_name.at(i), h_value.at(i)));
  ASSERT_EQ(size_t(2 * kNumberOfChunks), chunkstore->chunkstore_set_.size());
  key = "key";
  val = "val";
  ASSERT_EQ(0, chunkstore->LoadRandomChunk(&key, &val));
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
  ASSERT_EQ(0, chunkstore->Load(key, &stored_value));
  ASSERT_EQ(val, stored_value);
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreUpdateChunk) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(2, cry_obj, true, 3, 32000, &h_size,
                                          &h_value, &h_name));
  ASSERT_NE(h_value.at(0), h_value.at(1));
  ASSERT_EQ(size_t(0), chunkstore->GetChunkSize(h_name.at(0)));
  ASSERT_EQ(0, chunkstore->Store(h_name.at(0), h_value.at(0)));
  ASSERT_EQ(h_size.at(0), chunkstore->GetChunkSize(h_name.at(0)));
  ASSERT_EQ(0, chunkstore->UpdateChunk(h_name.at(0), h_value.at(1)));
  std::string rec_value("Value");
  ASSERT_EQ(0, chunkstore->Load(h_name.at(0), &rec_value));
  ASSERT_EQ(h_value.at(1), rec_value);
  ASSERT_EQ(h_size.at(1), chunkstore->GetChunkSize(h_name.at(0)));
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(2, cry_obj, true, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_NE(nh_value.at(0), nh_value.at(1));
  ASSERT_EQ(size_t(0), chunkstore->GetChunkSize(nh_name.at(0)));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(0), nh_value.at(0)));
  ASSERT_EQ(nh_size.at(0), chunkstore->GetChunkSize(nh_name.at(0)));
  ASSERT_EQ(0, chunkstore->UpdateChunk(nh_name.at(0), nh_value.at(1)));
  rec_value = "Value";
  ASSERT_EQ(0, chunkstore->Load(nh_name.at(0), &rec_value));
  ASSERT_EQ(nh_value.at(1), rec_value);
  ASSERT_EQ(nh_size.at(1), chunkstore->GetChunkSize(nh_name.at(0)));
  // check using non-existent chunk
  std::string othername = cry_obj->Hash("otherfile", "", crypto::STRING_STRING,
                                        false);
  ASSERT_EQ(kInvalidChunkType,
            chunkstore->UpdateChunk(othername, h_value.at(0)));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_EQ(kIncorrectKeySize,
            chunkstore->UpdateChunk(wrong_length_key, h_value.at(0)));
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreHashCheckChunk) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // check using hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, true, 3, 32000, &h_size,
                                          &h_value, &h_name));
  int test_chunk = 0;
  ASSERT_EQ(0, chunkstore->Store(h_name.at(test_chunk),
                                     h_value.at(test_chunk)));
  boost::posix_time::ptime original_check_time;
  {
    boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
    maidsafe::chunk_set_by_non_hex_name::iterator itr = chunkstore->
        chunkstore_set_.get<maidsafe::non_hex_name>().find(
        h_name.at(test_chunk));
    original_check_time = (*itr).last_checked_;
  }
  // Allow thread to sleep to ensure different check times.
  boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  ASSERT_EQ(0, chunkstore->HashCheckChunk(h_name.at(test_chunk)));
  boost::posix_time::ptime later_check_time;
  {
    boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
    maidsafe::chunk_set_by_non_hex_name::iterator itr = chunkstore->
        chunkstore_set_.get<maidsafe::non_hex_name>().find(
        h_name.at(test_chunk));
    later_check_time = (*itr).last_checked_;
  }
  ASSERT_GT(later_check_time - original_check_time,
            boost::posix_time::milliseconds(0));
  // check using non-hashable chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(test_chunk),
                                     nh_value.at(test_chunk)));
  ASSERT_EQ(kHashCheckFailure,
            chunkstore->HashCheckChunk(nh_name.at(test_chunk)));
  // check using non-existent chunk
  std::string othername = cry_obj->Hash("otherfile", "", crypto::STRING_STRING,
                                        false);
  ASSERT_EQ(kInvalidChunkType, chunkstore->HashCheckChunk(othername));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_EQ(kIncorrectKeySize, chunkstore->HashCheckChunk(wrong_length_key));
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreChangeChunkType) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = chunkstore->path_map_.size();  // 8
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true, 3,
                                          32000, &h_size, &h_value, &h_name));
  ASSERT_TRUE(test_chunkstore::MakeChunks(2, cry_obj, false, 3, 32000, &nh_size,
                                          &nh_value, &nh_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_EQ(0, chunkstore->Store(h_name.at(i), h_value.at(i)));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(0), nh_value.at(0)));
  ASSERT_EQ(0, chunkstore->Store(nh_name.at(1), nh_value.at(1)));
  // Move a chunk to each of the different types and the single chunk to the
  // original type of all the others.
  maidsafe::path_map_iterator path_map_itr;
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
      maidsafe::chunk_set_by_non_hex_name::iterator itr = chunkstore->
          chunkstore_set_.get<maidsafe::non_hex_name>().find(h_name.at(i));
      ASSERT_EQ((*path_map_itr).first, (*itr).type_);
    }
    ++i;
  }
  path_map_itr = chunkstore->path_map_.begin();
  {
    boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
    maidsafe::chunk_set_by_non_hex_name::iterator itr = chunkstore->
        chunkstore_set_.get<maidsafe::non_hex_name>().find(nh_name.at(0));
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
  maidsafe::ChunkType type = 3;
  ASSERT_EQ(kInvalidChunkType,
            chunkstore->ChangeChunkType(nh_name.at(1), type));
  type = (maidsafe::kNonHashable | maidsafe::kNormal);
  {
    boost::mutex::scoped_lock lock(chunkstore->chunkstore_set_mutex_);
    maidsafe::chunk_set_by_non_hex_name::iterator itr = chunkstore->
        chunkstore_set_.get<maidsafe::non_hex_name>().find(nh_name.at(1));
    ASSERT_EQ(type, (*itr).type_);
  }
  ASSERT_TRUE(test_chunkstore::FindFile(storedir, nh_name.at(1), &found_path));
  ASSERT_TRUE(test_chunkstore::CheckFilePath(found_path,
                                             chunkstore->kNonHashableLeaf_,
                                             chunkstore->kNormalLeaf_));
  // check using non-existent chunk
  std::string othername = cry_obj->Hash("otherfile", "", crypto::STRING_STRING,
                                        false);
  ASSERT_EQ(kChunkstoreError, chunkstore->ChangeChunkType(othername,
            (maidsafe::kHashable | maidsafe::kNormal)));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_EQ(kIncorrectKeySize, chunkstore->ChangeChunkType(wrong_length_key,
            (maidsafe::kHashable | maidsafe::kNormal)));
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreChunkType) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = chunkstore->path_map_.size();  // 8
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true, 3,
                                          32000, &h_size, &h_value, &h_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_EQ(0, chunkstore->Store(h_name.at(i), h_value.at(i)));
  // Move a chunk to each of the different types.
  maidsafe::path_map_iterator path_map_itr;
  int i = 0;
  std::vector<fs::path> found;
  for (path_map_itr = chunkstore->path_map_.begin();
       path_map_itr != chunkstore->path_map_.end();
       ++path_map_itr) {
    ASSERT_EQ(0, chunkstore->ChangeChunkType(h_name.at(i),
                                             (*path_map_itr).first));
    ++i;
  }
  // Check each chunk has the correct type
  i = 0;
  for (path_map_itr = chunkstore->path_map_.begin();
       path_map_itr != chunkstore->path_map_.end();
       ++path_map_itr) {
    ASSERT_EQ((*path_map_itr).first, chunkstore->chunk_type(h_name.at(i)));
    ++i;
  }
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreSpace) {
  const int kStartingAvailableSpace(100000);
  const int kStartingUsedSpace(250);
  const int kStartingFreeSpace(kStartingAvailableSpace - kStartingUsedSpace);
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), kStartingAvailableSpace, kStartingUsedSpace));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  ASSERT_EQ(size_t(0), chunkstore->chunkstore_set_.size());
  // check space
  ASSERT_EQ(boost::uint64_t(kStartingAvailableSpace),
            chunkstore->available_space());
  ASSERT_EQ(boost::uint64_t(kStartingUsedSpace), chunkstore->used_space());
  ASSERT_EQ(boost::uint64_t(kStartingFreeSpace), chunkstore->FreeSpace());
  // store a chunk
  ASSERT_TRUE(test_chunkstore::MakeChunks(1, cry_obj, true, 1000, 10000,
                                          &h_size, &h_value, &h_name));
  ASSERT_EQ(0, chunkstore->Store(h_name.at(0), h_value.at(0)));
  ASSERT_EQ(size_t(1), chunkstore->chunkstore_set_.size());
  // check space has been amended correctly
  ASSERT_EQ(boost::uint64_t(kStartingAvailableSpace),
            chunkstore->available_space());
  ASSERT_EQ(boost::uint64_t(kStartingUsedSpace + h_size.at(0)),
            chunkstore->used_space());
  ASSERT_EQ(boost::uint64_t(kStartingFreeSpace - h_size.at(0)),
            chunkstore->FreeSpace());
  // delete the chunk
  ASSERT_EQ(0, chunkstore->DeleteChunk(h_name.at(0)));
  ASSERT_EQ(size_t(0), chunkstore->chunkstore_set_.size());
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

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreReuseDirectory) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 5 * chunkstore->path_map_.size();  // 40
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true, 3,
                                          32000, &h_size, &h_value, &h_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_EQ(0, chunkstore->Store(h_name.at(i), h_value.at(i)));
  // Move 5 chunks to each of the different types.
  maidsafe::path_map_iterator path_map_itr;
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
  boost::shared_ptr<VaultChunkStore> chunkstore1(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore1->Init());
  test_chunkstore::WaitForInitialisation(chunkstore1, 60000);
  ASSERT_TRUE(chunkstore1->is_initialised());
  ASSERT_EQ(size_t(kNumberOfChunks), chunkstore1->chunkstore_set_.size());
  for (int k = 0; k < kNumberOfChunks; k++) {
    ASSERT_TRUE(chunkstore1->Has(h_name.at(k)));
    std::string rec_value("Value");
    ASSERT_EQ(0, chunkstore1->Load(h_name.at(k), &rec_value));
  }
  // creating a new chunkstore that has same root dir but with one of the
  // hashable chunks modified to fail hash check
  ASSERT_EQ(0, chunkstore->UpdateChunk(h_name.at(0), "modified content"));
  boost::shared_ptr<VaultChunkStore> chunkstore2(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore2->Init());
  test_chunkstore::WaitForInitialisation(chunkstore2, 60000);
  ASSERT_TRUE(chunkstore2->is_initialised());
  ASSERT_EQ(size_t(kNumberOfChunks - 1), chunkstore2->chunkstore_set_.size());
  ASSERT_FALSE(chunkstore2->Has(h_name.at(0)));
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreClear) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 5 * chunkstore->path_map_.size();  // 40
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true, 3,
                                          32000, &h_size, &h_value, &h_name));

  // Clear empty chunk store
  ASSERT_EQ(0, chunkstore->Clear());
  ASSERT_EQ(size_t(0), chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(fs::exists(chunkstore->kChunkstorePath_));

  // Empty with one chunk in
  ASSERT_TRUE(chunkstore->Init());
  ASSERT_EQ(0, chunkstore->Store(h_name.at(0), h_value.at(0)));
  std::string tempval;
  ASSERT_EQ(0, chunkstore->Load(h_name.at(0), &tempval));
  ASSERT_EQ(h_value.at(0), tempval);
  ASSERT_EQ(size_t(1), chunkstore->chunkstore_set_.size());
  ASSERT_EQ(0, chunkstore->Clear());
  ASSERT_EQ(size_t(0), chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(fs::exists(chunkstore->kChunkstorePath_));

  // Empty with kNumberOfChunks chunks
  ASSERT_TRUE(chunkstore->Init());
  for (size_t i = 0; i < h_value.size(); ++i)
    ASSERT_EQ(0, chunkstore->Store(h_name.at(i), h_value.at(i)));
  ASSERT_EQ(size_t(kNumberOfChunks), chunkstore->chunkstore_set_.size());
  ASSERT_EQ(0, chunkstore->Clear());
  ASSERT_EQ(size_t(0), chunkstore->chunkstore_set_.size());
  ASSERT_FALSE(fs::exists(chunkstore->kChunkstorePath_));
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreGetAllChunks) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // Check with empty chunkstore.
  std::list<std::string> ret_chunk_names;
  chunkstore->GetAllChunks(&ret_chunk_names);
  ASSERT_EQ(size_t(0), ret_chunk_names.size());
  // Put 50 hashable and 50 non-hashable chunks in and check again.
  const int kNumberOfChunks = 50;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true, 3,
                                          32000, &h_size, &h_value, &h_name));
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, false, 3,
                                         32000, &nh_size, &nh_value, &nh_name));
  for (int i = 0; i < kNumberOfChunks; ++i) {
    ASSERT_EQ(0, chunkstore->Store(h_name.at(i), h_value.at(i)));
    ASSERT_EQ(0, chunkstore->Store(nh_name.at(i), nh_value.at(i)));
  }
  chunkstore->GetAllChunks(&ret_chunk_names);
  ASSERT_EQ(size_t(2 * kNumberOfChunks), ret_chunk_names.size());
  for (int i = 0; i < kNumberOfChunks; ++i) {
    ret_chunk_names.remove(h_name.at(i));
    ret_chunk_names.remove(nh_name.at(i));
  }
  ASSERT_EQ(size_t(0), ret_chunk_names.size());
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreCheckAllChunks) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 5 * chunkstore->path_map_.size();  // 40
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true, 3,
                                          32000, &h_size, &h_value, &h_name));
  for (int i = 0; i < kNumberOfChunks; ++i)
    ASSERT_EQ(0, chunkstore->Store(h_name.at(i), h_value.at(i)));
  // Move 5 chunks to each of the different types.
  maidsafe::path_map_iterator path_map_itr;
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
  ASSERT_EQ(size_t(0), failed_chunk_names.size());
  ASSERT_EQ(0, chunkstore->HashCheckAllChunks(true, &failed_chunk_names));
  ASSERT_EQ(size_t(0), failed_chunk_names.size());
  // Modify four of the hashable files (one in each subdirectory).
  std::string modified_content("modified content");
  ASSERT_EQ(0, chunkstore->UpdateChunk(h_name.at(0), modified_content));
  ASSERT_EQ(0, chunkstore->UpdateChunk(h_name.at(5), modified_content));
  ASSERT_EQ(0, chunkstore->UpdateChunk(h_name.at(10), modified_content));
  ASSERT_EQ(0, chunkstore->UpdateChunk(h_name.at(15), modified_content));
  // Check failed files don't get removed
  ASSERT_EQ(0, chunkstore->HashCheckAllChunks(false, &failed_chunk_names));
  ASSERT_TRUE(chunkstore->Has(h_name.at(0)));
  ASSERT_TRUE(chunkstore->Has(h_name.at(5)));
  ASSERT_TRUE(chunkstore->Has(h_name.at(10)));
  ASSERT_TRUE(chunkstore->Has(h_name.at(15)));
  std::string rec_value("Value");
  ASSERT_EQ(0, chunkstore->Load(h_name.at(0), &rec_value));
  ASSERT_EQ(modified_content, rec_value);
  rec_value = "Value";
  ASSERT_EQ(0, chunkstore->Load(h_name.at(5), &rec_value));
  ASSERT_EQ(modified_content, rec_value);
  rec_value = "Value";
  ASSERT_EQ(0, chunkstore->Load(h_name.at(10), &rec_value));
  ASSERT_EQ(modified_content, rec_value);
  rec_value = "Value";
  ASSERT_EQ(0, chunkstore->Load(h_name.at(15), &rec_value));
  ASSERT_EQ(modified_content, rec_value);
  ASSERT_EQ(size_t(4), failed_chunk_names.size());
  failed_chunk_names.remove(h_name.at(0));
  failed_chunk_names.remove(h_name.at(5));
  failed_chunk_names.remove(h_name.at(10));
  failed_chunk_names.remove(h_name.at(15));
  ASSERT_EQ(size_t(0), failed_chunk_names.size());
  // Check failed files do get removed
  ASSERT_EQ(0, chunkstore->HashCheckAllChunks(true, &failed_chunk_names));
  ASSERT_FALSE(chunkstore->Has(h_name.at(0)));
  ASSERT_FALSE(chunkstore->Has(h_name.at(5)));
  ASSERT_FALSE(chunkstore->Has(h_name.at(10)));
  ASSERT_FALSE(chunkstore->Has(h_name.at(15)));
  rec_value = "Value";
  ASSERT_EQ(kInvalidChunkType, chunkstore->Load(h_name.at(0), &rec_value));
  ASSERT_NE(modified_content, rec_value);
  rec_value = "Value";
  ASSERT_EQ(kInvalidChunkType, chunkstore->Load(h_name.at(5), &rec_value));
  ASSERT_NE(modified_content, rec_value);
  rec_value = "Value";
  ASSERT_EQ(kInvalidChunkType, chunkstore->Load(h_name.at(10), &rec_value));
  ASSERT_NE(modified_content, rec_value);
  rec_value = "Value";
  ASSERT_EQ(kInvalidChunkType, chunkstore->Load(h_name.at(15), &rec_value));
  ASSERT_NE(modified_content, rec_value);
  ASSERT_EQ(size_t(4), failed_chunk_names.size());
  failed_chunk_names.remove(h_name.at(0));
  failed_chunk_names.remove(h_name.at(5));
  failed_chunk_names.remove(h_name.at(10));
  failed_chunk_names.remove(h_name.at(15));
  ASSERT_EQ(size_t(0), failed_chunk_names.size());
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreThreadedStoreAndLoad) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 50;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true, 3,
                                          32000, &h_size, &h_value, &h_name));
  test_chunkstore::ThreadedTest tester(chunkstore);
  // Store each chunk after a 50 ms delay
  boost::posix_time::milliseconds store_delay(50);
  std::vector<boost::shared_ptr<int> > store_result;
  boost::thread_group store_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    store_result.push_back(res);
    store_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::Store, tester, store_delay,
        h_name.at(i), h_value.at(i), store_result.at(i)));
  }
  // Start checking for each chunk via Has with no delay
  bool result(false);
  std::vector<boost::shared_ptr<bool> > has_chunk;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<bool> res(new bool(false));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    has_chunk.push_back(res);
  }
  const boost::uint64_t kTimeout(5000);
  boost::uint64_t count(0);
  boost::posix_time::milliseconds has_delay(0);
  while (count < kTimeout && !result) {
    boost::thread_group has_thread_group;
    for (int i = 0; i < kNumberOfChunks; ++i) {
      has_thread_group.create_thread(boost::bind(
          &test_chunkstore::ThreadedTest::Has, tester, has_delay,
          h_name.at(i), has_chunk.at(i)));
    }
    has_thread_group.join_all();
    result = true;
    for (int i = 0; i < kNumberOfChunks; ++i)
      result = result && *has_chunk.at(i);
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  ASSERT_TRUE(result);
  // Check all stores returned 0
  for (int i = 0; i < kNumberOfChunks; ++i)
    result = result && (*store_result.at(i) == 0);
  ASSERT_TRUE(result);
  // Load back all chunks
  boost::posix_time::milliseconds load_delay(0);
  std::vector<boost::shared_ptr<std::string> > load_value;
  std::vector<boost::shared_ptr<int> > load_result;
  boost::thread_group load_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<std::string> val(new std::string("Value"));
    load_value.push_back(val);
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    load_result.push_back(res);
    load_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::Load, tester, load_delay,
        h_name.at(i), load_value.at(i), load_result.at(i)));
  }
  load_thread_group.join_all();
  // Check all loads returned 0 and all values loaded correctly
  for (int i = 0; i < kNumberOfChunks; ++i) {
    ASSERT_EQ(h_value.at(i), *load_value.at(i));
    result = result && (*load_result.at(i) == 0);
  }
  ASSERT_TRUE(result);
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreThreadedUpdate) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 50;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true,
                                          1000, 32000, &h_size, &h_value,
                                          &h_name));
  test_chunkstore::ThreadedTest tester(chunkstore);
  // Prepare update vectors
  boost::posix_time::milliseconds update_delay(0);
  std::vector<boost::shared_ptr<int> > update_result;
  boost::thread_group update_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    update_result.push_back(res);
  }
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
  // Start updating chunks in reverse order once first chunk has been stored to
  // ensure some update failures.
  while (!chunkstore->Has(h_name.at(0)))
    boost::this_thread::yield();
  for (int i = kNumberOfChunks - 1; i >= 0; --i) {
    update_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::UpdateChunk, tester, update_delay,
        h_name.at(i), "Updated", update_result.at(i)));
  }
  update_thread_group.join_all();
  store_thread_group.join_all();
  // Check all stores returned 0
  bool result(true);
  for (int i = 0; i < kNumberOfChunks; ++i)
    result = result && (*store_result.at(i) == 0);
  ASSERT_TRUE(result);
  // Count number of successful updates
  int successful_updates(0);
  for (int i = 0; i < kNumberOfChunks; ++i) {
    if (*update_result.at(i) == 0)
      ++successful_updates;
  }
  // Load back all chunks
  boost::posix_time::milliseconds load_delay(0);
  std::vector<boost::shared_ptr<std::string> > load_value;
  std::vector<boost::shared_ptr<int> > load_result;
  boost::thread_group load_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<std::string> val(new std::string("Value"));
    load_value.push_back(val);
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    load_result.push_back(res);
    load_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::Load, tester, load_delay,
        h_name.at(i), load_value.at(i), load_result.at(i)));
  }
  load_thread_group.join_all();
  // Check all loads returned 0 and all values loaded correctly
  for (int i = 0; i < kNumberOfChunks; ++i) {
    ASSERT_TRUE((h_value.at(i) == *load_value.at(i)) ||
                ("Updated" == *load_value.at(i)));
    result = result && (*load_result.at(i) == 0);
  }
  ASSERT_TRUE(result);
  // Check results match number of successful updates
  int stored(0), updated(0);
  for (int i = 0; i < kNumberOfChunks; ++i) {
    if (h_value.at(i) == (*load_value.at(i)))
      ++stored;
    if ("Updated" == (*load_value.at(i)))
      ++updated;
  }
  printf("%i stored, %i updated\n", stored, updated);
  ASSERT_EQ(kNumberOfChunks, stored + updated);
  ASSERT_EQ(successful_updates, updated);
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreThreadedDelete) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 50;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true,
                                          1000, 32000, &h_size, &h_value,
                                          &h_name));
  test_chunkstore::ThreadedTest tester(chunkstore);
  // Prepare delete vectors
  boost::posix_time::milliseconds delete_delay(0);
  std::vector<boost::shared_ptr<int> > delete_result;
  boost::thread_group delete_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    delete_result.push_back(res);
  }
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
  // Start deleting chunks in reverse order once first chunk has been stored to
  // ensure some update failures.
  while (!chunkstore->Has(h_name.at(0)))
    boost::this_thread::yield();
  for (int i = kNumberOfChunks - 1; i >= 0; --i) {
    delete_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::DeleteChunk, tester, delete_delay,
        h_name.at(i), delete_result.at(i)));
  }
  delete_thread_group.join_all();
  store_thread_group.join_all();
  // Check all stores returned 0
  bool result(true);
  for (int i = 0; i < kNumberOfChunks; ++i)
    result = result && (*store_result.at(i) == 0);
  ASSERT_TRUE(result);
  // Check all deletes returned true with possibly one or two having failed if
  // it threw a filesystem exception
  int successful_deletes(0);
  for (int i = 0; i < kNumberOfChunks; ++i) {
    if (*delete_result.at(i) == 0)
      ++successful_deletes;
  }
  ASSERT_GE(successful_deletes, kNumberOfChunks - 2);
  // Load back any remaining chunks and check they are OK
  boost::posix_time::milliseconds load_delay(0);
  std::vector<boost::shared_ptr<std::string> > load_value;
  std::vector<boost::shared_ptr<int> > load_result;
  boost::thread_group load_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<std::string> val(new std::string("Value"));
    load_value.push_back(val);
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    load_result.push_back(res);
    load_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::Load, tester, load_delay,
        h_name.at(i), load_value.at(i), load_result.at(i)));
  }
  load_thread_group.join_all();
  for (int i = 0; i < kNumberOfChunks; ++i) {
    if (*load_result.at(i) == 0)
      ASSERT_EQ(h_value.at(i), *load_value.at(i));
  }
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreThreadedRandLoad) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 50;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true, 10000,
                                          32000, &h_size, &h_value, &h_name));
  test_chunkstore::ThreadedTest tester(chunkstore);
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
        &test_chunkstore::ThreadedTest::LoadRandomChunk, tester,
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

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreThreadedCheckSingle) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 50;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true,
                                          1000, 32000, &h_size, &h_value,
                                          &h_name));
  test_chunkstore::ThreadedTest tester(chunkstore);
  // Prepare hash check vectors
  boost::posix_time::milliseconds check_delay(0);
  std::vector<boost::shared_ptr<int> > check_result;
  boost::thread_group check_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<int> res(new int(5318008));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    check_result.push_back(res);
  }
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
  // Start checking chunks in reverse order once first chunk has been stored to
  // ensure some check failures.
  while (!chunkstore->Has(h_name.at(0)))
    boost::this_thread::yield();
  for (int i = kNumberOfChunks - 1; i >= 0; --i) {
    check_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::HashCheckChunk, tester, check_delay,
        h_name.at(i), check_result.at(i)));
  }
  store_thread_group.join_all();
  check_thread_group.join_all();
  // Check all stores returned 0
  bool result(true);
  for (int i = 0; i < kNumberOfChunks; ++i)
    result = result && (*store_result.at(i) == 0);
  ASSERT_TRUE(result);
  // Do hash check again now that all chunks are available
  for (int i = 0; i < kNumberOfChunks; ++i) {
    check_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::HashCheckChunk, tester, check_delay,
        h_name.at(i), check_result.at(i)));
  }
  check_thread_group.join_all();
  // Check all checks returned true
  int result_int(0);
  for (int i = 0; i < kNumberOfChunks; ++i)
    result_int += *check_result.at(i);
  ASSERT_EQ(0, result_int);
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreThreadedCheckAll) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 50;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true,
                                          1000, 32000, &h_size, &h_value,
                                          &h_name));
  test_chunkstore::ThreadedTest tester(chunkstore);
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
      &test_chunkstore::ThreadedTest::HashCheckAllChunks, tester,
      check_all_delay, false, failed_chunks, check_all_result);
  check_all_thread.join();
  store_thread_group.join_all();
  // Check all stores returned 0
  bool result(true);
  for (int i = 0; i < kNumberOfChunks; ++i)
    result = result && (*store_result.at(i) == 0);
  ASSERT_TRUE(result);
  ASSERT_EQ(size_t(0), (*failed_chunks).size());
  // Amend a chunk to fail and retest
  ASSERT_EQ(0, chunkstore->UpdateChunk(h_name.at(0), h_value.at(1)));
  boost::thread check_all_thread1(
      &test_chunkstore::ThreadedTest::HashCheckAllChunks, tester,
      check_all_delay, true, failed_chunks, check_all_result);
  check_all_thread1.join();
  ASSERT_EQ(size_t(1), (*failed_chunks).size());
  ASSERT_EQ(h_name.at(0), failed_chunks->front());
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreThreadedChangeType) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  const int kNumberOfChunks = 80;
  ASSERT_TRUE(test_chunkstore::MakeChunks(kNumberOfChunks, cry_obj, true,
                                          3, 16000, &h_size, &h_value,
                                          &h_name));
  test_chunkstore::ThreadedTest tester(chunkstore);
  // Prepare change_type vectors
  boost::posix_time::milliseconds change_type_delay(0);
  std::vector<boost::shared_ptr<int> > change_type_result;
  std::vector<maidsafe::ChunkType> chunk_type;
  int count(0);
  while (count < kNumberOfChunks) {
    maidsafe::path_map_iterator path_map_itr = chunkstore->path_map_.begin();
    chunk_type.push_back((*path_map_itr).first);
    ++path_map_itr;
    if (path_map_itr == chunkstore->path_map_.end())
      path_map_itr = chunkstore->path_map_.begin();
    ++count;
  }
  boost::thread_group change_type_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<int> res(new int(5318008));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    change_type_result.push_back(res);
  }
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
  // Start changing chunks' types in reverse order once first chunk has been
  // stored to ensure some failures.
  while (!chunkstore->Has(h_name.at(0)))
    boost::this_thread::yield();
  for (int i = kNumberOfChunks - 1; i >= 0; --i) {
    change_type_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::ChangeChunkType, tester,
        change_type_delay, h_name.at(i), chunk_type.at(i),
        change_type_result.at(i)));
  }
  change_type_thread_group.join_all();
  store_thread_group.join_all();
  // Check all stores returned 0
  bool result(true);
  for (int i = 0; i < kNumberOfChunks; ++i)
    result = result && (*store_result.at(i) == 0);
  ASSERT_TRUE(result);
  // Run change types again
  for (int i = kNumberOfChunks - 1; i >= 0; --i) {
    change_type_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::ChangeChunkType, tester,
        change_type_delay, h_name.at(i), chunk_type.at(i),
        change_type_result.at(i)));
  }
  change_type_thread_group.join_all();
  // Count number of successful updates
  int successful_changes(0);
  for (int i = 0; i < kNumberOfChunks; ++i) {
    if (*change_type_result.at(i) == 0)
      ++successful_changes;
  }
  ASSERT_EQ(kNumberOfChunks, successful_changes);
  // Load back all chunks
  boost::posix_time::milliseconds load_delay(0);
  std::vector<boost::shared_ptr<std::string> > load_value;
  std::vector<boost::shared_ptr<int> > load_result;
  boost::thread_group load_thread_group;
  for (int i = 0; i < kNumberOfChunks; ++i) {
    boost::shared_ptr<std::string> val(new std::string("Value"));
    load_value.push_back(val);
    boost::shared_ptr<int> res(new int(1));  // NOLINT (Fraser) - Incorrect interpretation by lint.
    load_result.push_back(res);
    load_thread_group.create_thread(boost::bind(
        &test_chunkstore::ThreadedTest::Load, tester, load_delay,
        h_name.at(i), load_value.at(i), load_result.at(i)));
  }
  load_thread_group.join_all();
  // Check all loads returned 0 and all values loaded correctly
  for (int i = 0; i < kNumberOfChunks; ++i) {
    ASSERT_TRUE(h_value.at(i) == *load_value.at(i));
    result = result && (*load_result.at(i) == 0);
  }
  ASSERT_TRUE(result);
}

TEST_F(ChunkstoreTest, BEH_MAID_ChunkstoreCacheChunk) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1000, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  ASSERT_EQ(0, chunkstore->space_used_by_cache());

  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content(base::RandomString(1001));
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  ASSERT_EQ(kNoSpaceForCaching, chunkstore->CacheChunk(chunkname, content));
  ASSERT_FALSE(chunkstore->Has(chunkname));
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath(chunkname,
            (maidsafe::kHashable | maidsafe::kCache), false));
  ASSERT_EQ(0, chunkstore->space_used_by_cache());
  ASSERT_EQ(1000, chunkstore->FreeSpace());

  content = base::RandomString(999);
  chunkname = co.Hash(content, "", crypto::STRING_STRING, false);
  ASSERT_EQ(kSuccess, chunkstore->CacheChunk(chunkname, content));
  ASSERT_TRUE(chunkstore->Has(chunkname));
  ASSERT_TRUE(fs::exists(chunkstore->GetChunkPath(chunkname,
              (maidsafe::kHashable | maidsafe::kCache), false)));
  ASSERT_EQ(999, chunkstore->space_used_by_cache());
  ASSERT_EQ(1, chunkstore->FreeSpace());

  content = base::RandomString(999);
  chunkname = co.Hash(content, "", crypto::STRING_STRING, false);
  ASSERT_EQ(kNoSpaceForCaching, chunkstore->CacheChunk(chunkname, content));
  ASSERT_FALSE(chunkstore->Has(chunkname));
  ASSERT_EQ(fs::path(""), chunkstore->GetChunkPath(chunkname,
            (maidsafe::kHashable | maidsafe::kCache), false));
  ASSERT_EQ(999, chunkstore->space_used_by_cache());
  ASSERT_EQ(1, chunkstore->FreeSpace());
}

TEST_F(ChunkstoreTest, FUNC_MAID_ChunkstoreFreeCacheSpace) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 20000, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  ASSERT_EQ(0, chunkstore->space_used_by_cache());
  ASSERT_EQ(kNoCacheSpaceToClear, chunkstore->FreeCacheSpace(1));

  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  int chunks_to_test(10);
  std::vector<std::string> chunknames;
  for (int n = 0; n < chunks_to_test; ++n) {
    std::string content(base::RandomString(1000));
    std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
    ASSERT_EQ(kSuccess, chunkstore->CacheChunk(chunkname, content));
    chunknames.push_back(chunkname);
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
  printf("Inserted %i chunks\n", chunks_to_test);
  ASSERT_EQ(1000 * chunks_to_test, chunkstore->space_used_by_cache());

  for (int a = 0; a < chunks_to_test; ++a) {
    ASSERT_EQ(1000 * (chunks_to_test - a), chunkstore->space_used_by_cache());
    ASSERT_TRUE(chunkstore->Has(chunknames[a]));
    ASSERT_EQ(chunks_to_test - a, chunkstore->chunkstore_set_.size());
    ASSERT_EQ(kSuccess, chunkstore->FreeCacheSpace(1000));
    ASSERT_FALSE(chunkstore->Has(chunknames[a]));
    ASSERT_EQ(1000 * (chunks_to_test - a - 1),
              chunkstore->space_used_by_cache());
    ASSERT_EQ(chunks_to_test - a - 1, chunkstore->chunkstore_set_.size());
  }
  ASSERT_EQ(0, chunkstore->space_used_by_cache());
  ASSERT_EQ(kNoCacheSpaceToClear, chunkstore->FreeCacheSpace(1));
  printf("Passed #1\n\n");

  chunknames.clear();
  for (int y = 0; y < chunks_to_test; ++y) {
    std::string content(base::RandomString(1000));
    std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
    ASSERT_EQ(kSuccess, chunkstore->CacheChunk(chunkname, content));
    chunknames.push_back(chunkname);
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
  printf("Inserted %i chunks\n", chunks_to_test);
  ASSERT_EQ(1000 * chunks_to_test, chunkstore->space_used_by_cache());

  ASSERT_TRUE(chunkstore->Has(chunknames[0]));
  ASSERT_TRUE(chunkstore->Has(chunknames[1]));
  ASSERT_EQ(chunks_to_test, chunkstore->chunkstore_set_.size());
  ASSERT_EQ(kSuccess, chunkstore->FreeCacheSpace(1500));
  ASSERT_FALSE(chunkstore->Has(chunknames[0]));
  ASSERT_FALSE(chunkstore->Has(chunknames[1]));
  ASSERT_EQ(chunks_to_test - 2, chunkstore->chunkstore_set_.size());
  ASSERT_EQ(1000 * (chunks_to_test - 2), chunkstore->space_used_by_cache());
  printf("Passed #2\n");
}

TEST_F(ChunkstoreTest, FUNC_MAID_ChunkstoreStorePackets) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // Check valid stores succeed.
  const int kNumberOfPackets = 10;
  ASSERT_TRUE(test_chunkstore::MakeKeys(kNumberOfPackets, &private_key,
      &public_key));
  ASSERT_TRUE(test_chunkstore::MakePackets(kNumberOfPackets, cry_obj, 3, 1024,
      private_key, &p_size, &p_value, &p_name));
  for (int i = 0; i < kNumberOfPackets; ++i) {
    ASSERT_EQ(kSuccess, chunkstore->StorePacket(p_name.at(i), p_value.at(i)));
  }
  ASSERT_EQ(size_t(kNumberOfPackets), chunkstore->pss_.size());
  // check further valid stores return kPacketAlreadyStored
  for (int i = 0; i < kNumberOfPackets; ++i) {
    ASSERT_EQ(kPacketStoreValueExists,
              chunkstore->StorePacket(p_name.at(i), p_value.at(i)));
  }
  ASSERT_EQ(size_t(kNumberOfPackets), chunkstore->pss_.size());
  // Check StorePacket call with invalid packet name fails.
  std::string data = base::RandomString(64);
  maidsafe::GenericPacket gp;
  gp.set_data(data);
  gp.set_signature(cry_obj->AsymSign(data, "", private_key.at(0),
                   crypto::STRING_STRING));
  ASSERT_EQ(kIncorrectKeySize, chunkstore->StorePacket("Invalid",
      p_value.at(0)));
  ASSERT_EQ(size_t(kNumberOfPackets), chunkstore->pss_.size());
}

TEST_F(ChunkstoreTest, FUNC_MAID_ChunkstoreAppendToPackets) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // Check append to non-existing name fails.
  const int kNumberOfPackets = 10;
  ASSERT_TRUE(test_chunkstore::MakeKeys(kNumberOfPackets, &private_key,
      &public_key));
  ASSERT_TRUE(test_chunkstore::MakePackets(kNumberOfPackets, cry_obj, 3, 1024,
      private_key, &p_size, &p_value, &p_name));
  ASSERT_EQ(kPacketAppendNotFound, chunkstore->AppendToPacket(p_name.at(0),
      p_value.at(0), public_key.at(0)));
  // Store packets.
  for (int i = 0; i < kNumberOfPackets; ++i) {
    ASSERT_EQ(kSuccess, chunkstore->StorePacket(p_name.at(i), p_value.at(i)));
  }
  size_t current_size(kNumberOfPackets);
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Check a round of valid appends succeed.
  std::vector<std::string> original_p_name(p_name);
  std::vector<maidsafe::GenericPacket> original_p_value(p_value);
  ASSERT_TRUE(test_chunkstore::MakePackets(kNumberOfPackets, cry_obj, 3, 1024,
      private_key, &p_size, &p_value, &p_name));
  for (int i = 0; i < kNumberOfPackets; ++i) {
    ASSERT_EQ(kSuccess, chunkstore->AppendToPacket(original_p_name.at(i),
        p_value.at(i), public_key.at(i)));
  }
  current_size *= 2;
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Check a second round of valid appends fail.
  for (int i = 0; i < kNumberOfPackets; ++i) {
    ASSERT_EQ(kPacketAppendValueExists, chunkstore->AppendToPacket(
        original_p_name.at(i), p_value.at(i), public_key.at(i)));
  }
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Check further append with different public key fails.
  ASSERT_EQ(kPacketAppendNotOwned, chunkstore->AppendToPacket(
      original_p_name.at(0), p_value.at(1), public_key.at(1)));
  // Check multiple appends to one packet name succeed.
  for (int i = 1; i < kNumberOfPackets; ++i) {
    // Amend generic packet to be signed by first private key.
    p_value.at(i).set_signature(cry_obj->AsymSign(p_value.at(i).data(), "",
        private_key.at(0), crypto::STRING_STRING));
    ASSERT_EQ(kSuccess, chunkstore->AppendToPacket(original_p_name.at(0),
        p_value.at(i), public_key.at(0)));
  }
  current_size += (kNumberOfPackets - 1);
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Check AppendToPacket call with invalid packet name fails.
  ASSERT_EQ(kIncorrectKeySize, chunkstore->AppendToPacket("Invalid",
      p_value.at(0), public_key.at(0)));
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Reload first packet and check its values are correct (content & LIFO order)
  std::vector<maidsafe::GenericPacket> first_generic_packets;
  ASSERT_EQ(kSuccess, chunkstore->LoadPacket(original_p_name.at(0),
      &first_generic_packets));
  ASSERT_EQ(size_t(kNumberOfPackets + 1), first_generic_packets.size());
  ASSERT_EQ(original_p_value.at(0).data(),
            first_generic_packets.at(first_generic_packets.size() - 1).data());
  for (int i = 0; i < kNumberOfPackets; ++i) {
    ASSERT_EQ(p_value.at(i).data(),
              first_generic_packets.at(kNumberOfPackets - 1 - i).data());
  }
  // Reload other packets and check values are correct (content & LIFO order)
  for (int i = 1; i < kNumberOfPackets; ++i) {
    std::vector<maidsafe::GenericPacket> generic_packets;
    ASSERT_EQ(kSuccess, chunkstore->LoadPacket(original_p_name.at(i),
        &generic_packets));
    ASSERT_EQ(size_t(2), generic_packets.size());
    ASSERT_EQ(p_value.at(i).data(), generic_packets.at(0).data());
    ASSERT_EQ(original_p_value.at(i).data(), generic_packets.at(1).data());
  }
}

TEST_F(ChunkstoreTest, FUNC_MAID_ChunkstoreOverwritePackets) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // Set up 2 vectors of 10 vectors of 1 and 7 GenericPackets
  const int kNumberOfPackets = 10;
  const int kNumberOfValues = 7;
  ASSERT_TRUE(test_chunkstore::MakeKeys(kNumberOfPackets, &private_key,
      &public_key));
  ASSERT_TRUE(test_chunkstore::MakePackets(kNumberOfPackets, cry_obj, 3, 1024,
      private_key, &p_size, &p_value, &p_name));
  std::vector<std::string> original_p_name(p_name);
  // Copy a GenericPacket for each key into a vector of vectors
  std::vector< std::vector<maidsafe::GenericPacket> > first_group;
  for (int i = 0; i < kNumberOfPackets; ++i) {
    std::vector<maidsafe::GenericPacket> gps;
    gps.push_back(p_value.at(i));
    first_group.push_back(gps);
  }
  // Copy GenericPackets for each key into a second vector of vectors
  std::vector< std::vector<maidsafe::GenericPacket> > second_group;
  for (int i = 0; i < kNumberOfPackets; ++i) {
    std::vector<maidsafe::GenericPacket> gps;
    for (int j = 0; j < kNumberOfValues; ++j) {
      ASSERT_TRUE(test_chunkstore::MakePackets(kNumberOfPackets, cry_obj, 3,
          1024, private_key, &p_size, &p_value, &p_name));
      gps.push_back(p_value.at(i));
    }
    second_group.push_back(gps);
  }
  // Check overwrite to non-existing name fails.
  ASSERT_EQ(kPacketOverwriteNotFound, chunkstore->OverwritePacket(p_name.at(0),
      first_group.at(0), public_key.at(0)));
  size_t current_size(0);
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Set up 10 new packets for storing
  ASSERT_TRUE(test_chunkstore::MakePackets(kNumberOfPackets, cry_obj, 3, 1024,
      private_key, &p_size, &p_value, &p_name));
  // Store packets.
  for (int i = 0; i < kNumberOfPackets; ++i) {
    ASSERT_EQ(kSuccess, chunkstore->StorePacket(original_p_name.at(i),
              p_value.at(i)));
  }
  current_size = kNumberOfPackets;
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Check a round of valid overwrites succeeds.
  for (int i = 0; i < kNumberOfPackets; ++i) {
    ASSERT_EQ(kSuccess, chunkstore->OverwritePacket(original_p_name.at(i),
        first_group.at(i), public_key.at(i)));
  }
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Load packets and check values
  for (int i = 0; i < kNumberOfPackets; ++i) {
    std::vector<maidsafe::GenericPacket> generic_packets;
    ASSERT_EQ(kSuccess, chunkstore->LoadPacket(original_p_name.at(i),
        &generic_packets));
    ASSERT_EQ(size_t(1), generic_packets.size());
    ASSERT_EQ(first_group.at(i).at(0).data(), generic_packets.at(0).data());
  }
  // Check a second round of valid overwrites succeeds.
  for (int i = 0; i < kNumberOfPackets; ++i) {
    ASSERT_EQ(kSuccess, chunkstore->OverwritePacket(original_p_name.at(i),
        second_group.at(i), public_key.at(i)));
  }
  current_size *= kNumberOfValues;
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Load packets and check values
  for (int i = 0; i < kNumberOfPackets; ++i) {
    std::vector<maidsafe::GenericPacket> generic_packets;
    ASSERT_EQ(kSuccess, chunkstore->LoadPacket(original_p_name.at(i),
        &generic_packets));
    ASSERT_EQ(size_t(kNumberOfValues), generic_packets.size());
    for (int j = 0; j < kNumberOfValues; ++j)
      ASSERT_EQ(second_group.at(i).at(j).data(), generic_packets.at(j).data());
  }
  // Check further overwrite with different public key fails.
  ASSERT_EQ(kPacketOverwriteNotOwned, chunkstore->OverwritePacket(
      original_p_name.at(0), second_group.at(0), public_key.at(1)));
  std::vector<maidsafe::GenericPacket> gps;
  ASSERT_EQ(kSuccess, chunkstore->LoadPacket(original_p_name.at(0),
      &gps));
  ASSERT_EQ(size_t(kNumberOfValues), gps.size());
  for (int j = 0; j < kNumberOfValues; ++j) {
    ASSERT_EQ(second_group.at(0).at(j).data(), gps.at(j).data());
  }
  // Check a third round of valid overwrites succeeds.
  for (int i = 0; i < kNumberOfPackets; ++i) {
    ASSERT_EQ(kSuccess, chunkstore->OverwritePacket(original_p_name.at(i),
        first_group.at(i), public_key.at(i)));
  }
  current_size = kNumberOfPackets;
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Load packets and check values
  for (int i = 0; i < kNumberOfPackets; ++i) {
    std::vector<maidsafe::GenericPacket> generic_packets;
    ASSERT_EQ(kSuccess, chunkstore->LoadPacket(original_p_name.at(i),
        &generic_packets));
    ASSERT_EQ(size_t(1), generic_packets.size());
    ASSERT_EQ(first_group.at(i).at(0).data(), generic_packets.at(0).data());
  }
  // Check OverwritePacket call with two identical values per name succeeds.
  for (int i = 0; i < kNumberOfPackets; ++i) {
    // Modify each vector to duplicate a value per packet name
    second_group.at(i).push_back(second_group.at(i).at(0));
    ASSERT_EQ(kSuccess, chunkstore->OverwritePacket(original_p_name.at(i),
        second_group.at(i), public_key.at(i)));
  }
  current_size *= kNumberOfValues;
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Load packets and check values
  for (int i = 0; i < kNumberOfPackets; ++i) {
    std::vector<maidsafe::GenericPacket> generic_packets;
    ASSERT_EQ(kSuccess, chunkstore->LoadPacket(original_p_name.at(i),
        &generic_packets));
    ASSERT_EQ(size_t(kNumberOfValues), generic_packets.size());
    for (int j = 0; j < kNumberOfValues; ++j)
      ASSERT_EQ(second_group.at(i).at(j).data(), generic_packets.at(j).data());
  }
  // Check OverwritePacket call with invalid packet name fails.
  std::string data = base::RandomString(64);
  ASSERT_EQ(kIncorrectKeySize, chunkstore->OverwritePacket("Invalid",
      second_group.at(0), public_key.at(0)));
  ASSERT_EQ(current_size, chunkstore->pss_.size());
}

TEST_F(ChunkstoreTest, FUNC_MAID_ChunkstoreDeletePackets) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // Set up a vector of 10 vectors of 7 GenericPackets
  const int kNumberOfPackets = 10;
  const int kNumberOfValues = 7;
  ASSERT_GE(kNumberOfValues, 3);  // To enable deletion of 2 individual values
  ASSERT_TRUE(test_chunkstore::MakeKeys(kNumberOfPackets, &private_key,
      &public_key));
  ASSERT_TRUE(test_chunkstore::MakePackets(kNumberOfPackets, cry_obj, 3, 1024,
      private_key, &p_size, &p_value, &p_name));
  std::vector<std::string> original_p_name(p_name);
  // Copy a GenericPacket for each key into the vector of vectors
  std::vector< std::vector<maidsafe::GenericPacket> > group;
  for (int i = 0; i < kNumberOfPackets; ++i) {
    std::vector<maidsafe::GenericPacket> gps;
    for (int j = 0; j < kNumberOfValues; ++j) {
      ASSERT_TRUE(test_chunkstore::MakePackets(kNumberOfPackets, cry_obj, 3,
          1024, private_key, &p_size, &p_value, &p_name));
      gps.push_back(p_value.at(i));
    }
    group.push_back(gps);
  }
  // Create 2 vector of vectors of existing values to be deleted and remaining
  std::vector< std::vector<maidsafe::GenericPacket> > delete_group;
  std::vector< std::vector<maidsafe::GenericPacket> > remain_group;
  for (int i = 0; i < kNumberOfPackets; ++i) {
    std::vector<maidsafe::GenericPacket> delete_gps;
    std::vector<maidsafe::GenericPacket> remain_gps;
    for (int j = 0; j < kNumberOfValues; ++j) {
      if ((j == i % kNumberOfValues) ||
          (j == ((i % kNumberOfValues) + 2) % kNumberOfValues)) {
        delete_gps.push_back(group.at(i).at(j));
      } else {
        remain_gps.push_back(group.at(i).at(j));
      }
    }
    ASSERT_EQ(size_t(2), delete_gps.size());
    delete_group.push_back(delete_gps);
    remain_group.push_back(remain_gps);
  }
  // Reverse order of delete vector values
  for (int i = 0; i < kNumberOfPackets; ++i) {
    std::vector<maidsafe::GenericPacket> gps(delete_group.at(i));
    delete_group.at(i).clear();
    delete_group.at(i).push_back(gps.back());
    delete_group.at(i).push_back(gps.front());
  }
  // Check delete to non-existing name fails.
  std::vector<maidsafe::GenericPacket> gps;
  ASSERT_EQ(kPacketDeleteNotFound,
      chunkstore->DeletePacket(original_p_name.at(0), gps, public_key.at(0)));
  // Store 10 single-value packets and overwrite them with the 7-value packets
  ASSERT_TRUE(test_chunkstore::MakePackets(kNumberOfPackets, cry_obj, 3, 1024,
      private_key, &p_size, &p_value, &p_name));
  for (int i = 0; i < kNumberOfPackets; ++i) {
    ASSERT_EQ(kSuccess, chunkstore->StorePacket(original_p_name.at(i),
              p_value.at(i)));
    ASSERT_EQ(kSuccess, chunkstore->OverwritePacket(original_p_name.at(i),
        group.at(i), public_key.at(i)));
  }
  size_t current_size(kNumberOfPackets * kNumberOfValues);
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Check delete two values per packet_name with different public key fails.
  ASSERT_EQ(kPacketDeleteNotOwned, chunkstore->DeletePacket(
      original_p_name.at(0), delete_group.at(0), public_key.at(1)));
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Check delete all values per packet_name with different public key fails.
  ASSERT_EQ(kPacketDeleteNotOwned, chunkstore->DeletePacket(
      original_p_name.at(0), gps, public_key.at(1)));
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Check delete two values per packet_name succeeds.
  for (int i = 0; i < kNumberOfPackets; ++i) {
    ASSERT_EQ(kSuccess, chunkstore->DeletePacket(original_p_name.at(i),
        delete_group.at(i), public_key.at(i)));
  }
  current_size = kNumberOfPackets * (kNumberOfValues - 2);
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Load packets and check values
  for (int i = 0; i < kNumberOfPackets; ++i) {
    std::vector<maidsafe::GenericPacket> generic_packets;
    ASSERT_EQ(kSuccess, chunkstore->LoadPacket(original_p_name.at(i),
        &generic_packets));
    ASSERT_EQ(size_t(kNumberOfValues - 2), generic_packets.size());
    for (int j = 0; j < kNumberOfValues - 2; ++j)
      ASSERT_EQ(remain_group.at(i).at(j).data(), generic_packets.at(j).data());
  }
  // Check delete all values per packet_name succeeds.
  for (int i = 0; i < kNumberOfPackets; ++i) {
    ASSERT_EQ(kSuccess, chunkstore->DeletePacket(original_p_name.at(i), gps,
        public_key.at(i)));
  }
  current_size = 0;
  ASSERT_EQ(current_size, chunkstore->pss_.size());
  // Check DeletePacket call with invalid packet name fails.
  ASSERT_EQ(kIncorrectKeySize, chunkstore->DeletePacket("Invalid", gps,
      public_key.at(0)));
  ASSERT_EQ(current_size, chunkstore->pss_.size());
}

TEST_F(ChunkstoreTest, FUNC_MAID_ChunkstoreHasPackets) {
  boost::shared_ptr<VaultChunkStore> chunkstore(new VaultChunkStore(
      storedir.string(), 1073741824, 0));
  ASSERT_TRUE(chunkstore->Init());
  test_chunkstore::WaitForInitialisation(chunkstore, 60000);
  ASSERT_TRUE(chunkstore->is_initialised());
  // Store packets
  const int kNumberOfPackets = 10;
  ASSERT_TRUE(test_chunkstore::MakeKeys(kNumberOfPackets, &private_key,
      &public_key));
  ASSERT_TRUE(test_chunkstore::MakePackets(kNumberOfPackets, cry_obj, 3, 1024,
      private_key, &p_size, &p_value, &p_name));
  for (int i = 0; i < kNumberOfPackets; ++i) {
    ASSERT_EQ(kSuccess, chunkstore->StorePacket(p_name.at(i), p_value.at(i)));
  }
  ASSERT_EQ(size_t(kNumberOfPackets), chunkstore->pss_.size());
  // Check HasPacket succeeds
  for (int i = 0; i < kNumberOfPackets; ++i)
    ASSERT_TRUE(chunkstore->HasPacket(p_name.at(i)));
  // Check HasPacket fails using non-existent chunk
  std::string othername = cry_obj->Hash("otherfile", "", crypto::STRING_STRING,
                                        false);
  ASSERT_FALSE(chunkstore->HasPacket(othername));
  // check we can handle keys of wrong length
  std::string wrong_length_key("too short");
  ASSERT_FALSE(chunkstore->HasPacket(wrong_length_key));
}

}  // namespace maidsafe_vault
