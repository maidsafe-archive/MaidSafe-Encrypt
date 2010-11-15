/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Allows creation of gtest environment where pdvaults are set up
*               and started
* Version:      1.0
* Created:      2009-06-22-15.51.35
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#ifndef MAIDSAFE_SHAREDTEST_CHUNKSTOREOPS_H_
#define MAIDSAFE_SHAREDTEST_CHUNKSTOREOPS_H_

#include <boost/cstdint.hpp>
#include <boost/filesystem.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <maidsafe/base/utils.h>

#include <string>
#include <vector>

#include "maidsafe/common/packet.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {
class ChunkStore;
}  // namespace maidsafe

namespace test_chunkstore {

void WaitForInitialisation(boost::shared_ptr<maidsafe::ChunkStore> chunkstore,
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
                bool hashable,
                const size_t &min_chunk_size,
                const size_t &max_chunk_size,
                std::vector<size_t> *chunksize,
                std::vector<std::string> *value,
                std::vector<std::string> *name) {
  chunksize->clear();
  value->clear();
  name->clear();
  size_t lower = min_chunk_size;
  size_t upper = max_chunk_size;
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
    size_t chunk_size(lower + static_cast<size_t>((rand() * factor)));  // NOLINT (Fraser)
    // just in case!
    while (chunk_size > upper)
      chunk_size = chunk_size / 2;
    chunksize->push_back(chunk_size);
    value->push_back(base::RandomAlphaNumericString(chunksize->at(i)));
    if (hashable) {
      name->push_back(maidsafe::SHA512String(value->at(i)));
    } else {
      name->push_back(maidsafe::SHA512String(base::IntToString(i)));
    }
  }
  return (chunksize->size() == num_chunks && value->size() == num_chunks &&
          name->size() == num_chunks);
}

// Makes (num_packets) packets of length between min_packet_size and
// max_packet_size bytes.  min_packet_size will be resized to 3 if too small and
// max_packet_size will be resized to 1024 if too large.
bool MakePackets(const boost::uint32_t &num_packets,
                 const size_t &min_packet_size,
                 const size_t &max_packet_size,
                 std::vector<std::string> private_key,
                 std::vector<size_t> *packetsize,
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
  size_t lower = min_packet_size;
  size_t upper = max_packet_size;
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
    size_t packet_size(lower + static_cast<size_t>((rand() * factor)));  // NOLINT (Fraser)
    // just in case!
    while (packet_size > upper)
      packet_size = packet_size / 2;
    packetsize->push_back(packet_size);
    std::string data = base::RandomAlphaNumericString(packetsize->at(i));
    maidsafe::GenericPacket gp;
    gp.set_data(data);
    gp.set_signature(maidsafe::RSASign(data, private_key.at(i)));
    value->push_back(gp);
    name->push_back(maidsafe::SHA512String(base::IntToString(i)));
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
    path_found->clear();
    return false;
  }
  std::string hex_filename = base::EncodeToHex(non_hex_filename);
  fs::directory_iterator end_itr;
  for (fs::directory_iterator itr(root_dir_path); itr != end_itr; ++itr) {
//    printf("Iter at %s\n", itr->path().filename().c_str());
    if (fs::is_directory((*itr).status())) {
      if (FindFile((*itr).path(), non_hex_filename, path_found))
        return true;
    } else if ((*itr).path().filename().string() == hex_filename) {
      *path_found = itr->path();
      return true;
    }
  }
  path_found->clear();
  return false;
}

// This checks that the file is in "./TESTSTORAGE/parent/branch" where the path
// is expected to be of form eg "./TESTSTORAGE/Hashable/Normal/0/c/5/0c56c76..."
bool CheckFilePath(const fs::path &file_path,
                   const std::string &parent,
                   const std::string &branch) {
  fs::path root_path(file_path);
  // need a remove_filename for each of the 4 subdirs
  for (int i = 0; i < 4; ++i)
    root_path.remove_filename();
  if (root_path.filename().string() != branch) {
#ifdef DEBUG
    printf("In CheckFilePath (branch), %s != %s\n",
           root_path.filename().string().c_str(), branch.c_str());
#endif
    return false;
  }
  root_path.remove_filename();
  if (root_path.filename().string() != parent) {
#ifdef DEBUG
    printf("In CheckFilePath (branch), %s != %s\n",
           root_path.filename().string().c_str(), parent.c_str());
#endif
    return false;
  }
  return true;
}

class ThreadedTest {
 public:
  explicit ThreadedTest(boost::shared_ptr<maidsafe::ChunkStore> chunkstore)
      : chunkstore_(chunkstore) {}
  virtual ~ThreadedTest() {}
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
  void HashCheckChunk(const boost::posix_time::milliseconds &delay,
                      const std::string &name,
                      boost::shared_ptr<int> result) {
    boost::this_thread::sleep(delay);
    *result = chunkstore_->HashCheckChunk(name);
  }
  void ChangeChunkType(const boost::posix_time::milliseconds &delay,
                       const std::string &name,
                       maidsafe::ChunkType type,
                       boost::shared_ptr<int> result) {
    boost::this_thread::sleep(delay);
    *result = chunkstore_->ChangeChunkType(name, type);
  }
 protected:
  boost::shared_ptr<maidsafe::ChunkStore> chunkstore_;
};

}  // namespace test_chunkstore


namespace maidsafe {

namespace test {

class ChunkstoreTest : public testing::Test {
 protected:
  ChunkstoreTest()
      : storedir(file_system::TempDir() / ("maidsafe_TestChunkstore"
                 + base::RandomAlphaNumericString(6))),
        file_path(storedir / "chunk.txt"),
        file_content("ABC"),
        hash_file_content(SHA512String(file_content)),
        other_hash(SHA512String("CBA")),
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
    try {
      fs::remove_all(storedir);
      fs::create_directory(storedir);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    fs::ofstream ofs;
    ofs.open(file_path);
    ofs << file_content;
    ofs.close();
  }
  void TearDown() {
    try {
      fs::remove_all(storedir);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
  fs::path storedir, file_path;
  std::string file_content, hash_file_content, other_hash;
  std::vector<size_t> h_size, nh_size, p_size;
  std::vector<std::string> h_value, nh_value, h_name, nh_name, p_name;
  std::vector<std::string> private_key, public_key;
  std::vector<maidsafe::GenericPacket> p_value;
};

}  // namespace test

namespace vault {

namespace test {

class VaultChunkstoreTest : public maidsafe::test::ChunkstoreTest {};

}  // namespace test

}  // namespace vault

}  // namespace maidsafe


#endif  // MAIDSAFE_SHAREDTEST_CHUNKSTOREOPS_H_