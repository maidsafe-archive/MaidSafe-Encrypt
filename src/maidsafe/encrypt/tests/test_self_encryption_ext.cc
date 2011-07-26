// /*******************************************************************************
//  *  Copyright 2011 maidsafe.net limited                                        *
//  *                                                                             *
//  *  The following source code is property of maidsafe.net limited and is not   *
//  *  meant for external use.  The use of this code is governed by the license   *
//  *  file LICENSE.TXT found in the root of this directory and also on           *
//  *  www.maidsafe.net.                                                          *
//  *                                                                             *
//  *  You are not free to copy, amend or otherwise use this source code without  *
//  *  the explicit written permission of the board of directors of maidsafe.net. *
//  ***************************************************************************//**
//  * @file  test_self_encryption_ext.cc
//  * @brief Extended tests for self-encryption.
//  * @date  2011-06-13
//  */
// 
// #include <cstdint>
// #include <functional>
// #include <iostream>  // NOLINT
// #include <memory>
// #include <sstream>
// 
// #include "boost/filesystem.hpp"
// #include "boost/filesystem/fstream.hpp"
// #include "boost/timer.hpp"
// #include "maidsafe/common/crypto.h"
// #include "maidsafe/common/memory_chunk_store.h"
// #include "maidsafe/common/test.h"
// #include "maidsafe/common/utils.h"
// #include "maidsafe/encrypt/data_map.h"
// #include "maidsafe/encrypt/self_encryption.h"
// #include "maidsafe/encrypt/self_encryption_stream.h"
// 
// namespace fs = boost::filesystem;
// 
// namespace maidsafe {
// 
// namespace encrypt {
// 
// namespace test {
// 
// namespace test_see {
// 
// const std::uint32_t kDefaultSelfEncryptionType(
//     kHashingSha512 | kCompressionNone | kObfuscationRepeated | kCryptoAes256);
// 
// fs::path CreateRandomFile(const fs::path &file_path,
//                           const std::uint64_t &file_size) {
//   fs::ofstream ofs(file_path, std::ios::binary | std::ios::out |
//                               std::ios::trunc);
//   if (file_size != 0) {
//     size_t string_size = (file_size > 100000) ? 100000 :
//                          static_cast<size_t>(file_size);
//     std::uint64_t remaining_size = file_size;
//     std::string rand_str = RandomString(2 * string_size);
//     std::string file_content;
//     std::uint64_t start_pos = 0;
//     while (remaining_size) {
//       srand(17);
//       start_pos = rand() % string_size;  // NOLINT (Fraser)
//       if (remaining_size < string_size) {
//         string_size = static_cast<size_t>(remaining_size);
//         file_content = rand_str.substr(0, string_size);
//       } else {
//         file_content = rand_str.substr(static_cast<size_t>(start_pos),
//                                        string_size);
//       }
//       ofs.write(file_content.c_str(), file_content.size());
//       remaining_size -= string_size;
//     }
//   }
//   ofs.close();
//   return file_path;
// }
// 
// std::uint64_t TotalChunkSize(const std::vector<std::uint32_t> &chunk_sizes) {
//   std::uint64_t total(0);
//   for (size_t i = 0; i < chunk_sizes.size(); ++i)
//     total += chunk_sizes[i];
//   return total;
// }
// 
// size_t CountUniqueChunks(std::shared_ptr<DataMap> data_map) {
//   std::set<std::string> chunks;
//   for (auto it = data_map->chunks.begin(); it != data_map->chunks.end(); ++it)
//     chunks.insert(it->hash);
//   return chunks.size();
// }
// 
// bool VerifyChunks(std::shared_ptr<DataMap> data_map,
//                   std::shared_ptr<ChunkStore> chunk_store) {
//   std::set<std::string> chunks;
//   std::uintmax_t ref_sum(0);
//   bool invalid(false);
//   for (auto it = data_map->chunks.begin(); it != data_map->chunks.end(); ++it)
//     if (chunks.count(it->hash) == 0) {
//       chunks.insert(it->hash);
//       ref_sum += chunk_store->Count(it->hash);
//       invalid = invalid || !chunk_store->Validate(it->hash);
//     }
//   return !invalid && ref_sum == data_map->chunks.size();
// }
// 
// }  // namespace test_see
// 
// class SelfEncryptionExtTest : public testing::Test {
//  public:
//   SelfEncryptionExtTest()
//       : test_dir_(),
//         hash_func_(std::bind(&crypto::Hash<crypto::SHA512>,
//                              std::placeholders::_1)) {
//     boost::system::error_code ec;
//     test_dir_ = boost::filesystem::temp_directory_path(ec) /
//         ("maidsafe_TestSE_" + RandomAlphaNumericString(6));
//   }
//   virtual ~SelfEncryptionExtTest() {}
//  protected:
//   void SetUp() {
//     if (fs::exists(test_dir_))
//       fs::remove_all(test_dir_);
//     fs::create_directory(test_dir_);
//   }
//   void TearDown() {
//     try {
//       if (fs::exists(test_dir_))
//         fs::remove_all(test_dir_);
//     }
//     catch(const std::exception& e) {
//       printf("%s\n", e.what());
//     }
//   }
//   testing::AssertionResult AssertStringsEqual(const char* expr1,
//                                               const char* expr2,
//                                               std::string s1,
//                                               std::string s2) {
//     if (s1 == s2)
//       return testing::AssertionSuccess();
// 
//     const size_t kLineLength(76);
// 
//     s1 = EncodeToBase64(s1);
//     if (s1.size() > kLineLength)
//       s1 = s1.substr(0, kLineLength / 2 - 1) + ".." +
//            s1.substr(s1.size() - kLineLength / 2 - 1);
// 
//     s2 = EncodeToBase64(s2);
//     if (s2.size() > kLineLength)
//       s2 = s2.substr(0, kLineLength / 2 - 1) + ".." +
//            s2.substr(s2.size() - kLineLength / 2 - 1);
// 
//     return testing::AssertionFailure()
//         << "Strings " << expr1 << " and " << expr2 << " are not equal: \n  "
//         << s1 << "\n  " << s2;
//   }
// 
//   fs::path test_dir_;
//   MemoryChunkStore::HashFunc hash_func_;
// };
// 
// TEST_F(SelfEncryptionExtTest, FUNC_SelfEnDecryptLargeFile) {
//   fs::path path_in(test_dir_ / "SelfEncryptFilesTestIn.dat");
//   fs::path path_out(test_dir_ / "SelfEncryptFilesTestOut.dat");
//   {
//     std::shared_ptr<DataMap> data_map(new DataMap);
//     std::shared_ptr<ChunkStore> chunk_store(
//         new MemoryChunkStore(true, hash_func_));
//     // Only need to check for just greater than 4GB.
//     std::uint64_t data_size((std::uint64_t(1) << 32) + 1);
//     test_see::CreateRandomFile(path_in, data_size);
//     EXPECT_EQ(kSuccess, SelfEncrypt(path_in, SelfEncryptionParams(), data_map,
//                                     chunk_store));
//     EXPECT_TRUE(ChunksExist(data_map, chunk_store, NULL));
//     EXPECT_TRUE(test_see::VerifyChunks(data_map, chunk_store));
//     EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, true, path_out))
//         << "Data size: " << data_size;
//     EXPECT_TRUE(fs::exists(path_out));
//     ASSERT_PRED_FORMAT2(AssertStringsEqual,
//                         crypto::HashFile<crypto::SHA512>(path_in),
//                         crypto::HashFile<crypto::SHA512>(path_out));
//   }
//   {
//     std::shared_ptr<DataMap> data_map(new DataMap);
//     std::shared_ptr<ChunkStore> chunk_store(
//         new MemoryChunkStore(true, hash_func_));
//     EXPECT_EQ(kFileAlreadyExists,
//               SelfDecrypt(data_map, chunk_store, false, path_out));
//     EXPECT_EQ(kSuccess, SelfDecrypt(data_map, chunk_store, true, path_out));
//   }
// }
// 
// }  // namespace test
// 
// }  // namespace encrypt
// 
// }  // namespace maidsafe
