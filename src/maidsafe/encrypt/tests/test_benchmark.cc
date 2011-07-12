/*******************************************************************************
 *  Copyright 2011 maidsafe.net limited                                   *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  test_benchmark.cc
 * @brief Stand-alone test to benchmark self-encryption.
 * @date  2011-04-05
 */

#include <cstdint>
#include <memory>
#include <vector>

#include "boost/timer.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/memory_chunk_store.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/log.h"
#include "maidsafe/encrypt/self_encryption.h"
#include "maidsafe/encrypt/utils.h"

namespace maidsafe {

namespace encrypt {

namespace test {

class SelfEncryptionBenchmarkTest
  : public testing::TestWithParam<SelfEncryptionParams> {
 public:
  SelfEncryptionBenchmarkTest()
      : test_dir_(),
        sep_(GetParam()) {
    boost::system::error_code ec;
    test_dir_ = boost::filesystem::temp_directory_path(ec) /
        ("maidsafe_TestSE_" + RandomAlphaNumericString(6));
  }
  virtual ~SelfEncryptionBenchmarkTest() {}
 protected:
  void SetUp() {
    if (fs::exists(test_dir_))
      fs::remove_all(test_dir_);
    fs::create_directory(test_dir_);

    printf("Current SE parameters:\n"
           "  max chunk size            = %d Bytes\n"
           "  max includable chunk size = %d Bytes\n"
           "  max includable data size  = %d bytes\n",
           sep_.max_chunk_size,
           sep_.max_includable_chunk_size,
           sep_.max_includable_data_size);
  }
  void TearDown() {
    try {
      if (fs::exists(test_dir_))
        fs::remove_all(test_dir_);
    }
    catch(const std::exception& e) {
      printf("%s\n", e.what());
    }
  }

  fs::path test_dir_;
  const SelfEncryptionParams sep_;
};

TEST_P(SelfEncryptionBenchmarkTest, FUNC_Benchmark) {
  const size_t kRunCount(16);
  for (size_t run = 0; run < kRunCount; ++run) {
    size_t repetitions(0);
    size_t data_size(64 << run);
    if (data_size <= (1 << 12))
      repetitions = 1000;
    else if (data_size <= (1 << 15))
      repetitions = 100;
    else
      repetitions = 10;

    printf("Timing Self-encryption of %d strings at %d bytes (run %d/%d)...\n",
           repetitions, data_size, run + 1, kRunCount);

    std::vector<std::shared_ptr<std::istringstream>> contents;
    std::vector<std::shared_ptr<DataMap>> data_maps;
    std::shared_ptr<ChunkStore> chunk_store(new MemoryChunkStore(true,
        std::bind(&crypto::HashFile<crypto::SHA512>, std::placeholders::_1)));
    for (size_t i = 0; i < repetitions; ++i) {
      std::shared_ptr<std::istringstream> stream_ptr(
          new std::istringstream(RandomString(data_size)));
      contents.push_back(stream_ptr);
      std::shared_ptr<DataMap> data_map_ptr(new DataMap);
      data_maps.push_back(data_map_ptr);
    }
    ASSERT_EQ(repetitions, contents.size());
    ASSERT_EQ(repetitions, data_maps.size());

    boost::posix_time::ptime time =
        boost::posix_time::microsec_clock::universal_time();
    for (size_t i = 0; i < repetitions; ++i)
      SelfEncrypt(contents[i], sep_, data_maps[i], chunk_store);
    uint64_t duration =
        (boost::posix_time::microsec_clock::universal_time() -
         time).total_microseconds();
    if (duration == 0)
      duration = 1;
    printf("Self-encrypted %d strings à %d bytes in %.2f seconds "
           "(%.3f MB/s).\n", repetitions, data_size, duration / 1000000.0,
           (repetitions * data_size) / duration / 1.048576);

    std::vector<std::shared_ptr<std::ostringstream>> dec_contents;
    for (size_t i = 0; i < repetitions; ++i) {
      std::shared_ptr<std::ostringstream> stream_ptr(new std::ostringstream);
      dec_contents.push_back(stream_ptr);
    }
    ASSERT_EQ(repetitions, dec_contents.size());

    time = boost::posix_time::microsec_clock::universal_time();
    for (size_t i = 0; i < repetitions; ++i)
      SelfDecrypt(data_maps[i], chunk_store, dec_contents[i]);
    duration = (boost::posix_time::microsec_clock::universal_time() -
                time).total_microseconds();
    if (duration == 0)
      duration = 1;

    printf("Self-decrypted %d strings à %d bytes in %.2f seconds "
           "(%.3f MB/s).\n", repetitions, data_size, duration / 1000000.0,
           (repetitions * data_size) / duration / 1.048576);

//     for (size_t i = 0; i < repetitions; ++i)
    size_t idx(RandomUint32() % repetitions);
    EXPECT_EQ(contents[idx]->str(), dec_contents[idx]->str());
  }
}

INSTANTIATE_TEST_CASE_P(ChunkSize, SelfEncryptionBenchmarkTest, testing::Values(
    // Variation in chunk_size
    SelfEncryptionParams(1 << 8, 0, kMinChunks - 1),  // 256 Bytes
    SelfEncryptionParams(1 << 10, 0, kMinChunks - 1),  // 1 KiB
    SelfEncryptionParams(1 << 12, 0, kMinChunks - 1),  // 4 KiB
    SelfEncryptionParams(1 << 14, 0, kMinChunks - 1),  // 16 KiB
    SelfEncryptionParams(1 << 16, 0, kMinChunks - 1),  // 64 KiB
    SelfEncryptionParams(1 << 17, 0, kMinChunks - 1),  // 128 KiB
    SelfEncryptionParams(1 << 18, 0, kMinChunks - 1),  // 256 KiB (default)
    SelfEncryptionParams(1 << 19, 0, kMinChunks - 1),  // 512 KiB
    SelfEncryptionParams(1 << 20, 0, kMinChunks - 1),  // 1 MiB
    SelfEncryptionParams(1 << 21, 0, kMinChunks - 1)  // 2 MiB
));

INSTANTIATE_TEST_CASE_P(IncData, SelfEncryptionBenchmarkTest, testing::Values(
    // Variation in max_includable_data_size
    SelfEncryptionParams(1 << 18, 0, 1 << 6),  // 64 Bytes
    SelfEncryptionParams(1 << 18, 0, 1 << 8),  // 256 Bytes
    SelfEncryptionParams(1 << 18, 0, 1 << 10),  // 1 KiB (default)
    SelfEncryptionParams(1 << 18, 0, 1 << 12),  // 4 KiB
    SelfEncryptionParams(1 << 18, 0, 1 << 14),  // 16 KiB
    SelfEncryptionParams(1 << 18, 0, 1 << 16)  // 64 KiB
));

INSTANTIATE_TEST_CASE_P(IncChunk, SelfEncryptionBenchmarkTest, testing::Values(
    // Variation in max_includable_chunk_size
    SelfEncryptionParams(1 << 18, 1 << 6, 1 << 8),  // 64 Bytes
    SelfEncryptionParams(1 << 18, 1 << 8, 1 << 10),  // 256 Bytes (default)
    SelfEncryptionParams(1 << 18, 1 << 10, 1 << 12),  // 1 KiB
    SelfEncryptionParams(1 << 18, 1 << 12, 1 << 14),  // 4 KiB
    SelfEncryptionParams(1 << 18, 1 << 14, 1 << 16),  // 16 KiB
    SelfEncryptionParams(1 << 18, 1 << 16, 1 << 18)  // 64 KiB
));

}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe

int main(int argc, char **argv) {
  google::InitGoogleLogging(argv[0]);
  // setting output to be stderr
  FLAGS_logtostderr = false;
  // Severity levels are INFO, WARNING, ERROR, and FATAL (0 to 3 respectively).
  FLAGS_minloglevel = google::FATAL;

  FLAGS_ms_logging_common = false;

  testing::InitGoogleTest(&argc, argv);
  int result(RUN_ALL_TESTS());
  int test_count = testing::UnitTest::GetInstance()->test_to_run_count();
  return (test_count == 0) ? -1 : result;
}
