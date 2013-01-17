
/*******************************************************************************
*  Copyright 2011 MaidSafe.net limited                                         *
*                                                                              *
*  The following source code is property of MaidSafe.net limited and is not    *
*  meant for external use.  The use of this code is governed by the license    *
*  file LICENSE.TXT found in the root of this directory and also on            *
*  www.MaidSafe.net.                                                           *
*                                                                              *
*  You are not free to copy, amend or otherwise use this source code without   *
*  the explicit written permission of the board of directors of MaidSafe.net.  *
*******************************************************************************/

#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/filesystem/operations.hpp"
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/encrypt/tests/encrypt_test_base.h"


namespace bptime = boost::posix_time;

namespace maidsafe {
namespace encrypt {
namespace test {

class Benchmark : public EncryptTestBase,
                  public testing::TestWithParam<uint32_t> {
 public:
  Benchmark() : EncryptTestBase(0),
                kTestDataSize_(1024 * 1024 * 20),
                kPieceSize_(GetParam() ? GetParam() : kTestDataSize_) {
    original_.reset(new char[kTestDataSize_]);
    decrypted_.reset(new char[kTestDataSize_]);
  }

 protected:
  void PrintResult(const bptime::ptime &start_time,
                   const bptime::ptime &stop_time,
                   bool encrypting,
                   bool compressible) {
    uint64_t duration = (stop_time - start_time).total_microseconds();
    if (duration == 0)
      duration = 1;
    uint64_t rate((static_cast<uint64_t>(kTestDataSize_) * 1000000) / duration);
    std::string encrypted(encrypting ? "Self-encrypted " : "Self-decrypted ");
    std::string comp(compressible ? "compressible" : "incompressible");
    std::cout << encrypted << BytesToBinarySiUnits(kTestDataSize_) << " of "
              << comp << " data in " << BytesToBinarySiUnits(kPieceSize_)
              << " pieces in " << (duration / 1000000.0) << " seconds at a "
              << "speed of " << BytesToBinarySiUnits(rate) << "/s" << std::endl;
  }
  const uint32_t kTestDataSize_, kPieceSize_;
};

TEST_P(Benchmark, FUNC_BenchmarkMemOnly) {
  bool compressible(true);
  for (int z(0); z != 2; ++z) {
    if (compressible) {
      memset(original_.get(), 'a', kTestDataSize_);
    } else {
      memcpy(original_.get(), RandomString(kTestDataSize_).data(),
             kTestDataSize_);
    }

    bptime::ptime start_time(bptime::microsec_clock::universal_time());
    for (uint32_t i(0); i < kTestDataSize_; i += kPieceSize_)
      ASSERT_TRUE(self_encryptor_->Write(&original_[i], kPieceSize_, i));
    self_encryptor_->Flush();
    bptime::ptime stop_time(bptime::microsec_clock::universal_time());
    PrintResult(start_time, stop_time, true, compressible);

    start_time = bptime::microsec_clock::universal_time();
    for (uint32_t i(0); i < kTestDataSize_; i += kPieceSize_)
      ASSERT_TRUE(self_encryptor_->Read(&decrypted_[i], kPieceSize_, i));
    stop_time = bptime::microsec_clock::universal_time();
    for (uint32_t i(0); i < kTestDataSize_; ++i)
      ASSERT_EQ(original_[i], decrypted_[i]) << "failed @ count " << i;
    PrintResult(start_time, stop_time, false, compressible);
    compressible = false;
  }
}

INSTANTIATE_TEST_CASE_P(WriteRead, Benchmark, testing::Values(0, 4096, 65536));

// This test is to allow confirmation that memory usage is capped at an
// acceptable level.  While the test is running, memory usage must be visually
// monitored.
TEST(MassiveFile, FUNC_MemCheck) {
  int kNumProcs(8);
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  fs::path data_store_path(*test_dir / "data_store");
  ClientNfsPtr client_nfs;
  DataStore data_store(MemoryUsage(uint64_t(0)),
                       DiskUsage(uint64_t(4294967296)),  // 1 << 32
                       PopFunctor(),
                       data_store_path);

  DataMapPtr data_map(new DataMap);
  SelfEncryptorPtr self_encryptor(new SelfEncryptor(data_map, *client_nfs, data_store, kNumProcs));

  const uint32_t kDataSize((1 << 20) + 1);
  boost::scoped_array<char> original(new char[kDataSize]);
  std::string content(RandomString(kDataSize));
  std::copy(content.data(), content.data() + kDataSize, original.get());

  // Writes ~200MB
  for (uint64_t offset(0); offset != 200 * kDataSize; offset += kDataSize)
    EXPECT_TRUE(self_encryptor->Write(original.get(), kDataSize, offset));

  LOG(kInfo) << "Resetting self encryptor.";
  self_encryptor.reset();
  // Sleep to allow chosen memory monitor to update its display.
  Sleep(boost::posix_time::seconds(1));

  LOG(kInfo) << "Resetting chunk store.";
  client_nfs.reset();
  boost::system::error_code rm_error_code, exists_error_code;
  EXPECT_GT(fs::remove_all(data_store_path, rm_error_code), 0U)
      << rm_error_code.message();
  EXPECT_FALSE(fs::exists(data_store_path, exists_error_code))
      << "Remove all failed: " << rm_error_code
      << (exists_error_code ?
          "\nExists error: " + exists_error_code.message() :
          "");
  // Sleep to allow chosen memory monitor to update its display.
  Sleep(boost::posix_time::seconds(3));
}

}  // namespace test
}  // namespace encrypt
}  // namespace maidsafe
