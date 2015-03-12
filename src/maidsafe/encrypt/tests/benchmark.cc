/*  Copyright 2011 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include <chrono>
#include <memory>
#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/test.h"

#include "maidsafe/encrypt/tests/encrypt_test_base.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {

class Benchmark : public EncryptTestBase, public testing::TestWithParam<uint32_t> {
 public:
  typedef std::chrono::time_point<std::chrono::high_resolution_clock> chrono_time_point;

  Benchmark()
      : EncryptTestBase(),
        kTestDataSize_(1024 * 1024 * 20),
        kPieceSize_(GetParam() ? GetParam() : kTestDataSize_) {
    original_.reset(new char[kTestDataSize_]);
    decrypted_.reset(new char[kTestDataSize_]);
  }

 protected:
  void PrintResult(const chrono_time_point& start_time, const chrono_time_point& stop_time,
                   bool encrypting, bool compressible) {
    uint64_t duration =
        std::chrono::duration_cast<std::chrono::microseconds>(stop_time - start_time).count();
    if (duration == 0)
      duration = 1;
    uint64_t rate((static_cast<uint64_t>(kTestDataSize_) * 1000000) / duration);
    std::string encrypted(encrypting ? "Self-encrypted " : "Self-decrypted ");
    std::string comp(compressible ? "compressible" : "incompressible");
    std::cout << encrypted << BytesToDecimalSiUnits(kTestDataSize_) << " of " << comp << " data in "
              << BytesToDecimalSiUnits(kPieceSize_) << " pieces in " << (duration / 1000)
              << " milliseconds at a speed of " << BytesToDecimalSiUnits(rate) << "/s\n";
  }
  void WriteThenRead(bool compressible) {
    chrono_time_point start_time(std::chrono::high_resolution_clock::now());
    for (uint32_t i(0); i < kTestDataSize_; i += kPieceSize_)
      ASSERT_TRUE(self_encryptor_->Write(&original_[i], kPieceSize_, i));
    self_encryptor_->Close();
    chrono_time_point stop_time(std::chrono::high_resolution_clock::now());
    PrintResult(start_time, stop_time, true, compressible);

    self_encryptor_ =
        maidsafe::make_unique<SelfEncryptor>(data_map_, local_store_, get_from_store_);
    start_time = std::chrono::high_resolution_clock::now();
    for (uint32_t i(0); i < kTestDataSize_; i += kPieceSize_)
      ASSERT_TRUE(self_encryptor_->Read(&decrypted_[i], kPieceSize_, i));
    stop_time = std::chrono::high_resolution_clock::now();
    for (uint32_t i(0); i < kTestDataSize_; ++i)
      ASSERT_EQ(original_[i], decrypted_[i]) << "failed @ count " << i;
    PrintResult(start_time, stop_time, false, compressible);
    self_encryptor_->Close();
  }
  const uint32_t kTestDataSize_, kPieceSize_;
};

TEST_P(Benchmark, FUNC_BenchmarkCompressible) {
  memset(original_.get(), 'a', kTestDataSize_);
  WriteThenRead(true);
}

TEST_P(Benchmark, FUNC_BenchmarkIncompressible) {
  memcpy(original_.get(), RandomString(kTestDataSize_).data(), kTestDataSize_);
  WriteThenRead(false);
}

INSTANTIATE_TEST_CASE_P(WriteRead, Benchmark, testing::Values(0, 4096, 65536, 1048576));

// This test is to allow confirmation that memory usage is capped at an
// acceptable level.  While the test is running, memory usage must be visually
// monitored.
TEST(MassiveFile, FUNC_MemCheck) {
  maidsafe::test::TestPath test_dir(maidsafe::test::CreateTestPath());
  fs::path store_path(*test_dir / "data_store");
  DataBuffer buffer(
      MemoryUsage(4294967296U),
      DiskUsage(4294967296U),
      [](const DataBuffer::KeyType& name, const NonEmptyString&) {
    LOG(kError) << "Buffer full - deleting " << base64::Substr(name.name);
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::cannot_exceed_limit));
  },
    store_path);

  DataMap data_map;
  std::unique_ptr<SelfEncryptor> self_encryptor(
      new SelfEncryptor(data_map, buffer, [&buffer](const std::string& name) {
        return buffer.Get(DataBuffer::KeyType(Identity(name), DataTypeId(0)));
      }));

  const uint32_t kDataSize((1 << 20) + 1);
  std::unique_ptr<char> original(new char[kDataSize]);
  std::string content(RandomString(kDataSize));
  std::copy(content.data(), content.data() + kDataSize, original.get());

  // Writes ~200MB
  for (uint64_t offset(0); offset != 200 * kDataSize; offset += kDataSize)
    EXPECT_TRUE(self_encryptor->Write(original.get(), kDataSize, offset));

  LOG(kInfo) << "Resetting self encryptor.";
  self_encryptor->Close();
}

}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
