/*******************************************************************************
 *  Copyright 2009 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  test_string_io_handler.cc
 * @brief Tests for the interface to handle string IO operations.
 * @date  2009-10-25
 */

#include <cstdint>
#include <limits>
#include <memory>

#include "gtest/gtest.h"
#include "maidsafe-dht/common/utils.h"
#include "maidsafe-encrypt/data_io_handler.h"

namespace maidsafe {

namespace encrypt {

namespace test {

class StringIOHandlerTest : public testing::Test {
 public:
  StringIOHandlerTest()
      : kMinSize_(1000),
        kDataSize_((RandomUint32() % 249000) + kMinSize_),
        // ensure input contains null chars
        kData_(std::string(10, 0) + RandomString(kDataSize_ - 10)),
        data_(kData_) {}
 protected:
  const size_t kMinSize_, kDataSize_;
  const std::string kData_;
  std::string data_;
};

TEST_F(StringIOHandlerTest, BEH_ENCRYPT_TestReadFromString) {
  // Check before opening
  StringIOHandler input_handler(&data_, true);
  EXPECT_EQ(kData_, input_handler.Data());
  std::uint64_t tempsize;
  EXPECT_TRUE(input_handler.Size(&tempsize));
  EXPECT_EQ(kDataSize_, tempsize);
  EXPECT_FALSE(input_handler.Write("a"));
  size_t test_size(kMinSize_ / 10);
  std::string read_data("Test");
  EXPECT_FALSE(input_handler.Read(test_size, &read_data));
  EXPECT_TRUE(read_data.empty());
  EXPECT_FALSE(input_handler.SetGetPointer(test_size));

  // Check after opening
  EXPECT_TRUE(input_handler.Open());
  EXPECT_EQ(kData_, input_handler.Data());
  EXPECT_FALSE(input_handler.Write("a"));
  read_data = "Test";
  EXPECT_TRUE(input_handler.Read(test_size, &read_data));
  EXPECT_EQ(kData_.substr(0, test_size), read_data);

  // Read again
  read_data.clear();
  EXPECT_TRUE(input_handler.Read(test_size, &read_data));
  EXPECT_EQ(kData_.substr(test_size, test_size), read_data);

  // Read past eof
  EXPECT_TRUE(input_handler.Read(kDataSize_, &read_data));
  EXPECT_EQ(kData_.substr(2 * test_size), read_data);

  // Read again
  EXPECT_TRUE(input_handler.Read(test_size, &read_data));
  EXPECT_TRUE(read_data.empty());

  // Check re-opening while open has no effect
  EXPECT_TRUE(input_handler.Open());
  EXPECT_EQ(kData_, input_handler.Data());
  read_data = "Test";
  EXPECT_TRUE(input_handler.Read(test_size, &read_data));
  EXPECT_TRUE(read_data.empty());

  // Check after closing
  input_handler.Close();
  EXPECT_EQ(kData_, input_handler.Data());
  read_data = "Test";
  EXPECT_FALSE(input_handler.Read(test_size, &read_data));
  EXPECT_TRUE(read_data.empty());

  // Check re-opening sets get pointer back to 0
  EXPECT_TRUE(input_handler.Open());
  EXPECT_EQ(kData_, input_handler.Data());
  EXPECT_TRUE(input_handler.Read(test_size, &read_data));
  EXPECT_EQ(kData_.substr(0, test_size), read_data);

  // Check empty string handling
  std::string empty_data;
  StringIOHandler empty_input_handler(&empty_data, true);
  EXPECT_TRUE(empty_input_handler.Data().empty());
  EXPECT_TRUE(empty_input_handler.Size(&tempsize));
  EXPECT_EQ(0U, tempsize);
  EXPECT_TRUE(empty_input_handler.Open());
  read_data = "Test";
  EXPECT_TRUE(empty_input_handler.Read(test_size, &read_data));
  EXPECT_TRUE(read_data.empty());
}

TEST_F(StringIOHandlerTest, BEH_ENCRYPT_TestSetGetPointerString) {
  // Open and apply offset
  StringIOHandler input_handler(&data_, true);
  size_t test_size(kMinSize_ / 10), offset(kMinSize_ / 2);
  EXPECT_FALSE(input_handler.SetGetPointer(test_size));
  std::string read_data;
  EXPECT_TRUE(input_handler.Open());
  EXPECT_TRUE(input_handler.SetGetPointer(offset));
  EXPECT_TRUE(input_handler.Read(test_size, &read_data));
  EXPECT_EQ(kData_.substr(offset, test_size), read_data);

  // Retry with different offset
  offset = kMinSize_ / 3;
  EXPECT_TRUE(input_handler.SetGetPointer(offset));
  EXPECT_TRUE(input_handler.Read(test_size, &read_data));
  EXPECT_EQ(kData_.substr(offset, test_size), read_data);

  // Retry with offset > file size
  offset = kDataSize_ + 1;
  EXPECT_TRUE(input_handler.SetGetPointer(offset));
  EXPECT_TRUE(input_handler.Read(test_size, &read_data));
  EXPECT_TRUE(read_data.empty());
}

TEST_F(StringIOHandlerTest, BEH_ENCRYPT_WriteToString) {
  // Check before opening
  StringIOHandler output_handler(&data_, false);
  EXPECT_EQ(kData_, output_handler.Data());
  std::uint64_t tempsize;
  EXPECT_TRUE(output_handler.Size(&tempsize));
  EXPECT_EQ(kDataSize_, tempsize);
  EXPECT_FALSE(output_handler.Write("abc"));
  size_t test_size(kMinSize_ / 10);
  std::string read_data("Test");
  EXPECT_FALSE(output_handler.Read(test_size, &read_data));
  EXPECT_TRUE(read_data.empty());
  EXPECT_FALSE(output_handler.SetGetPointer(test_size));

  // Check after opening
  EXPECT_TRUE(output_handler.Open());
  EXPECT_TRUE(output_handler.Data().empty());
  EXPECT_TRUE(output_handler.Size(&tempsize));
  EXPECT_EQ(0U, tempsize);
  read_data = "Test";
  EXPECT_FALSE(output_handler.Read(test_size, &read_data));
  EXPECT_TRUE(read_data.empty());
  size_t split(RandomUint32() % kDataSize_);
  std::string part1(kData_.substr(0, split)), part2(kData_.substr(split));
  EXPECT_TRUE(output_handler.Write(part1));
  EXPECT_EQ(part1, output_handler.Data());
  EXPECT_TRUE(output_handler.Size(&tempsize));
  EXPECT_EQ(split, tempsize);

  // Write again
  EXPECT_TRUE(output_handler.Write(part2));
  EXPECT_EQ(kData_, output_handler.Data());
  EXPECT_TRUE(output_handler.Size(&tempsize));
  EXPECT_EQ(kDataSize_, tempsize);

  // Write with empty string
  EXPECT_TRUE(output_handler.Write(""));
  EXPECT_EQ(kData_, output_handler.Data());
  EXPECT_TRUE(output_handler.Size(&tempsize));
  EXPECT_EQ(kDataSize_, tempsize);

  // Check re-opening while open has no effect
  EXPECT_TRUE(output_handler.Open());
  EXPECT_EQ(kData_, output_handler.Data());
  EXPECT_TRUE(output_handler.Size(&tempsize));
  EXPECT_EQ(kDataSize_, tempsize);
  EXPECT_TRUE(output_handler.Write("a"));
  EXPECT_EQ(kData_ + "a", output_handler.Data());
  EXPECT_TRUE(output_handler.Size(&tempsize));
  EXPECT_EQ(kDataSize_ + 1, tempsize);

  // Check after closing
  output_handler.Close();
  EXPECT_EQ(kData_ + "a", output_handler.Data());
  EXPECT_TRUE(output_handler.Size(&tempsize));
  EXPECT_EQ(kDataSize_ + 1, tempsize);
  EXPECT_FALSE(output_handler.Write("b"));
  EXPECT_EQ(kData_ + "a", output_handler.Data());
  EXPECT_TRUE(output_handler.Size(&tempsize));
  EXPECT_EQ(kDataSize_ + 1, tempsize);

  // Check re-opening after closing clears data
  EXPECT_TRUE(output_handler.Open());
  EXPECT_TRUE(output_handler.Data().empty());
  EXPECT_TRUE(output_handler.Size(&tempsize));
  EXPECT_EQ(0U, tempsize);
  EXPECT_TRUE(output_handler.Write(kData_));
  EXPECT_EQ(kData_, output_handler.Data());
  EXPECT_TRUE(output_handler.Size(&tempsize));
  EXPECT_EQ(kDataSize_, tempsize);
}

}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
