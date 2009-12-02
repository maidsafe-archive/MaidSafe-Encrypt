/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Interface to handle IO operations.
* Version:      1.0
* Created:      2009-10-25
* Revision:     none
* Compiler:     gcc
* Author:       Alec Macdonald
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
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem.hpp>
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>

#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/client/dataiohandler.h"

class TestStringIOHandler : public testing::Test {
 public:
  TestStringIOHandler() : handler_(), data_(base::RandomString(255*1024)) {}
 protected:
  virtual void SetUp() {
    ASSERT_EQ("", handler_.GetAsString());
  }
  virtual void TearDown() {
    handler_.Reset();
  }
  StringIOHandler handler_;
  std::string data_;
};

TEST_F(TestStringIOHandler, BEH_MAID_TestReadFromString) {
  ASSERT_TRUE(handler_.SetData(data_, true));
  boost::uint64_t tempsize;
  handler_.Size(&tempsize);
  ASSERT_EQ(255*1024, tempsize);
  ASSERT_FALSE(handler_.Write("abc", 3));
  unsigned int size(10);
  char *read_data = new char[size];
  ASSERT_FALSE(handler_.Read(read_data, size));
  ASSERT_TRUE(handler_.Open());
  ASSERT_FALSE(handler_.SetData(data_, true));

  ASSERT_FALSE(handler_.Write("abc", 3));
  ASSERT_TRUE(handler_.Read(read_data, size));
  std::string result(read_data, size);
  ASSERT_EQ(data_.substr(0, size), result);
  result.clear();

  ASSERT_TRUE(handler_.Read(read_data, size));
  result = std::string(read_data, size);
  ASSERT_EQ(data_.substr(size, size), result);

  handler_.Close();
  handler_.Reset();
  ASSERT_EQ(std::string(""), handler_.GetAsString());

  delete[] read_data;
}

TEST_F(TestStringIOHandler, BEH_MAID_TestSetGetPointerString) {
  ASSERT_TRUE(handler_.SetData(data_, true));
  ASSERT_FALSE(handler_.SetGetPointer(999));
  unsigned int size(24);
  char *read_data = new char[size];
  ASSERT_TRUE(handler_.Open());
  ASSERT_TRUE(handler_.SetGetPointer(999));
  ASSERT_TRUE(handler_.Read(read_data, size));
  std::string result(read_data, size);
  ASSERT_EQ(data_.substr(999, 24), result);
  handler_.Close();

  delete[] read_data;
}

TEST_F(TestStringIOHandler, BEH_MAID_WriteToString) {
  ASSERT_TRUE(handler_.SetData("", false));
  ASSERT_FALSE(handler_.Write("abc", 3));
  unsigned int size(10);
  char *read_data = new char[size];
  ASSERT_TRUE(handler_.Open());
  ASSERT_FALSE(handler_.SetData("", false));
  ASSERT_FALSE(handler_.Read(read_data, size));
  std::string in_data = base::RandomString(20);
  std::string result = in_data;
  ASSERT_TRUE(handler_.Write(in_data.c_str(), in_data.size()));
  in_data = base::RandomString(10);
  result += in_data;
  ASSERT_TRUE(handler_.Write(in_data.c_str(), in_data.size()));
  ASSERT_EQ(result, handler_.GetAsString());
  handler_.Close();
  boost::uint64_t tempsize;
  handler_.Size(&tempsize);
  ASSERT_EQ(30, tempsize);
  handler_.Reset();
  ASSERT_EQ(std::string(""), handler_.GetAsString());
  delete [] read_data;
}

class TestFileIOHandler : public testing::Test {
 public:
  TestFileIOHandler() : handler_(), in_file(), out_file(),
    data_(base::RandomString(255*1024)), in("in_file"), out("out_file") {
    in += boost::lexical_cast<std::string>(
      base::random_32bit_integer());
    out += boost::lexical_cast<std::string>(
      base::random_32bit_integer());
  }
 protected:
  virtual void SetUp() {
    ASSERT_EQ("", handler_.GetAsString());
    in_file.open(in, std::ifstream::binary);
  }
  virtual void TearDown() {
    handler_.Reset();
    try {
      if (boost::filesystem::exists(
          boost::filesystem::path(in)))
        boost::filesystem::remove(boost::filesystem::path(in));
      if (boost::filesystem::exists(
          boost::filesystem::path(out)))
        boost::filesystem::remove(boost::filesystem::path(out));
    }
    catch(const std::exception&) {
    }
  }
  void WriteDataToInFile() {
    boost::filesystem::ofstream out_file;
    try {
      out_file.open(in, boost::filesystem::ofstream::binary);
      out_file.write(data_.c_str(), data_.size());
      out_file.close();
    }
    catch(const std::exception&) {
    }
  }
  std::string ReadDataFromOutFile() {
    boost::filesystem::ifstream in_file;
    boost::uint64_t size = boost::filesystem::file_size(
      boost::filesystem::path(out));
    char *data = new char[size];
    try {
      in_file.open(out, boost::filesystem::ofstream::binary);
      in_file.read(data, size);
      out_file.close();
    }
    catch(const std::exception&) {
    }
    std::string str(data, size);
    delete[] data;
    return str;
  }
  FileIOHandler handler_;
  boost::filesystem::fstream in_file, out_file;
  std::string data_, in, out;
};

TEST_F(TestFileIOHandler, BEH_MAID_TestReadFromFile) {
  WriteDataToInFile();
  ASSERT_TRUE(handler_.SetData(in, true));
  ASSERT_FALSE(handler_.Write("abc", 3));
  unsigned int size(10);
  char *read_data = new char[size];
  ASSERT_FALSE(handler_.Read(read_data, size));
  ASSERT_TRUE(handler_.Open());
  ASSERT_FALSE(handler_.SetData(in, true));

  ASSERT_FALSE(handler_.Write("abc", 3));
  ASSERT_TRUE(handler_.Read(read_data, size));
  std::string result(read_data, size);
  ASSERT_EQ(data_.substr(0, size), result);
  result.clear();

  ASSERT_TRUE(handler_.Read(read_data, size));
  result = std::string(read_data, size);
  ASSERT_EQ(data_.substr(size, size), result);
  handler_.Close();
  handler_.Reset();
  ASSERT_EQ(std::string(""), handler_.GetAsString());

  delete[] read_data;
}

TEST_F(TestFileIOHandler, BEH_MAID_TestSetGetPointerFile) {
  WriteDataToInFile();
  handler_.SetData(in, true);
  ASSERT_FALSE(handler_.SetGetPointer(999));
  unsigned int size(24);
  char *read_data = new char[size];
  ASSERT_TRUE(handler_.Open());
  ASSERT_TRUE(handler_.SetGetPointer(999));
  ASSERT_TRUE(handler_.Read(read_data, size));
  std::string result(read_data, size);
  ASSERT_EQ(data_.substr(999, size), result);
  handler_.Close();

  delete[] read_data;
}

TEST_F(TestFileIOHandler, BEH_MAID_WriteToFile) {
  handler_.SetData(out, false);
  ASSERT_FALSE(handler_.Write("abc", 3));
  unsigned int size(10);
  char *read_data = new char[size];
  ASSERT_TRUE(handler_.Open());
  ASSERT_FALSE(handler_.Read(read_data, size));
  std::string in_data = base::RandomString(20);
  std::string result = in_data;
  ASSERT_TRUE(handler_.Write(in_data.c_str(), in_data.size()));
  in_data = base::RandomString(10);
  result += in_data;
  ASSERT_TRUE(handler_.Write(in_data.c_str(), in_data.size()));
  handler_.Close();
  ASSERT_EQ(result, ReadDataFromOutFile());
  boost::uint64_t tempsize;
  handler_.Size(&tempsize);
  ASSERT_EQ(30, tempsize);
  handler_.Reset();
  ASSERT_EQ(std::string(""), handler_.GetAsString());
  delete [] read_data;
}
