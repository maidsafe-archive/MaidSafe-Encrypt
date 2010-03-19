/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Test for CryptoKeyPairs class
* Version:      1.0
* Created:      2010-03-15-17.21.51
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

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include "maidsafe/client/packetfactory.h"

namespace fs = boost::filesystem;

namespace maidsafe {

class CryptoKeyPairsTest : public testing::Test {
 public:
  CryptoKeyPairsTest() {}
 protected:
  void SetUp() {}
  void TearDown() {}
 private:
  CryptoKeyPairsTest &operator=(const CryptoKeyPairsTest&);
  CryptoKeyPairsTest(const CryptoKeyPairsTest&);
};

TEST_F(CryptoKeyPairsTest, BEH_MAID_GetCryptoKeysUnthreaded) {
  CryptoKeyPairs ckp;
  ckp.Init(0, 0);
  ASSERT_EQ(boost::uint16_t(0), ckp.max_thread_count_);
  ASSERT_EQ(boost::uint16_t(0), ckp.buffer_count_);
  ASSERT_EQ(boost::uint16_t(0), ckp.running_thread_count_);
  ASSERT_TRUE(ckp.key_buffer_.empty());
  crypto::RsaKeyPair rsakp = ckp.GetKeyPair();
  ASSERT_FALSE(rsakp.public_key().empty());
  ASSERT_FALSE(rsakp.private_key().empty());
  ASSERT_EQ(boost::uint16_t(0), ckp.max_thread_count_);
  ASSERT_EQ(boost::uint16_t(0), ckp.buffer_count_);
  ASSERT_EQ(boost::uint16_t(0), ckp.running_thread_count_);
  ASSERT_TRUE(ckp.key_buffer_.empty());
}

TEST_F(CryptoKeyPairsTest, FUNC_MAID_GetCryptoKeysThreaded) {
  CryptoKeyPairs ckp;
  ckp.Init(kMaxCryptoThreadCount + 1, kNoOfSystemPackets + 1);
  ASSERT_EQ(kMaxCryptoThreadCount, ckp.max_thread_count());
  ASSERT_EQ(kNoOfSystemPackets, ckp.buffer_count());
  const int kTimeout(200000);
  int count(0);
  bool success(false);
  while (count < kTimeout) {
    boost::mutex::scoped_lock lock(ckp.kb_mutex_);
    if (ckp.key_buffer_.size() == ckp.buffer_count_) {
      success = true;
      break;
    } else {
      lock.unlock();
      count += 100;
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    }
  }
  ASSERT_TRUE(success);
  {
    boost::mutex::scoped_lock lock(ckp.kb_mutex_);
    ASSERT_EQ(boost::uint16_t(0), ckp.running_thread_count_);
  }
  ckp.set_max_thread_count(0);
  ckp.set_buffer_count(0);
  {
    boost::mutex::scoped_lock lock(ckp.kb_mutex_);
    ASSERT_EQ(ckp.key_buffer_.size(), kNoOfSystemPackets);
  }
  crypto::RsaKeyPair rsakp;
  for (size_t i = 0; i < kNoOfSystemPackets; ++i) {
    rsakp = ckp.GetKeyPair();
    ASSERT_FALSE(rsakp.public_key().empty());
    ASSERT_FALSE(rsakp.private_key().empty());
  }
  {
    boost::mutex::scoped_lock lock(ckp.kb_mutex_);
    ASSERT_EQ(boost::uint16_t(0), ckp.running_thread_count_);
    ASSERT_EQ(size_t(0), ckp.key_buffer_.size());
  }
  ckp.set_max_thread_count(kMaxCryptoThreadCount + 1);
  ASSERT_EQ(kMaxCryptoThreadCount, ckp.max_thread_count());
  {
    boost::mutex::scoped_lock lock(ckp.kb_mutex_);
    ASSERT_EQ(size_t(0), ckp.key_buffer_.size());
    ASSERT_EQ(boost::uint16_t(0), ckp.running_thread_count_);
  }
  rsakp = ckp.GetKeyPair();
  {
    boost::mutex::scoped_lock lock(ckp.kb_mutex_);
    ASSERT_EQ(size_t(0), ckp.key_buffer_.size());
    ASSERT_EQ(boost::uint16_t(0), ckp.running_thread_count_);
  }
  ckp.set_max_thread_count(0);
  ckp.set_buffer_count(kNoOfSystemPackets + 1);
  ASSERT_EQ(kNoOfSystemPackets, ckp.buffer_count());
  {
    boost::mutex::scoped_lock lock(ckp.kb_mutex_);
    ASSERT_EQ(size_t(0), ckp.key_buffer_.size());
    ASSERT_EQ(boost::uint16_t(0), ckp.running_thread_count_);
  }
  rsakp = ckp.GetKeyPair();
  {
    boost::mutex::scoped_lock lock(ckp.kb_mutex_);
    ASSERT_EQ(size_t(0), ckp.key_buffer_.size());
    ASSERT_EQ(boost::uint16_t(0), ckp.running_thread_count_);
  }
  ckp.set_max_thread_count(1);
}

}  // namespace maidsafe
