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

#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/cache.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {

TEST(CacheTest, BEH_Constructor) {
  Cache cache;
  EXPECT_NO_THROW(Cache cache);
  EXPECT_NO_THROW(Cache cache(0));
  EXPECT_NO_THROW(Cache cache(std::numeric_limits<uint32_t>::max()));
  EXPECT_NO_THROW(Cache cache(std::numeric_limits<uint32_t>::min()));
}

TEST(CacheTest, BEH_Get_empty) {
  Cache cache;
  EXPECT_NO_THROW(Cache cache);
  std::vector<char> data{3};
  EXPECT_FALSE(cache.Get(data, 2, 99)) << "reading data not written";
  EXPECT_FALSE(cache.Get(data, 0, 0)) << "reading data not written";
  EXPECT_FALSE(cache.Get(data, 0, std::numeric_limits<uint64_t>::min()))
      << "reading data not written";
  EXPECT_FALSE(cache.Get(data, 0, std::numeric_limits<uint64_t>::max()))
      << "reading data not written";
  EXPECT_FALSE(
      cache.Get(data, std::numeric_limits<uint32_t>::max(), std::numeric_limits<uint64_t>::max()))
      << "reading data not written";
  EXPECT_FALSE(
      cache.Get(data, std::numeric_limits<uint32_t>::min(), std::numeric_limits<uint64_t>::max()))
      << "reading data not written";
  EXPECT_FALSE(
      cache.Get(data, std::numeric_limits<uint32_t>::max(), std::numeric_limits<uint64_t>::min()))
      << "reading data not written";
  EXPECT_FALSE(
      cache.Get(data, std::numeric_limits<uint32_t>::min(), std::numeric_limits<uint64_t>::min()))
      << "reading data not written";
}


TEST(CacheTest, BEH_PutInSequence) {
  Cache cache;
  EXPECT_NO_THROW(Cache cache);
  std::vector<char> v(10000);
  std::generate(v.begin(), v.end(), [] {return static_cast<char>(RandomUint32()); ;});
  cache.Put(v, 0);
  std::vector<char> answer;
  EXPECT_TRUE(cache.Get(answer, v.size(), 0));
  EXPECT_EQ(v, answer);
}

TEST(CacheTest, BEH_MoreTHanMaxSize) {
  Cache cache(10);
  EXPECT_NO_THROW(Cache cache);
  std::vector<char> v(10000);
  std::generate(v.begin(), v.end(), [] {return static_cast<char>(RandomUint32()); ;});
  cache.Put(v, 0);
  std::vector<char> answer;
  EXPECT_FALSE(cache.Get(answer, v.size(), 0));
  EXPECT_NE(v, answer);
}

TEST(CacheTest, BEH_PutOutOfSequence) {
  Cache cache;
  EXPECT_NO_THROW(Cache cache);
  std::vector<char> v(10000);
  std::generate(v.begin(), v.end(), [] {return static_cast<char>(RandomUint32()); ;});
  std::vector<char> v2(10000);
  std::generate(v.begin(), v.end(), [] {return static_cast<char>(RandomUint32()); ;});
  cache.Put(v, 0);
  cache.Put(v2, 10);
  std::vector<char> answer;
  EXPECT_TRUE(cache.Get(answer, v.size(), 0));
  EXPECT_EQ(v, answer);
}





}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
