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
  ByteVector data{3};
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
  ByteVector v(10000);
  std::generate(v.begin(), v.end(), [] {
    return static_cast<char>(RandomUint32());
  });
  cache.Put(v, 0);
  ByteVector answer;
  EXPECT_TRUE(cache.Get(answer, static_cast<uint32_t>(v.size()), 0));
  EXPECT_EQ(v, answer);
}

TEST(CacheTest, BEH_MoreTHanMaxSize) {
  Cache cache_10(10);
  Cache cache_zero(0);
  ByteVector v(11);
  std::generate(v.begin(), v.end(), [] { return static_cast<char>(RandomUint32()); });
  cache_10.Put(v, 0);
  cache_zero.Put(v, 0);

  ByteVector answer;
  EXPECT_FALSE(cache_10.Get(answer, static_cast<uint32_t>(v.size()), 0));
  EXPECT_FALSE(cache_zero.Get(answer, static_cast<uint32_t>(v.size()), 0));
  EXPECT_TRUE(answer.empty());
}

TEST(CacheTest, BEH_PutOutOfSequence) {
  Cache cache;
  EXPECT_NO_THROW(Cache cache);
  ByteVector v(10000);
  std::generate(v.begin(), v.end(), [] { return static_cast<char>(RandomUint32()); });
  auto v2 = v;
  auto offset = 10;
  cache.Put(v, 0);
  cache.Put(v2, offset);
  ByteVector answer1, answer2;
  EXPECT_TRUE(cache.Get(answer1, static_cast<uint32_t>(v2.size()), offset))
      << "Unable to read from just written data";
  EXPECT_EQ(v, answer1) << "invalid data read from an offset";
  cache.Put(v, 0);
  EXPECT_TRUE(cache.Get(answer2, static_cast<uint32_t>(v2.size()), 0))
      << "Unable to read from just written data";
  EXPECT_EQ(v, answer2);
  answer1.clear();
  EXPECT_TRUE(cache.Get(answer1, static_cast<uint32_t>(v.size()), offset))
      << "should have been erased from this position";
  EXPECT_NE(v, answer1);
  EXPECT_EQ(v, answer2);
  EXPECT_EQ(v[10], answer1[0]);
  cache.Put(v, v.size());
  cache.Put(v, v.size() * 2);
}



}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
