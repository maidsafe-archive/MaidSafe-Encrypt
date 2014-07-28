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
#include "maidsafe/encrypt/sequencer.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {

TEST(SequencerTest, BEH_Chunk1WriteRead) {
  Sequencer seq;
  ByteVector vec{'a', 'b', '2'};
  seq.Add(vec, 0);
  ByteVector result(seq.Read(3, 0));
  EXPECT_TRUE(vec.size() == 3);
  EXPECT_TRUE(result.size() == 3);
  EXPECT_EQ(vec, result);
  // Try reading at an offset.
  ByteVector result2(seq.Read(2, 1));
  EXPECT_EQ(result2.size(), 2);
  EXPECT_EQ(vec[1], result2[0]);
  // Try reading past end.
  ByteVector result3(seq.Read(3, 2));
  EXPECT_EQ(result3.size(), 1);
  EXPECT_EQ(vec[2], result3[0]);
  // Try reading past end.
  ByteVector result4(seq.Read(3, 4));
  EXPECT_EQ(result4.size(), 0);
}
TEST(SequencerTest, BEH_Chunk2WriteRead) {
  Sequencer seq;
  ByteVector vec{'a', 'b', '2'};
  seq.Add(vec, 0 + kMaxChunkSize);
  ByteVector result(seq.Read(3, 0 + kMaxChunkSize));
  EXPECT_TRUE(vec.size() == 3);
  EXPECT_TRUE(result.size() == 3);
  EXPECT_EQ(vec, result);
  // Try reading at an offset.
  ByteVector result2(seq.Read(2, 1 + kMaxChunkSize));
  EXPECT_EQ(result2.size(), 2);
  EXPECT_EQ(vec[1], result2[0]);
  // Try reading past end.
  ByteVector result3(seq.Read(3, 2 + kMaxChunkSize));
  EXPECT_EQ(result3.size(), 1);
  EXPECT_EQ(vec[2], result3[0]);
  // Try reading past end.
  ByteVector result4(seq.Read(3, 4 + kMaxChunkSize));
  EXPECT_EQ(result4.size(), 0);
}

TEST(SequencerTest, BEH_Chunk2WriteReadOffset) {
  Sequencer seq;
  ByteVector vec{'a', 'b', '2'};
  seq.Add(vec, 100 + kMaxChunkSize);
  ByteVector result(seq.Read(3, 100 + kMaxChunkSize));
  EXPECT_TRUE(vec.size() == 3);
  EXPECT_TRUE(result.size() == 3);
  EXPECT_EQ(vec, result);
  // Try reading at an offset.
  ByteVector result2(seq.Read(2, 101 + kMaxChunkSize));
  EXPECT_EQ(result2.size(), 2);
  EXPECT_EQ(vec[1], result2[0]);
  // Try reading past end.
  ByteVector result3(seq.Read(3, 102 + kMaxChunkSize));
  EXPECT_EQ(result3.size(), 1);
  EXPECT_EQ(vec[2], result3[0]);
  // Try reading past end.
  ByteVector result4(seq.Read(3, 104 + kMaxChunkSize));
  EXPECT_EQ(result4.size(), 0);
  }

  TEST(SequencerTest, BEH_ReadPastEnd) {
  Sequencer seq;
  ByteVector vec{'a', 'b', '2'};
  seq.Add(vec, 50 + kMaxChunkSize);
  ByteVector result(seq.Read(3, 100 + kMaxChunkSize));
  EXPECT_TRUE(vec.size() == 3);
  EXPECT_TRUE(result.size() == 0);

  }

}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
