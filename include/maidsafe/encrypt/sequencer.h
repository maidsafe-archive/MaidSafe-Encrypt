/* Copyright 2011 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

#ifndef MAIDSAFE_ENCRYPT_SEQUENCER_H_
#define MAIDSAFE_ENCRYPT_SEQUENCER_H_

#include <cstdint>
#include <limits>
#include <map>

#include "maidsafe/encrypt/byte_array.h"

namespace maidsafe {
namespace encrypt {

typedef std::map<uint64_t, ByteArray> SequenceBlockMap;
typedef SequenceBlockMap::value_type SequenceBlock;

class Sequencer {
 public:
  Sequencer() : blocks_() {}
  // Adds a new block to the map.  If this overlaps or joins any existing ones,
  // the new block is set to cover the total span of all the overlapping blocks
  // and the old ones are removed.
  int Add(const char *data, const uint32_t &length, const uint64_t &position);
  // Returns and removes the block of sequenced data at position in the map.  If
  // no block exists at position, it returns a default (NULL) ByteArray.
  ByteArray Get(const uint64_t &position);
  // Returns and removes the first block of sequenced data in the map.  If the
  // map is empty, it returns kInvalidSeqBlock.
  SequenceBlock GetFirst();
  // Returns without removing the first block of sequenced data in the map which
  // compares >= position.  If this is the map end, it returns kInvalidSeqBlock.
  SequenceBlock PeekBeyond(const uint64_t &position) const;
  // Returns without removing the first block of sequenced data in the map which
  // has data contained within area defined by position and length.  If this is
  // the map end, it returns kInvalidSeqBlock.
  SequenceBlock Peek(const uint32_t &length, const uint64_t &position) const;
  // Removes all blocks after position, and reduces any block spanning position
  // to terminate at position.
  void Truncate(const uint64_t &position);
  void clear() { blocks_.clear(); }

 private:
  Sequencer &operator=(const Sequencer&);
  Sequencer(const Sequencer&);
  SequenceBlockMap blocks_;
};

}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SEQUENCER_H_
