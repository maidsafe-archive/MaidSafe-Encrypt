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
  int Add(const char* data, uint32_t length, uint64_t position);
  // Returns and removes the block of sequenced data at position in the map.  If
  // no block exists at position, it returns a default (NULL) ByteArray.
  ByteArray Get(uint64_t position);
  // Returns and removes the first block of sequenced data in the map.  If the
  // map is empty, it returns kInvalidSeqBlock.
  SequenceBlock GetFirst();
  // Returns without removing the first block of sequenced data in the map which
  // compares >= position.  If this is the map end, it returns kInvalidSeqBlock.
  SequenceBlock PeekBeyond(uint64_t position) const;
  // Returns without removing the first block of sequenced data in the map which
  // has data contained within area defined by position and length.  If this is
  // the map end, it returns kInvalidSeqBlock.
  SequenceBlock Peek(uint32_t length, uint64_t position) const;
  // Removes all blocks after position, and reduces any block spanning position
  // to terminate at position.
  void Truncate(uint64_t position);
  void clear() { blocks_.clear(); }

 private:
  Sequencer& operator=(const Sequencer&);
  Sequencer(const Sequencer&);
  SequenceBlockMap blocks_;
};

}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SEQUENCER_H_
