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
#include <vector>
#include <limits>
#include <map>
#include "maidsafe/common/config.h"
#include "maidsafe/encrypt/config.h"
namespace maidsafe {

namespace encrypt {
using byte = unsigned char;
typedef std::map<uint64_t, ByteVector> SequenceBlockMap;
typedef SequenceBlockMap::value_type SequenceBlock;

// This object treats all chunks as of size kMaxChunkSize

class Sequencer {
 public:
  Sequencer() : blocks_() {}
  Sequencer& operator=(const Sequencer&) = delete;
  Sequencer(const Sequencer&) = delete;
  Sequencer(Sequencer&&) = delete;
  ~Sequencer() = default;
  // Adds a new block to the map.  If this overlaps or joins any existing ones,
  // the new block is set to cover the total span of all the overlapping blocks
  // and the old ones are removed.
  void Add(ByteVector data, uint64_t position);
  // returns and removes chunk
  ByteVector GetChunk(uint32_t chunk_number);
  // Returns copy of data
  // no data exists at position, it returns an empty ByteVector.
  ByteVector Read(uint32_t length, uint64_t position);
  // Removes all blocks after position, and reduces any block spanning position
  // to terminate at position.
  void Truncate(uint64_t position);
  uint32_t Size();
  std::set<uint32_t> Chunks() { return has_chunks_; }
  bool HasChunk(uint32_t chunk);

 private:
  SequenceBlockMap blocks_;
  std::set<uint32_t> has_chunks_;
};

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SEQUENCER_H_
