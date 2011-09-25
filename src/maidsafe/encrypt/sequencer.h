
/*******************************************************************************
*  Copyright 2011 MaidSafe.net limited                                         *
*                                                                              *
*  The following source code is property of MaidSafe.net limited and is not    *
*  meant for external use.  The use of this code is governed by the license    *
*  file LICENSE.TXT found in the root of this directory and also on            *
*  www.MaidSafe.net.                                                           *
*                                                                              *
*  You are not free to copy, amend or otherwise use this source code without   *
*  the explicit written permission of the board of directors of MaidSafe.net.  *
*******************************************************************************/

#ifndef MAIDSAFE_ENCRYPT_SEQUENCER_H_
#define MAIDSAFE_ENCRYPT_SEQUENCER_H_

#include <cstdint>
#include <limits>
#include <map>

#include "boost/shared_array.hpp"
#include "cryptopp/config.h"

namespace maidsafe {
namespace encrypt {

struct SequenceData;

typedef boost::shared_array<byte> ByteArray;
typedef std::map<uint64_t, SequenceData> SequenceBlockMap;
typedef SequenceBlockMap::value_type SequenceBlock;

struct SequenceData {
  explicit SequenceData(const uint32_t &sz) : data(new byte[sz]), size(sz) {}
  SequenceData() : data(), size(0) {}
  ByteArray data;
  uint32_t size;
};

class Sequencer {
 public:
  Sequencer() : blocks_(), end_position_(0) {}
  // Adds a new block to the map.  If this overlaps or joins any existing ones,
  // the new block is set to cover the total span of all the overlapping blocks
  // and the old ones are removed.
  int Add(const char *data, const uint32_t &length, const uint64_t &position);
  // Returns and removes the block of sequenced data at position in the map.  If
  // no block exists at position, it returns a default (invalid) SequenceData.
  SequenceData Get(const uint64_t &position);
  // Returns and removes the first block of sequenced data in the map.  If the
  // map is empty, it returns kInvalidSeqBlock.
  SequenceBlock GetFirst();
  // Returns without removing the first block of sequenced data in the map which
  // compares >= position.  If this is the map end, it returns kInvalidSeqBlock.
  SequenceBlock Peek(const uint64_t &position) const;
  void clear() { blocks_.clear(); }
 private:
  Sequencer &operator=(const Sequencer&);
  Sequencer(const Sequencer&);
  SequenceBlockMap blocks_;
  uint64_t end_position_;
};

}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SEQUENCER_H_
