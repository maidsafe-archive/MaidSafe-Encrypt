
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

#include <stdint.h>
#include <map>

#include "boost/shared_array.hpp"
#include "cryptopp/config.h"
#include "maidsafe/encrypt/version.h"


#if MAIDSAFE_ENCRYPT_VERSION != 906
#  error This API is not compatible with the installed library.\
    Please update the library.
#endif


namespace maidsafe {
namespace encrypt {

typedef boost::shared_array<byte> ByteArray;
typedef std::pair<ByteArray, uint32_t> SequenceData;

class Sequencer {
 public:
  bool Add(const char *data,
           const uint32_t &length,
           const uint64_t &position);
  // Returns and removes the block of sequenced data at position in the map.  If
  // no block exists at position, it returns
  // pair<max uint64_t, invalid SequenceData>
  SequenceData Get(const uint64_t &position);
  // Returns and removes the first block of sequenced data in the map.  If the
  // map is empty, it returns pair<max uint64_t, invalid SequenceData>
  std::pair<uint64_t, SequenceData> GetFirst();
  // Returns without removing the first block of sequenced data in the map which
  // compares >= position.  If this is the map end, it returns
  // pair<max uint64_t, invalid SequenceData>
  std::pair<uint64_t, SequenceData> Peek(const uint64_t &position);
  // Returns position of end of last piece of sequence data
  uint64_t GetEndPosition();
  bool empty() const { return blocks_.empty(); }
  void clear() { blocks_.clear(); }
 private:
  std::map<uint64_t, SequenceData> blocks_;
};

}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SEQUENCER_H_
