
/*******************************************************************************
 *  Copyright 2009-2011 maidsafe.net limited                                   *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  sequencer.h
 * @brief random access buffer.
 * @date  2011-08-14
 */

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

  SequenceData Peek(uint64_t position) {
    return PositionFromSequencer(position, false);
  }
  SequenceData Get(uint64_t position) {
    return PositionFromSequencer(position, true);
  }

  bool empty() const { return sequencer_.empty(); }

  void Clear();

  std::pair<uint64_t, SequenceData> GetFirst();

  // Returns position of end of last piece of sequence data
  uint64_t GetEndPosition();

 private:
  SequenceData PositionFromSequencer(uint64_t position, bool remove);
  uint64_t NextFromSequencer(char *data, uint32_t *length, bool remove);
  std::map<uint64_t, SequenceData> sequencer_;
};

}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SEQUENCER_H_
