
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

#include "maidsafe/encrypt/sequencer.h"
#include <limits>
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/log.h"

namespace maidsafe {
namespace encrypt {

int Sequencer::Add(const char *data,
                   const uint32_t &length,
                   const uint64_t &position) {
  try {
    // If the insertion point is past the current end, just insert a new element
    auto last_block(blocks_.rbegin());
    const uint64_t last_start_position(0);
    const uint32_t last_size(0);
    if (!blocks_.empty()) {
      const uint64_t &last_start_position((*last_block).first);
      const uint32_t &last_size((*last_block).second.second);
    }
    
    if (blocks_.empty() || position > last_start_position + last_size) {
      auto result = blocks_.insert(std::make_pair(position,
          std::make_pair(ByteArray(new byte[length]), length)));
      BOOST_ASSERT(result.second);
      memcpy((*(result.first)).second.first.get(), data, length);
      return kSuccess;
    }

    auto lower_itr = blocks_.lower_bound(position);
    auto upper_itr = blocks_.upper_bound(position + length);
    // Check to see if new data spans part of, or joins onto, data of element
    // preceding lower_itr
    if (lower_itr == blocks_.end() ||
        (lower_itr != blocks_.begin() && (*lower_itr).first != position)) {
      --lower_itr;
      if ((*lower_itr).first + (*lower_itr).second.second < position)
        ++lower_itr;
    }

    const uint64_t &lower_start_position((*lower_itr).first);
    uint64_t new_start_position(position);
    uint32_t pre_overlap_size(0);
    bool reduced_upper(false);

    if (position > lower_start_position) {
      BOOST_ASSERT(position - lower_start_position <
                   std::numeric_limits<uint32_t>::max());
      pre_overlap_size = static_cast<uint32_t>(position - lower_start_position);
      new_start_position = lower_start_position;
    }

    if (upper_itr != blocks_.begin()) {
      --upper_itr;
      reduced_upper = true;
    }
    const uint64_t &upper_start_position((*upper_itr).first);
    const uint32_t &upper_size((*upper_itr).second.second);

    uint64_t post_overlap_posn(position + length);
    uint32_t post_overlap_size(0);

    if ((position + length) < (upper_start_position + upper_size) &&
        reduced_upper) {
      BOOST_ASSERT(upper_size > post_overlap_posn - upper_start_position);
      BOOST_ASSERT(upper_size - (post_overlap_posn - upper_start_position) <
                   std::numeric_limits<uint32_t>::max());
      post_overlap_size = upper_size -
          static_cast<uint32_t>(post_overlap_posn - upper_start_position);
    }
    uint32_t new_length(pre_overlap_size + length + post_overlap_size);

    SequenceData new_entry(std::make_pair(ByteArray(new byte[new_length]),
                                          new_length));

    memcpy(new_entry.first.get(), (*lower_itr).second.first.get(),
           pre_overlap_size);
    memcpy(new_entry.first.get() + pre_overlap_size, data, length);
    memcpy(new_entry.first.get() + pre_overlap_size + length,
           (*upper_itr).second.first.get() +
                (post_overlap_posn - upper_start_position),
           post_overlap_size);

    if (reduced_upper)
      ++upper_itr;
    blocks_.erase(lower_itr, upper_itr);
    auto result = blocks_.insert(std::make_pair(new_start_position,
                                                new_entry));
    BOOST_ASSERT(result.second);
  }
  catch(const std::exception &e) {
    // TODO(DI) here we need to catch the error - likely out of mem.  We
    // should then set up a flilestream in boost::tmp_dir, empty sequencer and
    // this write data to the file and set a flag to say we have written a
    // fstream.  All further writes to fstream.  On destruct - write all data
    // from fstream to SE::write method. This will encrypt whole file.  Write
    // 0s where there are 0s in the fstream.  Read from fstream as well as
    // write, maybe make protected getter/setter and we can run all tests
    // against the fstream as well.  Else fail ???
    DLOG(ERROR) << e.what();
    return kSequencerException;
  }
  return kSuccess;
}

SequenceData Sequencer::Get(const uint64_t &position) {
  auto itr(blocks_.find(position));
  if (itr == blocks_.end())
    return kInvalidSeqData;
  SequenceData result((*itr).second);
  blocks_.erase(itr);
  return result;
}

SequenceBlock Sequencer::GetFirst() {
  if (blocks_.empty())
    return kInvalidSeqBlock;
  std::pair<uint64_t, SequenceData> result(*blocks_.begin());
  blocks_.erase(blocks_.begin());
  return result;
}

SequenceBlock Sequencer::Peek(const uint64_t &position) const {
  auto itr(blocks_.lower_bound(position));
  return itr == blocks_.end() ? kInvalidSeqBlock : *itr;
}

}  // namespace encrypt
}  // namespace maidsafe
