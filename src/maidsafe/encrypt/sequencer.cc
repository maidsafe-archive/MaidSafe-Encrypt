
/*******************************************************************************
 *  Copyright 2008-2011 maidsafe.net limited                                   *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  sequencer.cc
 * @brief random access buffer.
 * @date  2011-08-14
 */

#include "maidsafe/encrypt/sequencer.h"
#include <limits>
#include "maidsafe/encrypt/log.h"

namespace maidsafe {
namespace encrypt {

bool Sequencer::Add(const char *data,
                    const uint32_t &length,
                    const uint64_t &position) {
  auto lower_itr = sequencer_.lower_bound(position);
  auto upper_itr = sequencer_.upper_bound(position + length);
  try {
    // If the insertion point is past the current end, just insert a new element
    if (lower_itr == sequencer_.end()) {
      auto result = sequencer_.insert(std::make_pair(position,
          std::make_pair(ByteArray(new byte[length]), length)));
      memcpy((*(result.first)).second.first.get(), data, length);
    } else {
      // Check to see if new data spans part of, or joins onto, data of element
      // preceding lower_itr
      if (lower_itr != sequencer_.begin() && (*lower_itr).first != position) {
        --lower_itr;
        if ((*lower_itr).first + (*lower_itr).second.second + 1 < position)
          ++lower_itr;
      }

      const uint64_t &lower_start_position((*lower_itr).first);
      uint64_t new_start_position(position);
      uint32_t pre_overlap_size(0);
      bool reduced_upper(false);

      if (position > lower_start_position) {
        BOOST_ASSERT(position - lower_start_position <
                     std::numeric_limits<uint32_t>::max());
        pre_overlap_size =
            static_cast<uint32_t>(position - lower_start_position);
        new_start_position = lower_start_position;
      }

      if (upper_itr != sequencer_.begin() &&
          position + length < (*upper_itr).first) {
        --upper_itr;
        reduced_upper = true;
      }
      const uint64_t &upper_start_position((*upper_itr).first);
      const uint32_t &upper_size((*upper_itr).second.second);

      uint64_t post_overlap_posn(0);
      uint32_t post_overlap_size(0);

      if (((position + length) >= upper_start_position) &&
          (position < upper_start_position)) {
        post_overlap_posn = position + length;
        BOOST_ASSERT(upper_size > post_overlap_posn - upper_start_position);
        post_overlap_size = upper_size -
            static_cast<uint32_t>(post_overlap_posn - upper_start_position);
      }
      uint32_t new_length(pre_overlap_size + length + post_overlap_size);

      SequenceData new_entry(std::make_pair(ByteArray(new byte[new_length]),
                                            new_length));

      memcpy(new_entry.first.get(),
             (*lower_itr).second.first.get(),
             pre_overlap_size);
      memcpy(new_entry.first.get(), data, length);
      memcpy(new_entry.first.get(),
             (*upper_itr).second.first.get() +
                 (post_overlap_posn - upper_start_position),
             post_overlap_size);

      if (reduced_upper)
        ++upper_itr;
      sequencer_.erase(lower_itr, upper_itr);
      auto result = sequencer_.insert(std::make_pair(new_start_position,
                                                     new_entry));
    }
  }
  catch(const std::exception &e) {
    // TODO(DI) here we need to catch the error - likely out of mem
    // We should then set up a flilestream in boost::tmp_dir
    // empty sequencer and this write data to the file
    // set a flag to say we have written a fstream.
    // all further writes to fstream
    // on destruct - write all data from fstream
    // to write method, This will encrypt whole file
    // write zero's where there are zero's in the fstream.
    // read form fstream as well as write
    // maybe make protected getter/setter and we can run all tests against the
    // fstream as well
    // else fail ???
    DLOG(ERROR) << e.what();
    return false;
  }
  return true;
}

SequenceData Sequencer::PositionFromSequencer(uint64_t position, bool remove) {
  if (sequencer_.empty())
    return (SequenceData(static_cast<ByteArray>(NULL), 0));
  for (auto it = sequencer_.begin(); it != sequencer_.end(); ++it) {
    uint64_t this_position = (*it).first;
    ByteArray this_data = (*it).second.first;
    uint32_t this_length = (*it).second.second;
    // got the data - it is contiguous
    if (this_position == position) {
      SequenceData result(this_data, this_length);
      if (remove)
        sequencer_.erase(it);
      return result;
    }
    // get some data that's inside a chunk of sequenced data
//     if (this_position + this_length >= position) {
//       // get address of element and length
//       SequenceData result(&this_data[position - this_position],
//           this_length - static_cast<uint32_t>(position - this_position));
//       if (remove) {
//         // get the remaining data and re-add
//         Add(&this_data[position - this_position],
//             this_length - static_cast<uint32_t>(position - this_position),
//             this_position);
//         sequencer_.erase(it);
//       }
//       return result;
//     }
  }
  return (SequenceData(static_cast<ByteArray>(NULL), 0));  // nothing found
}

uint64_t Sequencer::NextFromSequencer(char *data,
                                      uint32_t *length,
                                      bool remove) {
  if (sequencer_.empty())
    return 0;
  auto it = sequencer_.begin();
  uint64_t position = (*it).first;
  data = reinterpret_cast<char*>((*it).second.first[0]);
  *length = (*it).second.second;

  if (remove)
    sequencer_.erase(it);
  return position;
}

void Sequencer::Clear() {
  sequencer_.clear();
}

std::pair<uint64_t, SequenceData> Sequencer::GetFirst() {
  if (sequencer_.empty()) {
    SequenceData invalid(std::make_pair(ByteArray(), 0));
    return std::make_pair(std::numeric_limits<uint64_t>::max(), invalid);
  } else {
    std::pair<uint64_t, SequenceData> result(*sequencer_.begin());
    sequencer_.erase(sequencer_.begin());
    return result;
  }
}

std::pair<uint64_t, SequenceData> Sequencer::Peek(const uint64_t &position) {
  auto itr(sequencer_.lower_bound(position));
  if (itr == sequencer_.end()) {
    SequenceData invalid(std::make_pair(ByteArray(), 0));
    return std::make_pair(std::numeric_limits<uint64_t>::max(), invalid);
  } else {
    return *itr;
  }
}

uint64_t Sequencer::GetEndPosition() {
  if (sequencer_.empty())
    return 0;
  else
    return (*sequencer_.rbegin()).first + (*sequencer_.rbegin()).second.second;
}

}  // namespace encrypt
}  // namespace maidsafe
