
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
#include "maidsafe/encrypt/log.h"

namespace maidsafe {
namespace encrypt {

bool Sequencer::Add(uint64_t position, char *data, uint32_t length) {
  // TODO(dirvine) if a write happens half way through we count as 2 sets,
  // need to take care of this here, otherwise we lose timeline
  auto iter = sequencer_.find(position);
  if (iter == sequencer_.end()) {
    try {
      auto it = sequencer_.end();
      sequencer_.insert(it,
                        std::make_pair(position, SequenceData(data, length)));
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
  } else {
    (*iter).second.first = data;
    (*iter).second.second = length;
  }
  return true;
}

uint64_t Sequencer::PeekLast(uint32_t *length) {
  auto it = sequencer_.end();
  *length = (*it).second.second;
  return (*it).first;
}

SequenceData Sequencer::PositionFromSequencer(uint64_t position, bool remove) {
  if (sequencer_.empty())
    return (SequenceData(static_cast<char*>(NULL), 0));
  for (auto it = sequencer_.begin(); it != sequencer_.end(); ++it) {
    uint64_t this_position = (*it).first;
    char *this_data = (*it).second.first;
    uint32_t this_length = (*it).second.second;
    // got the data - it is contiguous
    if (this_position == position) {
      SequenceData result(this_data, this_length);
      if (remove)
        sequencer_.erase(it);
      return result;
    }
    // get some data that's inside a chunk of sequenced data
    if (this_position + this_length >= position) {
      // get address of element and length
      SequenceData result(&this_data[position - this_position],
          this_length - static_cast<uint32_t>(position - this_position));
      if (remove) {
        // get the remaining data and re-add
        Add(this_position,
            &this_data[position - this_position],
            this_length - static_cast<uint32_t>(position - this_position));
        sequencer_.erase(it);
      }
      return result;
    }
  }
  return (SequenceData(static_cast<char*>(NULL), 0));  // nothing found
}

uint64_t Sequencer::NextFromSequencer(char *data,
                                      uint32_t *length,
                                      bool remove) {
  if (sequencer_.empty())
    return 0;
  auto it = sequencer_.begin();
  uint64_t position = (*it).first;
  data = (*it).second.first;
  *length = (*it).second.second;

  if (remove)
    sequencer_.erase(it);
  return position;
}

}  // namespace encrypt
}  // namespace maidsafe
