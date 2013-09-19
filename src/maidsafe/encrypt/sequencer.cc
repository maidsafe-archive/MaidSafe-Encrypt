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

#include "boost/assert.hpp"
#include "maidsafe/common/log.h"
#include "maidsafe/encrypt/sequencer.h"
#include "maidsafe/encrypt/config.h"

namespace maidsafe {
namespace encrypt {

namespace {
const SequenceBlock kInvalidSeqBlock(std::make_pair(
    std::numeric_limits<uint64_t>::max(), ByteArray()));
}  // unnamed namespace

int Sequencer::Add(const char *data,
                   const uint32_t &length,
                   const uint64_t &position) {
  try {
    // If the insertion point is past the current end, just insert a new element
    if (blocks_.empty() || position >
        (*blocks_.rbegin()).first + Size((*blocks_.rbegin()).second)) {
      auto result = blocks_.insert(std::make_pair(position,
                                                  GetNewByteArray(length)));
      BOOST_ASSERT(result.second);
      if (MemCopy((*(result.first)).second, 0, data, length) != length) {
        LOG(kError) << "Error adding " << length << " bytes to sequencer at "
                    << position;
        return kSequencerAddError;
      }
      return kSuccess;
    }

    auto lower_itr = blocks_.lower_bound(position);
    auto upper_itr = blocks_.upper_bound(position + length);

    // Check to see if new data spans part of, or joins onto, data of element
    // preceding lower_itr
    if (lower_itr == blocks_.end() ||
        (lower_itr != blocks_.begin() && (*lower_itr).first != position)) {
      --lower_itr;
      if ((*lower_itr).first + Size((*lower_itr).second) < position)
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

    // Check to see if new data spans part of, or joins onto, data of element
    // preceding upper_itr
    if (upper_itr != blocks_.begin()) {
      --upper_itr;
      reduced_upper = true;
    }
    const uint64_t &upper_start_position((*upper_itr).first);
    uint32_t upper_size(Size((*upper_itr).second));

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

    ByteArray new_entry =
        GetNewByteArray(pre_overlap_size + length + post_overlap_size);

    if (MemCopy(new_entry, 0, (*lower_itr).second.get(), pre_overlap_size) !=
        pre_overlap_size) {
      LOG(kError) << "Error adding pre-overlap";
      return kSequencerAddError;
    }

    if (MemCopy(new_entry, pre_overlap_size, data, length) != length) {
      LOG(kError) << "Error adding mid-overlap";
      return kSequencerAddError;
    }

    if (MemCopy(new_entry,
                pre_overlap_size + length,
                (*upper_itr).second.get() +
                    (post_overlap_posn - upper_start_position),
                post_overlap_size) != post_overlap_size) {
      LOG(kError) << "Error adding post-overlap";
      return kSequencerAddError;
    }

    if (reduced_upper)
      ++upper_itr;
    blocks_.erase(lower_itr, upper_itr);
    auto result = blocks_.insert(std::make_pair(new_start_position, new_entry));
    BOOST_ASSERT(result.second);
    static_cast<void>(result);
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
    LOG(kError) << e.what();
    return kSequencerException;
  }
  return kSuccess;
}

ByteArray Sequencer::Get(const uint64_t &position) {
  auto itr(blocks_.find(position));
  if (itr == blocks_.end())
    return ByteArray();
  ByteArray result((*itr).second);
  blocks_.erase(itr);
  return result;
}

SequenceBlock Sequencer::GetFirst() {
  if (blocks_.empty())
    return kInvalidSeqBlock;
  auto result(*blocks_.begin());
  blocks_.erase(blocks_.begin());
  return result;
}

SequenceBlock Sequencer::PeekBeyond(const uint64_t &position) const {
  auto itr(blocks_.lower_bound(position));
  return itr == blocks_.end() ? kInvalidSeqBlock : *itr;
}

SequenceBlock Sequencer::Peek(const uint32_t &length,
                              const uint64_t &position) const {
  if (blocks_.empty())
    return kInvalidSeqBlock;

  auto itr(blocks_.lower_bound(position));
  if (itr != blocks_.end() && (*itr).first == position)
    return *itr;

  if (itr == blocks_.end() || itr != blocks_.begin())
    --itr;

  if ((*itr).first < position) {
    if ((*itr).first + Size((*itr).second) > position)
      return *itr;
    else
      ++itr;
  }

  if (itr == blocks_.end())
    return kInvalidSeqBlock;

  return ((*itr).first < length + position) ? *itr : kInvalidSeqBlock;
}

void Sequencer::Truncate(const uint64_t &position) {
  if (blocks_.empty())
    return;

  // Find the block which spans position, or if none, the first one starting
  // after position
  auto lower_itr(blocks_.lower_bound(position));
  if (lower_itr == blocks_.end() ||
      (lower_itr != blocks_.begin() && (*lower_itr).first != position)) {
    --lower_itr;
  }
  if ((*lower_itr).first < position) {
    // If it spans, truncate the block
    if ((*lower_itr).first + Size((*lower_itr).second) > position) {
      uint32_t reduced_size = static_cast<uint32_t>((*lower_itr).first +
                              Size((*lower_itr).second) - position);
      ByteArray temp(GetNewByteArray(reduced_size));
#ifndef NDEBUG
      uint32_t copied =
#endif
          MemCopy(temp, 0, (*lower_itr).second.get(), reduced_size);
      BOOST_ASSERT(reduced_size == copied);
      (*lower_itr).second = temp;
    }
    // Move to first block past position
    ++lower_itr;
  }

  blocks_.erase(lower_itr, blocks_.end());
}

}  // namespace encrypt
}  // namespace maidsafe
