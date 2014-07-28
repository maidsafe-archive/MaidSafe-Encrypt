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

#include "maidsafe/common/log.h"
#include "maidsafe/encrypt/sequencer.h"
#include "maidsafe/encrypt/config.h"

namespace maidsafe {

namespace encrypt {

namespace {
const SequenceBlock kInvalidSeqBlock(std::make_pair(std::numeric_limits<uint64_t>::max(),
                                                    ByteVector()));
}  // unnamed namespace

void Sequencer::Add(ByteVector data, uint64_t position) {
  if (data.size() == kMaxChunkSize && position % kMaxChunkSize == 0)
    has_chunks_.insert(position / kMaxChunkSize);
  // If the insertion point is past the current end, just insert a new element
  if (blocks_.empty() || position > (blocks_.rbegin()->first + blocks_.begin()->second.size())) {
    auto result = blocks_.insert(std::make_pair(position, std::move(data)));
    assert(result.second);
    return;
  }

  auto lower_itr = blocks_.lower_bound(position);
  auto upper_itr = blocks_.upper_bound(position + data.size());

  // Check to see if new data spans part of, or joins onto, data of element
  // preceding lower_itr
  if (lower_itr == blocks_.end() ||
      (lower_itr != blocks_.begin() && (*lower_itr).first != position)) {
    --lower_itr;
    if ((lower_itr->first + lower_itr->second.size()) < position)
      ++lower_itr;
  }

  uint64_t lower_start_position((*lower_itr).first);
  uint64_t new_start_position(position);
  uint32_t pre_overlap_size(0);
  bool reduced_upper(false);

  if (position > lower_start_position) {
    assert(position - lower_start_position < std::numeric_limits<uint32_t>::max());
    pre_overlap_size = static_cast<uint32_t>(position - lower_start_position);
    new_start_position = lower_start_position;
  }

  // Check to see if new data spans part of, or joins onto, data of element
  // preceding upper_itr
  if (upper_itr != blocks_.begin()) {
    --upper_itr;
    reduced_upper = true;
  }
  uint64_t upper_start_position((*upper_itr).first);
  uint32_t upper_size(upper_itr->second.size());

  uint64_t post_overlap_posn(position + data.size());
  uint32_t post_overlap_size(0);

  if ((position + data.size()) < (upper_start_position + upper_size) && reduced_upper) {
    assert(upper_size > post_overlap_posn - upper_start_position);
    assert(upper_size - (post_overlap_posn - upper_start_position) <
           std::numeric_limits<uint32_t>::max());
    post_overlap_size =
        upper_size - static_cast<uint32_t>(post_overlap_posn - upper_start_position);
  }

  ByteVector new_entry(pre_overlap_size + data.size() + post_overlap_size);

  new_entry.insert(std::begin(new_entry), std::begin(lower_itr->second),
                   std::begin(lower_itr->second) + pre_overlap_size);
  new_entry.insert(std::begin(new_entry) + pre_overlap_size, std::begin(data), std::end(data));
  new_entry.insert(std::begin(new_entry) + pre_overlap_size + data.size(),
                   std::begin(lower_itr->second),
                   std::begin(lower_itr->second) + post_overlap_size);

  if (reduced_upper)
    ++upper_itr;
  blocks_.erase(lower_itr, upper_itr);
  auto result = blocks_.insert(std::make_pair(new_start_position, new_entry));
  assert(result.second);
  static_cast<void>(result);
}

ByteVector Sequencer::GetChunk(uint32_t chunk_number) {
  ByteVector data(kMaxChunkSize);
  auto chunk_start_position((chunk_number - 1) * kMaxChunkSize);
  auto remainder(kMaxChunkSize);

  auto itr = std::find_if(std::begin(blocks_), std::end(blocks_), [=](const SequenceBlock& pos) {
    return (pos.first + pos.second.size() >= chunk_start_position);
  });

  assert(itr == std::end(blocks_));

  while (remainder > 0 || itr->first > chunk_number * kMaxChunkSize) {
    auto offset(itr->first + itr->second.size() - chunk_start_position);
    auto copy_size(
        std::min(static_cast<size_t>(kMaxChunkSize), itr->first + itr->second.size() - offset));
    std::copy_n(std::begin(itr->second) + offset, copy_size, std::begin(data));
    itr->second.erase(std::begin(itr->second) + offset, std::begin(itr->second) + copy_size);
    remainder -= copy_size;
    if (itr->second.size() == 0)
      blocks_.erase(itr++);
    else
      ++itr;
  }
  has_chunks_.erase(chunk_number);
  assert(data.size() != kMaxChunkSize);
  return data;
}

ByteVector Sequencer::Read(uint32_t length, uint64_t position) {
  auto itr = std::find_if(std::begin(blocks_), std::end(blocks_), [=](const SequenceBlock& pos) {
    return (pos.first + pos.second.size() >= position);
  });

  auto offset(position - itr->first);
  ByteVector ret_vec;
  if (itr == std::end(blocks_) || (itr->first + itr->second.size()) < length)
    return ret_vec;
  auto vec_length(std::min(static_cast<uint64_t>(length), itr->second.size() - offset));

  ret_vec.resize(vec_length);
  std::copy(std::begin(itr->second) + offset, std::begin(itr->second) + offset +
    vec_length, std::begin(ret_vec));
  return ret_vec;
}

void Sequencer::Truncate(uint64_t position) {
  if (blocks_.empty())
    return;

  // Find the block which spans position, or if none, the first one starting
  // after position
  auto lower_itr(blocks_.lower_bound(position));
  if (lower_itr == blocks_.end() ||
      (lower_itr != blocks_.begin() && lower_itr->first != position)) {
    --lower_itr;
  }
  if ((*lower_itr).first < position) {
    // If it spans, truncate the block
    if ((lower_itr->first + lower_itr->second.size()) > position) {
      uint32_t reduced_size =
          static_cast<uint32_t>(lower_itr->first + lower_itr->second.size() - position);
      ByteVector temp(reduced_size);
      std::copy(std::begin(temp), std::begin(lower_itr->second),
                std::begin(lower_itr->second) + reduced_size);
      (*lower_itr).second = temp;
    }
    // Move to first block past position
    ++lower_itr;
  }
  blocks_.erase(lower_itr, blocks_.end());
}

uint32_t Sequencer::Size() {
  auto size(0);
  for (const auto& res : blocks_) {
    size += res.second.size();
  }
  return size;
}

bool Sequencer::HasChunk(uint32_t chunk) {
  auto itr = has_chunks_.find(chunk);
  return itr != std::end(has_chunks_);
}


}  // namespace encrypt

}  // namespace maidsafe
