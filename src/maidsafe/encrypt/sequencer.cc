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

 
 namespace maidsafe {
 namespace encrypt {
 
 bool Sequencer::Add(size_t position, char* data, size_t length) {
   // TODO (dirvine) if a write happens half way through we count as 2 sets,
   // need to take
   // care of this in the getFromSequencer method.
   // ah no needs to be here, otherwise we lose timeline
   
   for (auto it = sequencer_.begin(); it != sequencer_.end(); ++it) {
     auto iter = sequencer_.find(position);
     if (iter == sequencer_.end()) {
       sequencer_.insert(std::pair<size_t, sequence_data>(position, sequence_data(data, length)));
     } else {
       (*iter).second.first = data;
       (*iter).second.second = length;
     }
   }
   return true;
 }
 
 sequence_data Sequencer::getFromSequencer(size_t position, bool remove) {
   if (sequencer_.size() == 0)
     return (sequence_data(0, NULL));
   for (auto it = sequencer_.begin(); it != sequencer_.end(); ++it) {
     size_t this_position = (*it).first;
     char * this_data = (*it).second.first;
     size_t this_length = (*it).second.second;
     // got the data - it is contiguous
     if ((*it).first == position) {
       sequence_data result = sequence_data((*it).second.first,
                                            (*it).second.second);
       if (remove)
         sequencer_.erase(it);
       return result;
     }
     // get some data that's inside a chunk of sequenced data
     if ((*it).first + (*it).second.second  >= position) {
       // get address of element and length
       sequence_data result =
           sequence_data (&(*it).second.first[position - (*it).first],
                          (*it).second.second - (position - (*it).first));

       if (remove) {
       // get the remaining data add again with Add
       Add((*it).first, (*it).second.first, position - (*it).first);
       sequencer_.erase(it); // remove this element
       }
       return result;
     }
   }
   return (sequence_data(0, NULL)); // nothing found
 }

bool Sequencer::FillinRange(size_t from, size_t to, char* data, size_t length)
{
  if (to - from != length)
    return false;
  for (auto it = sequencer_.begin(); it != sequencer_.end(); ++it) {
    size_t this_position = (*it).first;
    char * this_data = (*it).second.first;
    size_t this_length = (*it).second.second;
    
    if (from < (*it).first > to) {
      (for size_t j = this_position; j < length; ++j) {
        data[j] = this_data[j];
      }
      if(this_position + this_length > to - from) {
        Add(this_position + from,
            &this_data[from - this_position],
            this_length - (this_position + from));
      }
    }
  }
  
}



}  // namespace encrypt
}  // namespace maidsafe