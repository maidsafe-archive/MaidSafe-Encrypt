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
 * @file  sequencer.h
 * @brief random access buffer.
 * @date  2011-08-14
 */

#ifndef MAIDSAFE_ENCRYPT_SEQUENCER_H_
#define MAIDSAFE_ENCRYPT_SEQUENCER_H_
#include <map>
#include "boost/shared_array.hpp"
#include "boost/thread.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/scoped_array.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/log.h"

#include "maidsafe/encrypt/version.h"
#if MAIDSAFE_ENCRYPT_VERSION != 905
# error This API is not compatible with the installed library.\
Please update the library.
#endif


namespace maidsafe {
namespace encrypt {

typedef std::pair<char* , size_t > sequence_data;
  
class Sequencer {
 public:
   bool Add(size_t position, char * data, size_t length);
   sequence_data Peek(size_t position) {
             return  getFromSequencer(position, false);
   }
   sequence_data Get(size_t position) {
     return  getFromSequencer(position, true);
   }
   bool FillinRange(size_t from,
                             size_t to,
                             char * data,
                             size_t length,
                             bool remove);
   
 private:
   std::map <size_t ,sequence_data> sequencer_;
   sequence_data getFromSequencer(size_t position, bool remove);
   
};

}  // namespace encrypt
}  // namespace maidsafe

#endif // MAIDSAFE_ENCRYPT_SEQUENCER_H_
