/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Threadpool class
* Version:      1.0
* Created:      2009-08-06-02.58.27
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include "maidsafe/threadpool.h"

namespace maidsafe {

void ThreadPool::AddThread(boost::shared_ptr<boost::thread> thread_ptr) {
  boost::thread::id thread_id = thread_ptr->get_id();
#ifdef DEBUG
//  printf("Adding thread.\n");
#endif
  boost::mutex::scoped_lock lock(mutex_);
  thread_map_.insert(ThreadPair(thread_id, thread_ptr));
}

void ThreadPool::DeleteThread(boost::thread::id thread_id) {
#ifdef DEBUG
//  printf("Deleting thread.\n");
#endif
  boost::mutex::scoped_lock lock(mutex_);
  ThreadMap::iterator itr = thread_map_.find(thread_id);
  if (itr != thread_map_.end()) {
    (*itr).second.reset();
    thread_map_.erase(itr);
  }
}

boost::uint16_t ThreadPool::size() {
  boost::mutex::scoped_lock lock(mutex_);
  return thread_map_.size();
}

}  // namespace maidsafe
