/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Threadpool class
* Version:      1.0
* Created:      2009-08-06-02.55.09
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

#ifndef MAIDSAFE_THREADPOOL_H_
#define MAIDSAFE_THREADPOOL_H_

#include <boost/shared_ptr.hpp>
#include <boost/thread/thread.hpp>
#include <boost/thread/mutex.hpp>

#include <map>

namespace maidsafe {

typedef std::map< boost::thread::id, boost::shared_ptr<boost::thread> >
    ThreadMap;
typedef std::pair< boost::thread::id, boost::shared_ptr<boost::thread> >
    ThreadPair;

class ThreadPool {
 public:
  ThreadPool() : mutex_(), thread_map_() {}
  ~ThreadPool() {}
  void AddThread(boost::shared_ptr<boost::thread> thread_ptr);
  // DeleteThread is best added in the form:-
  // boost::this_thread::at_thread_exit(boost::bind(&ThreadPool::DeleteThread,
  //     &thread_pool, boost::this_thread::get_id()));
  // to the function being threaded where &thread_pool is a pointer to the
  // applicable ThreadPool instance.
  void DeleteThread(boost::thread::id thread_id);
  boost::uint16_t size();
 private:
  ThreadPool &operator=(const ThreadPool&);
  ThreadPool(const ThreadPool&);
  boost::mutex mutex_;
  ThreadMap thread_map_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_THREADPOOL_H_
