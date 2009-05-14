/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in teh root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Jul 25, 2008
 *      Author: haiyang
 */

#ifndef BASE_DEFERRED_H_
#define BASE_DEFERRED_H_

/*
 * Defer class is designed to contain and manipulate the callback functions.
 */
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include "entry.h"
#include "time.h"

namespace dht{
typedef void (*pt2Function)(void* pt2Object, entry &result);
typedef boost::function<void(dht::entry&)> function_type;

struct callbackFunc{
  void *pt2Obj;
  pt2Function pt2Func;
};

class Deferred{
public:
  Deferred();
  ~Deferred();
  void AddCallback(callbackFunc &cbFunc);
  void Callback(entry &result);
private:
  callbackFunc callback_;
  entry result_;
  bool is_callbacked_;
  bool is_result_set_;
};
}// namespace dht

#endif /* BASE_DEFERRED_H_ */
