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
#include "deferred.h"

namespace dht{
Deferred::Deferred(){
  callback_.pt2Func = NULL;
  is_result_set_ = false;
  is_callbacked_ = false;
}

Deferred::~Deferred(){
}

void Deferred::AddCallback(callbackFunc &cbFunc){
  callback_.pt2Obj = cbFunc.pt2Obj;
  callback_.pt2Func = cbFunc.pt2Func;
  if (is_result_set_)
    Callback(result_);
}

void Deferred::Callback(entry &result){
  if ((callback_.pt2Func != NULL)&&(!is_callbacked_)){// can only callback once
    // callback_.pt2Func(callback_.pt2Obj, result);
    function_type f = boost::bind(callback_.pt2Func, callback_.pt2Obj, result);
    f(result);
    is_callbacked_ = true;
  }
  else{
    is_result_set_ = true;
    result_ = result;
  }
}

}// namespace dht
