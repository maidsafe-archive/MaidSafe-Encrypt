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
 *  Created on: Jul 18, 2008
 *      Author: haiyang
 */

#ifndef TRANSPORT_TIME_H_
#define TRANSPORT_TIME_H_

#include <ace/Timer_Queue_Adapters.h>
#include <ace/Timer_Heap.h>
#include <ace/Singleton.h>

namespace dht{

typedef ACE_Thread_Timer_Queue_Adapter<ACE_Timer_Heap> ActiveTimer;
typedef ACE_Singleton<ActiveTimer, ACE_Null_Mutex> Timer;

}// namespace dht
#endif /* TRANSPORT_TIME_H_ */
