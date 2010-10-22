/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  A mock KadOps object, and related helper methods
* Created:      2010-02-11
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

#ifndef TESTS_MAIDSAFE_MOCKKADOPS_H_
#define TESTS_MAIDSAFE_MOCKKADOPS_H_

#include <gmock/gmock.h>
#include <maidsafe/maidsafe-dht_config.h>

#include <vector>
#include <string>

#include "maidsafe/maidsafe.h"
#include "maidsafe/kadops.h"
#include "tests/maidsafe/threadpool.h"

namespace mock_kadops {

enum FindNodesResponseType {
  kFailParse,
  kResultFail,
  kTooFewContacts,
  kGood
};

std::string MakeFindNodesResponse(const FindNodesResponseType &type,
                                  const boost::uint8_t k,
                                  std::vector<std::string> *pmids);

}  // namespace mock_kadops

namespace maidsafe {

class MockKadOps : public KadOps {
 public:
  MockKadOps(transport::TransportHandler *transport_handler,
             rpcprotocol::ChannelManager *channel_manager,
             kad::NodeType type,
             const std::string &private_key,
             const std::string &public_key,
             bool port_forwarded,
             bool use_upnp,
             boost::uint8_t k,
             boost::shared_ptr<ChunkStore> chunkstore)
      : KadOps(transport_handler, channel_manager, type, private_key,
               public_key, port_forwarded, use_upnp, k, chunkstore),
        tp_(1) {}
  MOCK_METHOD1(AddressIsLocal, bool(const kad::Contact &peer));
  MOCK_METHOD1(AddressIsLocal, bool(const kad::ContactInfo &peer));
  MOCK_METHOD3(FindValue, void(const std::string &key,
                               bool check_local,
                               kad::VoidFunctorOneString callback));
  MOCK_METHOD2(FindKClosestNodes, void(const std::string &key,
                                       VoidFuncIntContacts callback));
  MOCK_METHOD4(GetStorePeer, int(const double &ideal_rtt,
                                 const std::vector<kad::Contact> &exclude,
                                 kad::Contact *new_peer,
                                 bool *local));
//   void RealFindKClosestNodesCallback(const std::string &response,
//                                      VoidFuncIntContacts callback) {
//     KadOps::FindKClosestNodesCallback(response, callback);
//   }
  void ThreadedFindKClosestNodesCallback(const std::string &response,
                                         VoidFuncIntContacts callback) {
    tp_.EnqueueTask(boost::bind(&KadOps::FindKClosestNodesCallback, this,
                                response, callback));
  }
  bool Wait() {
    return tp_.WaitForTasksToFinish(boost::posix_time::milliseconds(3000));
  }
 private:
  base::Threadpool tp_;
};

}  // namespace maidsafe

#endif  // TESTS_MAIDSAFE_MOCKKADOPS_H_
