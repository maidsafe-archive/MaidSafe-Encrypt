/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Class for manipulating database of system packets
* Version:      1.0
* Created:      14/10/2010 11:43:59
* Revision:     none
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

#ifndef MAIDSAFE_PASSPORT_SYSTEMPACKETHANDLER_H_
#define MAIDSAFE_PASSPORT_SYSTEMPACKETHANDLER_H_

#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>

#include <map>
#include <string>

#include "maidsafe/passport/systempackets.h"

namespace maidsafe {

namespace passport {

class SystemPacketHandler {
 public:
  typedef std::map<PacketType, boost::shared_ptr<pki::Packet> > SystemPacketMap;
  SystemPacketHandler() : packets_(), mutex_() {}
  ~SystemPacketHandler() {}
  bool AddPacket(boost::shared_ptr<pki::Packet> packet, bool force);
  boost::shared_ptr<pki::Packet> Packet(const PacketType &packet_type);





  // If signed_public_key == "", it is set as signature of given public_key
  // using given private_key.
  int AddKey(const int &packet_type,
             const std::string &packet_id,
             const std::string &private_key,
             const std::string &public_key,
             const std::string &signed_public_key);
  std::string PackageID(const int &packet_type);
  std::string PrivateKey(const int &packet_type);
  std::string PublicKey(const int &packet_type);
  std::string SignedPublicKey(const int &packet_type);
  int RemoveKey(const int &packet_type);
//  void GetKeyRing(std::list<KeyAtlasRow> *keyring);
  size_t KeyRingSize();
  void ClearKeyRing();
 private:
  SystemPacketHandler &operator=(const SystemPacketHandler&);
  SystemPacketHandler(const SystemPacketHandler&);
  SystemPacketMap packets_;
  boost::mutex mutex_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_SYSTEMPACKETHANDLER_H_

