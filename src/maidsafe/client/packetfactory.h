/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Factory for system signature packets
* Version:      1.0
* Created:      2009-01-29-00.23.23
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

#ifndef MAIDSAFE_CLIENT_PACKETFACTORY_H_
#define MAIDSAFE_CLIENT_PACKETFACTORY_H_

#include <boost/any.hpp>
#include <list>
#include <string>
#include <map>

#include "maidsafe/crypto.h"
#include "maidsafe/rsakeypair.h"

namespace packethandler {

const int kRsaKeySize = 4096;  // size to generate RSA keys in bits.

typedef std::map<std::string, boost::any> PacketParams;

enum SystemPackets {
  MID,
  SMID,
  TMID,
  MPID,
  PMID,
  MAID,
  ANMID,
  ANSMID,
  ANTMID,
  ANMPID,
  ANPMID,
  MSID
};

class Packet {
 public:
  Packet();
  virtual PacketParams Create(PacketParams params) = 0;
  bool ValidateSignature(const std::string &serialised_packet,
                         const std::string &public_key);
  PacketParams GetData(std::string serialised_packet);
  virtual ~Packet()=0;
// protected:
  crypto::Crypto crypto_obj_;
};

class PacketFactory {
 public:
  static Packet *Factory(SystemPackets type);
};

}  // namespace packethandler

#endif  // MAIDSAFE_CLIENT_PACKETFACTORY_H_
