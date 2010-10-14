/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Base class for PKI packets
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

#ifndef MAIDSAFE_PKI_PACKET_H_
#define MAIDSAFE_PKI_PACKET_H_

#include <maidsafe/base/crypto.h>
#include <map>
#include <string>

#include "maidsafe/common/packet.pb.h"

namespace maidsafe {

namespace pki {

class Packet {
 public:
  explicit Packet(const int &packet_type)
      : packet_type_(packet_type), name_(), crypto_obj_() {
    crypto_obj_.set_hash_algorithm(crypto::SHA_512);
    crypto_obj_.set_symm_algorithm(crypto::AES_256);
  }
  virtual ~Packet() {}
  int packet_type() const { return packet_type_; }
  std::string name() const { return name_; }
  virtual std::string value() const = 0;
 protected:
  virtual void Initialise() = 0;
  virtual void Clear() = 0;
  int packet_type_;
  std::string name_;
  crypto::Crypto crypto_obj_;
};

}  // namespace pki

}  // namespace maidsafe

#endif  // MAIDSAFE_PKI_PACKET_H_
