/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Factory for system signature packets
* Version:      1.0
* Created:      09/09/2008 12:14:35 PM
* Revision:     none
* Compiler:     gcc
* Author:       David Irvine (di), david.irvine@maidsafe.net
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

#include "maidsafe/pki/packet.h"

namespace maidsafe {

namespace pki {

Packet::Packet(): crypto_obj_() {
  crypto_obj_.set_hash_algorithm(crypto::SHA_512);
  crypto_obj_.set_symm_algorithm(crypto::AES_256);
}

bool Packet::ValidateSignature(const GenericPacket &packet,
                               const std::string &public_key) {
  return crypto_obj_.AsymCheckSig(packet.data(), packet.signature(), public_key,
                                  crypto::STRING_STRING);
}

}  // namespace pki

}  // namespace maidsafe
