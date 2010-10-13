/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Classes of system packets
* Version:      1.0
* Created:      2009-01-29-00.59.58
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

#ifndef MAIDSAFE_PASSPORT_SYSTEMPACKETS_H_
#define MAIDSAFE_PASSPORT_SYSTEMPACKETS_H_

//#include <boost/cstdint.hpp>
//
//#include <string>
//#include <vector>
//
//#include "maidsafe/common/packet.pb.h"
#include "maidsafe/pki/packet.h"

namespace maidsafe {

namespace passport {

const boost::uint16_t kRsaKeySize = 4096;  // size to generate RSA keys in bits.
const boost::uint16_t kNoOfSystemPackets = 8;

class SignaturePacket : public pki::Packet {
 public:
  SignaturePacket(const std::string &public_key,
                  const std::string &private_key,
                  const std::string &signer_private_key);
  virtual ~SignaturePacket() {}
  virtual std::string value() const { return public_key_; }
  std::string signature() const { return signature_; }
 private:
  SignaturePacket &operator=(const SignaturePacket&);
  SignaturePacket(const SignaturePacket&);
  virtual void Initialise();
  virtual void Clear();
  std::string public_key_, private_key_, signer_private_key_, signature_;
};

class MidPacket : public pki::Packet {
 public:
  MidPacket(const std::string &username,
            const std::string &pin,
            const std::string &smid_appendix);
  virtual ~MidPacket() {}
  virtual std::string value() const { return encrypted_rid_; }
  boost::uint32_t ParseRid(const std::string &serialised_mid_packet);
 private:
  MidPacket &operator=(const MidPacket&);
  MidPacket(const MidPacket&);
  virtual void Initialise();
  virtual void Clear();
  std::string username_, pin_, smid_appendix_, encrypted_rid_, salt_;
  std::string secure_password_;
  boost::uint32_t rid_;
};

class TmidPacket : public pki::Packet {
 public:
  TmidPacket(const std::string &username,
             const std::string &pin,
             const std::string &password,
             const boost::uint32_t rid,
             const std::string &plain_data);
  virtual ~TmidPacket() {}
  virtual std::string value() const { return encrypted_data_; }
  std::string ParsePlainData(const std::string &serialised_tmid_packet);
 private:
  TmidPacket &operator=(const TmidPacket&);
  TmidPacket(const TmidPacket&);
  virtual void Initialise();
  virtual void Clear();
  std::string username_, pin_, password_;
  boost::uint32_t rid_;
  std::string plain_data_, salt_, secure_password_, encrypted_data_;
};

class MpidPacket : public pki::Packet {
 public:
  MpidPacket(const std::string &public_name,
             const std::string &public_key,
             const std::string &private_key);
  virtual ~MpidPacket() {}
  virtual std::string value() const { return public_key_; }
  std::string ParsePublicKey(const std::string &serialised_mpid_packet);
 private:
  MpidPacket &operator=(const MpidPacket&);
  MpidPacket(const MpidPacket&);
  virtual void Initialise();
  virtual void Clear();
  std::string public_name_, public_key_, private_key_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_SYSTEMPACKETS_H_

