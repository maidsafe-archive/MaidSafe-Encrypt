/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Setters and getters for system packets
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

#ifndef MAIDSAFE_PASSPORT_SYSTEMPACKETS_H_
#define MAIDSAFE_PASSPORT_SYSTEMPACKETS_H_

#include <boost/cstdint.hpp>
#include <string>
#include "maidsafe/pki/packet.h"

namespace maidsafe {

namespace passport {

class Key;

enum PacketType {
  UNKNOWN = -1,
  MID,
  SMID,
  TMID,
  STMID,
  MPID,
  PMID,
  MAID,
  ANMID,
  ANSMID,
  ANTMID,
  ANMPID,
  ANMAID,
  MSID,
  PD_DIR
};

std::string DebugString(const int &packet_type);

bool IsSignature(const int &packet_type, bool check_for_self_signer);

class SignaturePacket : public pki::Packet {
 public:
  SignaturePacket(const PacketType &packet_type,
                  const std::string &public_key,
                  const std::string &private_key,
                  const std::string &signer_private_key,
                  const std::string &public_name);
  SignaturePacket(const Key &key);
  virtual ~SignaturePacket() {}
  virtual std::string value() const { return public_key_; }
  std::string ParsePublicKey(const std::string &serialised_sig_packet);
  void PutToKey(Key *key);
  std::string private_key() const { return private_key_; }
  std::string public_key_signature() const { return public_key_signature_; }
 private:
  virtual void Initialise();
  virtual void Clear();
  std::string public_key_, private_key_, signer_private_key_;
  std::string public_key_signature_;
};

class MidPacket : public pki::Packet {
 public:
  MidPacket(const std::string &username,
            const std::string &pin,
            const std::string &smid_appendix);
  virtual ~MidPacket() {}
  virtual std::string value() const { return encrypted_rid_; }
  void SetRid(const boost::uint32_t rid);
  boost::uint32_t ParseRid(const std::string &serialised_mid_packet);
  std::string username() const { return username_; }
  std::string pin() const { return pin_; }
  boost::uint32_t rid() const { return rid_; }
 private:
  virtual void Initialise();
  virtual void Clear();
  std::string username_, pin_, smid_appendix_;
  boost::uint32_t rid_;
  std::string encrypted_rid_, salt_, secure_password_;
};

class TmidPacket : public pki::Packet {
 public:
  TmidPacket(const std::string &username,
             const std::string &pin,
             const std::string &password,
             const boost::uint32_t rid,
             const std::string &plain_data,
             bool surrogate);
  virtual ~TmidPacket() {}
  virtual std::string value() const { return encrypted_data_; }
  std::string ParsePlainData(const std::string &serialised_tmid_packet);
  void SetToSurrogate() { packet_type_ = STMID; }
  std::string username() const { return username_; }
  std::string pin() const { return pin_; }
  std::string password() const { return password_; }
 private:
  virtual void Initialise();
  virtual void Clear();
  std::string username_, pin_, password_;
  boost::uint32_t rid_;
  std::string plain_data_, salt_, secure_password_, encrypted_data_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_SYSTEMPACKETS_H_

