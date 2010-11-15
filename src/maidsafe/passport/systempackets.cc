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

#include "maidsafe/passport/systempackets.h"
#include <boost/lexical_cast.hpp>
#include <maidsafe/base/crypto.h>
#include <cstdio>
#include "maidsafe/passport/signaturepacket.pb.h"

namespace maidsafe {

namespace passport {

std::string DebugString(const int &packet_type) {
  switch (packet_type) {
    case UNKNOWN:
      return "unknown";
    case MID:
      return "MID";
    case SMID:
      return "SMID";
    case TMID:
      return "TMID";
    case STMID:
      return "STMID";
    case MPID:
      return "MPID";
    case PMID:
      return "PMID";
    case MAID:
      return "MAID";
    case ANMID:
      return "ANMID";
    case ANSMID:
      return "ANSMID";
    case ANTMID:
      return "ANTMID";
    case ANMPID:
      return "ANMPID";
    case ANMAID:
      return "ANMAID";
    case MSID:
      return "MSID";
    case PD_DIR:
      return "PD_DIR";
    default:
      return "error";
  }
};

bool IsSignature(const int &packet_type, bool check_for_self_signer) {
  switch (packet_type) {
    case MPID:
    case PMID:
    case MAID:
      return !check_for_self_signer;
    case ANMID:
    case ANSMID:
    case ANTMID:
    case ANMPID:
    case ANMAID:
    case MSID:
      return true;
    default:
      return false;
  }
}

SignaturePacket::SignaturePacket()
    : pki::Packet(UNKNOWN),
      public_key_(),
      private_key_(),
      signer_private_key_(),
      public_key_signature_() {}

SignaturePacket::SignaturePacket(const PacketType &packet_type,
                                 const std::string &public_key,
                                 const std::string &private_key,
                                 const std::string &signer_private_key,
                                 const std::string &public_name)
    : pki::Packet(packet_type),
      public_key_(public_key),
      private_key_(private_key),
      signer_private_key_(signer_private_key),
      public_key_signature_() {
  if (packet_type == MPID) {
    try {
      crypto::Crypto crypto_obj;
      name_ = crypto_obj.Hash(public_name, "", crypto::STRING_STRING, false);
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("MpidPacket::Ctor: %s\n", e.what());
#endif
      public_key_.clear();
    }
  }
  Initialise();
}

SignaturePacket::SignaturePacket(const Key &key)
    : pki::Packet(key.packet_type()),
      public_key_(key.public_key()),
      private_key_(key.private_key()),
      signer_private_key_(key.has_signer_private_key() ?
                          key.signer_private_key() : key.private_key()),
      public_key_signature_(key.public_key_signature()) {
  name_ = key.name();
}

void SignaturePacket::Initialise() {
  if (!IsSignature(packet_type_, false)) {
    packet_type_ = UNKNOWN;
    return Clear();
  }
  if (public_key_.empty() || private_key_.empty())
    return Clear();

  if (IsSignature(packet_type_, true)) {  // this is a self-signing packet
    if (signer_private_key_.empty()) {
      signer_private_key_ = private_key_;
    } else if (signer_private_key_ != private_key_) {
      return Clear();
    }
  } else if (signer_private_key_.empty() ||
             (signer_private_key_ == private_key_)) {
    return Clear();
  }

  try {
    crypto::Crypto crypto_obj;
    public_key_signature_ = crypto_obj.AsymSign(public_key_, "",
                            signer_private_key_, crypto::STRING_STRING);
    if (packet_type_ != MPID)
      name_ = crypto_obj.Hash(public_key_ + public_key_signature_, "",
                               crypto::STRING_STRING, false);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("SignaturePacket::Initialise: %s\n", e.what());
#endif
    name_.clear();
  }
  if (name_.empty())
    Clear();
}

void SignaturePacket::Clear() {
  name_.clear();
  public_key_.clear();
  private_key_.clear();
  signer_private_key_.clear();
  public_key_signature_.clear();
}

bool SignaturePacket::Equals(const pki::Packet *other) const {
  const SignaturePacket *rhs = static_cast<const SignaturePacket*>(other);
  return packet_type_ == rhs->packet_type_ &&
         name_ == rhs->name_ &&
         public_key_ == rhs->public_key_ &&
         private_key_ == rhs->private_key_ &&
         signer_private_key_ == rhs->signer_private_key_ &&
         public_key_signature_ == rhs->public_key_signature_;
}

void SignaturePacket::PutToKey(Key *key) {
  key->set_name(name_);
  key->set_packet_type(packet_type_);
  key->set_public_key(public_key_);
  key->set_private_key(private_key_);
  if(signer_private_key_ != private_key_)
    key->set_signer_private_key(signer_private_key_);
  key->set_public_key_signature(public_key_signature_);
}



MidPacket::MidPacket()
    : pki::Packet(UNKNOWN),
      username_(),
      pin_(),
      smid_appendix_(),
      rid_(),
      encrypted_rid_(),
      salt_(),
      secure_password_() {}

MidPacket::MidPacket(const std::string &username,
                     const std::string &pin,
                     const std::string &smid_appendix)
    : pki::Packet(smid_appendix.empty() ? MID : SMID),
      username_(username),
      pin_(pin),
      smid_appendix_(smid_appendix),
      rid_(0),
      encrypted_rid_(),
      salt_(),
      secure_password_() {
  Initialise();
}

void MidPacket::Initialise() {
  if (username_.empty() || pin_.empty())
    return Clear();

  crypto::Crypto crypto_obj;
  salt_ = crypto_obj.Hash(pin_ + username_, "",
                           crypto::STRING_STRING, false);
  try {
    secure_password_ = crypto_obj.SecurePassword(username_, salt_,
                       boost::lexical_cast<boost::uint32_t>(pin_));
    name_ = crypto_obj.Hash(
                crypto_obj.Hash(username_, "", crypto::STRING_STRING, false) +
                crypto_obj.Hash(pin_, "", crypto::STRING_STRING, false) +
                smid_appendix_, "", crypto::STRING_STRING, false);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("MidPacket::Initialise: %s\n", e.what());
#endif
    name_.clear();
  }
  if (name_.empty())
    Clear();
}

void MidPacket::SetRid(const boost::uint32_t &rid) {
  rid_ = rid;
  try {
    if (rid_ == 0) {
      encrypted_rid_.clear();
    } else {
      crypto::Crypto crypto_obj;
      encrypted_rid_ =
          crypto_obj.SymmEncrypt(boost::lexical_cast<std::string>(rid_), "",
                                 crypto::STRING_STRING, secure_password_);
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("MidPacket::SetRid: %s\n", e.what());
#endif
    encrypted_rid_.clear();
  }
  if (encrypted_rid_.empty())
    Clear();
}

boost::uint32_t MidPacket::DecryptRid(const std::string &encrypted_rid) {
  if (username_.empty() || pin_.empty() || encrypted_rid.empty()) {
#ifdef DEBUG
    printf("MidPacket::DecryptRid: Bad encrypted RID or user data empty.\n");
#endif
    Clear();
    return 0;
  }

  try {
    encrypted_rid_ = encrypted_rid;
    crypto::Crypto crypto_obj;
    std::string rid(crypto_obj.SymmDecrypt(encrypted_rid_, "",
                    crypto::STRING_STRING, secure_password_));
    rid_ = boost::lexical_cast<boost::uint32_t>(rid);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("MidPacket::DecryptRid: %s\n", e.what());
#endif
    rid_ = 0;
  }
  if (rid_ == 0)
    Clear();
  return rid_;
}

void MidPacket::Clear() {
  name_.clear();
  username_.clear();
  pin_.clear();
  smid_appendix_.clear();
  encrypted_rid_.clear();
  salt_.clear();
  secure_password_.clear();
  rid_ = 0;
}

bool MidPacket::Equals(const pki::Packet *other) const {
  const MidPacket *rhs = static_cast<const MidPacket*>(other);
  return packet_type_ == rhs->packet_type_ &&
         name_ == rhs->name_ &&
         username_ == rhs->username_ &&
         pin_ == rhs->pin_ &&
         smid_appendix_ == rhs->smid_appendix_ &&
         encrypted_rid_ == rhs->encrypted_rid_ &&
         salt_ == rhs->salt_ &&
         secure_password_ == rhs->secure_password_ &&
         rid_ == rhs->rid_;
}



TmidPacket::TmidPacket()
    : pki::Packet(UNKNOWN),
      username_(),
      pin_(),
      password_(),
      rid_(),
      plain_text_master_data_(),
      salt_(),
      secure_password_(),
      encrypted_master_data_() {}

TmidPacket::TmidPacket(const std::string &username,
                       const std::string &pin,
                       const boost::uint32_t rid,
                       bool surrogate,
                       const std::string &password,
                       const std::string &plain_text_master_data)
    : pki::Packet(surrogate ? STMID : TMID),
      username_(username),
      pin_(pin),
      password_(password),
      rid_(rid),
      plain_text_master_data_(plain_text_master_data),
      salt_(),
      secure_password_(),
      encrypted_master_data_() {
  Initialise();
}

void TmidPacket::Initialise() {
  if (username_.empty() || pin_.empty() || rid_ == 0)
    return Clear();

  try {
    crypto::Crypto crypto_obj;
    name_ = crypto_obj.Hash(
                crypto_obj.Hash(username_, "", crypto::STRING_STRING, false) +
                crypto_obj.Hash(pin_, "", crypto::STRING_STRING, false) +
                crypto_obj.Hash(boost::lexical_cast<std::string>(rid_), "",
                                 crypto::STRING_STRING, false), "",
                crypto::STRING_STRING, false);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("TmidPacket::Initialise: %s\n", e.what());
#endif
    name_.clear();
  }
  if (!SetPassword())
    return;
  if (!SetPlainData())
    return;
  if (name_.empty())
    Clear();
}

bool TmidPacket::SetPassword() {
  if (password_.empty()) {
    salt_.clear();
    secure_password_.clear();
    return false;
  }
  try {
    crypto::Crypto crypto_obj;
    salt_ = crypto_obj.Hash(boost::lexical_cast<std::string>(rid_) + password_,
                            "", crypto::STRING_STRING, false);
    secure_password_ = crypto_obj.SecurePassword(password_, salt_, rid_);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("TmidPacket::SetPassword: %s\n", e.what());
#endif
    salt_.clear();
  }
  if (salt_.empty()) {
    Clear();
    return false;
  } else {
    return true;
  }
}

bool TmidPacket::SetPlainData() {
  if (plain_text_master_data_.empty() || secure_password_.empty()) {
    encrypted_master_data_.clear();
    return false;
  }
  try {
    crypto::Crypto crypto_obj;
    encrypted_master_data_ = crypto_obj.SymmEncrypt(plain_text_master_data_, "",
                             crypto::STRING_STRING, secure_password_);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("TmidPacket::SetPlainData: %s\n", e.what());
#endif
    encrypted_master_data_.clear();
  }
  if (encrypted_master_data_.empty()) {
    Clear();
    return false;
  } else {
    return true;
  }
}

std::string TmidPacket::DecryptPlainData(
    const std::string &password,
    const std::string &encrypted_master_data) {
  password_ = password;
  if (!SetPassword())
    return "";
  if (encrypted_master_data.empty()) {
#ifdef DEBUG
    printf("TmidPacket::DecryptPlainData: bad encrypted data.\n");
#endif
    password_.clear();
    salt_.clear();
    secure_password_.clear();
    return "";
  }
  try {
    encrypted_master_data_ = encrypted_master_data;
    crypto::Crypto crypto_obj;
    plain_text_master_data_ = crypto_obj.SymmDecrypt(encrypted_master_data_, "",
                              crypto::STRING_STRING, secure_password_);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("TmidPacket::DecryptPlainData: %s\n", e.what());
#endif
    plain_text_master_data_.clear();
  }
  if (plain_text_master_data_.empty())
    Clear();
  return plain_text_master_data_;
}

void TmidPacket::Clear() {
  name_.clear();
  username_.clear();
  pin_.clear();
  password_.clear();
  rid_ = 0;
  plain_text_master_data_.clear();
  salt_.clear();
  secure_password_.clear();
  encrypted_master_data_.clear();
}

bool TmidPacket::Equals(const pki::Packet *other) const {
  const TmidPacket *rhs = static_cast<const TmidPacket*>(other);
  return packet_type_ == rhs->packet_type_ &&
         name_ == rhs->name_ &&
         username_ == rhs->username_ &&
         pin_ == rhs->pin_ &&
         password_ == rhs->password_ &&
         rid_ == rhs->rid_ &&
         plain_text_master_data_ == rhs->plain_text_master_data_ &&
         salt_ == rhs->salt_ &&
         secure_password_ == rhs->secure_password_ &&
         encrypted_master_data_ == rhs->encrypted_master_data_;
}

}  // namespace passport

}  // namespace maidsafe
