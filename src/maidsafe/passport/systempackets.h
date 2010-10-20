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
#include <boost/shared_ptr.hpp>
#include <string>
#include "maidsafe/pki/packet.h"

namespace testing {
class AssertionResult;
}

namespace maidsafe {

namespace passport {

class MidPacket;
class TmidPacket;

namespace test {
testing::AssertionResult Empty(boost::shared_ptr<pki::Packet> packet);
class SystemPacketsTest_BEH_PASSPORT_CreateSig_Test;
class SystemPacketsTest_BEH_PASSPORT_PutToAndGetFromKey_Test;
struct ExpectedMidContent;
testing::AssertionResult Equal(boost::shared_ptr<ExpectedMidContent> expected,
                               boost::shared_ptr<MidPacket> mid);
struct ExpectedTmidContent;
testing::AssertionResult Equal(boost::shared_ptr<ExpectedTmidContent> expected,
                               boost::shared_ptr<TmidPacket> mid);
}  // namespace test

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
  void PutToKey(Key *key);
  std::string private_key() const { return private_key_; }
  std::string public_key_signature() const { return public_key_signature_; }
 private:
  friend testing::AssertionResult
      test::Empty(boost::shared_ptr<pki::Packet> packet);
  friend class test::SystemPacketsTest_BEH_PASSPORT_CreateSig_Test;
  friend class test::SystemPacketsTest_BEH_PASSPORT_PutToAndGetFromKey_Test;
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
  void SetRid(const boost::uint32_t &rid);
  boost::uint32_t DecryptRid(const std::string &encrypted_rid);
  std::string username() const { return username_; }
  std::string pin() const { return pin_; }
  boost::uint32_t rid() const { return rid_; }
 private:
  friend testing::AssertionResult
      test::Empty(boost::shared_ptr<pki::Packet> packet);
  friend testing::AssertionResult
      test::Equal(boost::shared_ptr<ExpectedMidContent> expected,
                  boost::shared_ptr<MidPacket> mid);
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
             const boost::uint32_t rid,
             bool surrogate,
             const std::string &password,
             const std::string &plain_data);
  virtual ~TmidPacket() {}
  virtual std::string value() const { return encrypted_data_; }
  std::string DecryptPlainData(const std::string &password,
                               const std::string &encrypted_data);
  void SetToSurrogate() { packet_type_ = STMID; }
  std::string username() const { return username_; }
  std::string pin() const { return pin_; }
  std::string password() const { return password_; }
 private:
  friend testing::AssertionResult
      test::Empty(boost::shared_ptr<pki::Packet> packet);
  friend testing::AssertionResult
      test::Equal(boost::shared_ptr<ExpectedTmidContent> expected,
                  boost::shared_ptr<TmidPacket> mid);
  virtual void Initialise();
  bool SetPassword();
  bool SetPlainData();
  virtual void Clear();
  std::string username_, pin_, password_;
  boost::uint32_t rid_;
  std::string plain_data_, salt_, secure_password_, encrypted_data_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_SYSTEMPACKETS_H_

