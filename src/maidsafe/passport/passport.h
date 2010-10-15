/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  API to MaidSafe Passport
* Version:      1.0
* Created:      2010-10-13-14.01.23
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

#ifndef MAIDSAFE_PASSPORT_PASSPORT_H_
#define MAIDSAFE_PASSPORT_PASSPORT_H_

#include <boost/cstdint.hpp>

#include "maidsafe/passport/cryptokeypairs.h"
#include "maidsafe/passport/systempackethandler.h"

namespace maidsafe {

namespace passport {

class Passport {
 public:
  // Size to generate RSA keys in bits.
  explicit Passport(const boost::uint16_t &rsa_key_size,
                    const boost::int8_t &max_crypto_thread_count)
      : packet_handler_(),
        crypto_key_pairs_(rsa_key_size, max_crypto_thread_count),
        crypto_key_buffer_count_(0),
        kSmidAppendix_("1") {}
  void Init(const boost::uint16_t &crypto_key_buffer_count);
  ~Passport() {}
  int SetInitialDetails(const std::string &username,
                        const std::string &pin,
                        std::string *mid_name,
                        std::string *smid_name);
  int SetRid(boost::shared_ptr<MidPacket> mid,
             boost::shared_ptr<MidPacket> smid);
  int InitialiseTmid(const std::string &password,
                     bool surrogate,
                     const std::string &serialised_mid_packet,
                     std::string *tmid_name);
  int SetUserData(const std::string &plain_data,
                  boost::shared_ptr<TmidPacket> tmid);
  int GetUserData(bool surrogate,
                  const std::string &serialised_tmid_packet,
                  std::string *plain_data);
  std::string SerialiseKeyring();
  int ParseKeyring(const std::string &serialised_keyring);
  int InitialiseSignaturePacket(
      const PacketType &packet_type,
      boost::shared_ptr<SignaturePacket> signature_packet);
  int InitialiseMpid(const std::string &public_name,
                     boost::shared_ptr<SignaturePacket> mpid);
 private:
  Passport &operator=(const Passport&);
  Passport(const Passport&);
  int DoInitialiseSignaturePacket(
      const PacketType &packet_type,
      const std::string &public_name,
      boost::shared_ptr<SignaturePacket> signature_packet);
  SystemPacketHandler packet_handler_;
  CryptoKeyPairs crypto_key_pairs_;
  boost::uint16_t crypto_key_buffer_count_;
  const std::string kSmidAppendix_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORT_H_

