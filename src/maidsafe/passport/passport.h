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
  // Creates a MID and SMID which need to have their RID set.  If successful,
  // names of packets are set in mid_name and smid_name.
  int SetInitialDetails(const std::string &username,
                        const std::string &pin,
                        std::string *mid_name,
                        std::string *smid_name);
  // Sets a new RID for the MID and creates a TMID.  If successful, a *copy* of
  // the complete packets are set before returning kSuccess.
  int SetNewUserData(const std::string &password,
                     const std::string &plain_data,
                     boost::shared_ptr<MidPacket> mid,
                     boost::shared_ptr<TmidPacket> tmid);
  // Sets SMID's RID to MID's RID and generates new RID for MID.  Also creates
  // new TMID.  If successful, a *copy* of the new and old details are set
  // before returning kSuccess.
  int UpdateUserData(const std::string &plain_data,
                     std::string *mid_old_value,
                     std::string *smid_old_value,
                     boost::shared_ptr<MidPacket> updated_mid,
                     boost::shared_ptr<MidPacket> updated_smid,
                     boost::shared_ptr<TmidPacket> new_tmid,
                     boost::shared_ptr<TmidPacket> tmid_for_deletion);
  // Sets the RID for MID (or SMID) packet, and creates a corresponding TMID (or
  // STMID) which needs to have its plain_data set.  If successful, name of the
  // packet is set in tmid_name.
  int InitialiseTmid(const std::string &password,
                     bool surrogate,
                     const std::string &serialised_mid_packet,
                     std::string *tmid_name);
  // Returns the plain_data from a TMID (or STMID) serialised packet
  int GetUserData(bool surrogate,
                  const std::string &serialised_tmid_packet,
                  std::string *plain_data);
  // Serialises signature packets only to a keyring
  std::string SerialiseKeyring();
  // Parses a previously serialised keyring
  int ParseKeyring(const std::string &serialised_keyring);
  // Removes signature packets from packet_handler_
  void ClearKeyring();
  // Creates a new signature packet.  For non-self-signing packets, will fail if
  // signing packet type is not already in packet_handler_.  If successful, a
  // *copy* of the packet is set before returning kSuccess.
  int InitialiseSignaturePacket(
      const PacketType &packet_type,
      boost::shared_ptr<SignaturePacket> signature_packet);
  // Creates a new MPID.  Will fail if ANMPID is not already in packet_handler_.
  // If successful, a *copy* of the MPID is set before returning kSuccess.
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

