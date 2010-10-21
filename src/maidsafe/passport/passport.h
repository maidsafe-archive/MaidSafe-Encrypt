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
        kSmidAppendix_("1") {}
  // Starts buffering cryptographic key pairs
  void Init();
  ~Passport() {}
  // Used to initilise packet_handler_ in all cases.
  // Creates a pending MID and SMID which need to have their RID set.  If
  // successful, names of packets are set in mid_name and smid_name.  Can be
  // called repeatedly (with different username and/or pin) in case generated
  // mid_name or smid_name are unsuitable.
  int SetInitialDetails(const std::string &username,
                        const std::string &pin,
                        std::string *mid_name,
                        std::string *smid_name);
  // Used when creating a new user.
  // Sets a new RID for the pending MID and creates a pending TMID.  Also sets
  // same RID for a new pending SMID to ensure it is available for storing on
  // later.  If successful, a copy of the pending packets are set before
  // returning kSuccess.  Can be called repeatedly (with same password and
  // plain_data) in case generated tmid name is unsuitable.
  int SetNewUserData(const std::string &password,
                     const std::string &plain_data,
                     std::tr1::shared_ptr<MidPacket> mid,
                     std::tr1::shared_ptr<MidPacket> smid,
                     std::tr1::shared_ptr<TmidPacket> tmid);
  // Used when creating a new user.
  // Confirms MID, SMID and TMID are successfully stored.
  int ConfirmNewUserData(std::tr1::shared_ptr<MidPacket> mid,
                         std::tr1::shared_ptr<MidPacket> smid,
                         std::tr1::shared_ptr<TmidPacket> tmid);
  // Used when saving a session.
  // Adds a pending MID with a new RID, and adds a pending SMID with MID's old
  // RID.  Also creates a new pending TMID and sets existing confirmed TMID as
  // new confirmed STMID.  Old confirmed STMID is set as tmid_for_deletion
  // unless confirmed TMID == confirmed STMID (i.e. for a repeat attempt which
  // means that old STMID will have been provided in a previous attempt) in
  // which case tmid_for_deletion is NULL.  If successful, a copy of the new and
  // old details are set before returning kSuccess.  Can be called repeatedly
  // (with same plain_data) in case generated new_tmid name is unsuitable. 
  int UpdateUserData(const std::string &plain_data,
                     std::string *mid_old_value,
                     std::string *smid_old_value,
                     std::tr1::shared_ptr<MidPacket> updated_mid,
                     std::tr1::shared_ptr<MidPacket> updated_smid,
                     std::tr1::shared_ptr<TmidPacket> new_tmid,
                     std::tr1::shared_ptr<TmidPacket> tmid_for_deletion);
  // Used when logging in.
  // Sets the RID for pending MID (or pending SMID) packet, and creates a
  // corresponding pending TMID (or pending STMID) which needs to have its
  // password & plain_data set.  If successful, name of the packet is set in
  // tmid_name.
  int InitialiseTmid(bool surrogate,
                     const std::string &serialised_mid_packet,
                     std::string *tmid_name);
  // Used when logging in.
  // Returns the plain_data from a pending TMID (or pendig STMID) serialised
  // packet.
  int GetUserData(const std::string &password,
                  bool surrogate,
                  const std::string &serialised_tmid_packet,
                  std::string *plain_data);





  // Generates new MID, SMID, TMID and STMID packets based on the updated user
  // data.  If successful, a copy of the new and old details are set before
  // returning kSuccess.
  int ChangeUserData(const std::string &new_username,
                     const std::string &new_pin,
                     const std::string &plain_data,
                     std::tr1::shared_ptr<MidPacket> mid_for_deletion,
                     std::tr1::shared_ptr<MidPacket> smid_for_deletion,
                     std::tr1::shared_ptr<TmidPacket> tmid_for_deletion,
                     std::tr1::shared_ptr<TmidPacket> stmid_for_deletion,
                     std::tr1::shared_ptr<MidPacket> new_mid,
                     std::tr1::shared_ptr<MidPacket> new_smid,
                     std::tr1::shared_ptr<TmidPacket> new_tmid,
                     std::tr1::shared_ptr<TmidPacket> new_stmid);
  // Updates value of TMID and STMID packets based on the updated password.  If
  // successful, a copy of the new and old details are set before returning
  // kSuccess.
  int ChangePassword(const std::string &new_password,
                     const std::string &plain_data,
                     std::string *tmid_old_value,
                     std::string *stmid_old_value,
                     std::tr1::shared_ptr<TmidPacket> updated_tmid,
                     std::tr1::shared_ptr<TmidPacket> updated_stmid);
  // Serialises signature packets only to a keyring
  std::string SerialiseKeyring();
  // Parses a previously serialised keyring
  int ParseKeyring(const std::string &serialised_keyring);
  // Removes signature packets from packet_handler_
  void ClearKeyring() { packet_handler_.ClearKeyring(); }
  // Creates a new signature packet.  For non-self-signing packets, will fail if
  // signing packet type is not already in packet_handler_.  If MSID, it is not
  // added to the packet_handler_.  If successful, a copy of the packet is set
  // before returning kSuccess.
  int InitialiseSignaturePacket(
      const PacketType &packet_type,
      std::tr1::shared_ptr<SignaturePacket> signature_packet);
  // Creates a new MPID.  Will fail if ANMPID is not already in packet_handler_.
  // If successful, a copy of the MPID is set before returning kSuccess.
  int InitialiseMpid(const std::string &public_name,
                     std::tr1::shared_ptr<SignaturePacket> mpid);
  // Returns a copy of the packet.
  std::tr1::shared_ptr<pki::Packet> Packet(const PacketType &packet_type);
  void Clear() { packet_handler_.Clear(); }
 private:
  Passport &operator=(const Passport&);
  Passport(const Passport&);
  int DoInitialiseSignaturePacket(
      const PacketType &packet_type,
      const std::string &public_name,
      std::tr1::shared_ptr<SignaturePacket> signature_packet);
  SystemPacketHandler packet_handler_;
  CryptoKeyPairs crypto_key_pairs_;
  const std::string kSmidAppendix_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORT_H_

