/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Utility Functions
* Version:      1.0
* Created:      2010-04-29-13.26.25
* Revision:     none
* Compiler:     gcc
* Author:       Team, dev@maidsafe.net
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

#include "maidsafe/client/clientutils.h"
#include "maidsafe/common/commonutils.h"
#include "maidsafe/client/sessionsingleton.h"

namespace maidsafe {

std::string TidyPath(const std::string &original_path) {
  //  if path is root, don't change it
  if (original_path.size() == 1)
    return original_path;
  std::string amended_path = original_path;
  //  if path has training slash, remove it
  if (amended_path.at(amended_path.size() - 1) == '/' ||
      amended_path.at(amended_path.size() - 1) == '\\')
    amended_path = amended_path.substr(0, amended_path.size() - 1);
  //  if path has leading slash, remove it
  if (amended_path.at(0) == '/' || amended_path.at(0) == '\\')
    amended_path = amended_path.substr(1, amended_path.size() - 1);
  return amended_path;
}

std::string StringToLowercase(const std::string &str) {
  std::string lowercase;
  for (size_t i = 0; i < str.length(); ++i) {
    lowercase += tolower(str.at(i));
  }
  return lowercase;
}

ClientUtils::ClientUtils() : ss_(SessionSingleton::getInstance()) {}

void ClientUtils::GetChunkSignatureKeys(DirType dir_type,
                                    const std::string &msid,
                                    std::string *key_id,
                                    std::string *public_key,
                                    std::string *public_key_sig,
                                    std::string *private_key) {
  key_id->clear();
  public_key->clear();
  public_key_sig->clear();
  private_key->clear();
  switch (dir_type) {
    case PRIVATE_SHARE:
      if (kSuccess == ss_->GetShareKeys(msid, public_key, private_key)) {
        *key_id = msid;
        *public_key_sig = RSASign(*public_key, *private_key);
      } else {
        key_id->clear();
        public_key->clear();
        public_key_sig->clear();
        private_key->clear();
      }
      break;
    case PUBLIC_SHARE:
      *key_id = ss_->Id(passport::MPID, true);
      *public_key = ss_->PublicKey(passport::MPID, true);
      *public_key_sig = ss_->PublicKeySignature(passport::MPID, true);
      *private_key = ss_->PrivateKey(passport::MPID, true);
      break;
    case ANONYMOUS:
      *key_id = " ";
      *public_key = " ";
      *public_key_sig = " ";
      *private_key = "";
      break;
    case PRIVATE:
    default:
      *key_id = ss_->Id(passport::PMID, true);
      *public_key = ss_->PublicKey(passport::PMID, true);
      *public_key_sig = ss_->PublicKeySignature(passport::PMID, true);
      *private_key = ss_->PrivateKey(passport::PMID, true);
      break;
  }
}

void ClientUtils::GetPacketSignatureKeys(passport::PacketType packet_type,
                                         DirType dir_type,
                                         const std::string &msid,
                                         std::string *key_id,
                                         std::string *public_key,
                                         std::string *public_key_sig,
                                         std::string *private_key) {
  // For self-signers, signing packet will not be confirmed as stored.  For all
  // others, it must be.
  key_id->clear();
  public_key->clear();
  public_key_sig->clear();
  private_key->clear();
  bool confirmed_as_stored(true);
  switch (packet_type) {
    case passport::ANMID:
      confirmed_as_stored = false;
    case passport::MID:
      *key_id = ss_->Id(passport::ANMID, confirmed_as_stored);
      *public_key = ss_->PublicKey(passport::ANMID, confirmed_as_stored);
      *public_key_sig = ss_->PublicKeySignature(passport::ANMID,
                                                confirmed_as_stored);
      *private_key = ss_->PrivateKey(passport::ANMID, confirmed_as_stored);
      break;
    case passport::ANSMID:
      confirmed_as_stored = false;
    case passport::SMID:
      *key_id = ss_->Id(passport::ANSMID, confirmed_as_stored);
      *public_key = ss_->PublicKey(passport::ANSMID, confirmed_as_stored);
      *public_key_sig = ss_->PublicKeySignature(passport::ANSMID,
                                                confirmed_as_stored);
      *private_key = ss_->PrivateKey(passport::ANSMID, confirmed_as_stored);
      break;
    case passport::ANTMID:
      confirmed_as_stored = false;
    case passport::TMID:
    case passport::STMID:
      *key_id = ss_->Id(passport::ANTMID, confirmed_as_stored);
      *public_key = ss_->PublicKey(passport::ANTMID, confirmed_as_stored);
      *public_key_sig = ss_->PublicKeySignature(passport::ANTMID,
                                                confirmed_as_stored);
      *private_key = ss_->PrivateKey(passport::ANTMID, confirmed_as_stored);
      break;
    case passport::ANMPID:
      confirmed_as_stored = false;
    case passport::MPID:
      *key_id = ss_->Id(passport::ANMPID, confirmed_as_stored);
      *public_key = ss_->PublicKey(passport::ANMPID, confirmed_as_stored);
      *public_key_sig = ss_->PublicKeySignature(passport::ANMPID,
                                                confirmed_as_stored);
      *private_key = ss_->PrivateKey(passport::ANMPID, confirmed_as_stored);
      break;
    case passport::ANMAID:
      confirmed_as_stored = false;
    case passport::MAID:
      *key_id = ss_->Id(passport::ANMAID, confirmed_as_stored);
      *public_key = ss_->PublicKey(passport::ANMAID, confirmed_as_stored);
      *public_key_sig = ss_->PublicKeySignature(passport::ANMAID,
                                                confirmed_as_stored);
      *private_key = ss_->PrivateKey(passport::ANMAID, confirmed_as_stored);
      break;
    case passport::PMID:
      *key_id = ss_->Id(passport::MAID, true);
      *public_key = ss_->PublicKey(passport::MAID, true);
      *public_key_sig = ss_->PublicKeySignature(passport::MAID, true);
      *private_key = ss_->PrivateKey(passport::MAID, true);
      break;
    case passport::PD_DIR:
    case passport::MSID:
      GetChunkSignatureKeys(dir_type, msid, key_id, public_key, public_key_sig,
                            private_key);
      break;
    default:
      break;
  }
}

}  // namespace maidsafe
