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

#include "maidsafe/pdutils.h"
#include <maidsafe/kademlia/contact.h>
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

bool ContactHasId(const std::string &id, const kad::Contact &contact) {
  return contact.node_id().String() == id;
}

void PdUtils::GetChunkSignatureKeys(DirType dir_type,
                                    const std::string &msid,
                                    std::string *key_id,
                                    std::string *public_key,
                                    std::string *public_key_sig,
                                    std::string *private_key) {
  key_id->clear();
  public_key->clear();
  public_key_sig->clear();
  private_key->clear();
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  SessionSingleton *ss = SessionSingleton::getInstance();
  switch (dir_type) {
    case PRIVATE_SHARE:
      if (kSuccess == ss->GetShareKeys(msid, public_key, private_key)) {
        *key_id = msid;
        *public_key_sig =
            co.AsymSign(*public_key, "", *private_key, crypto::STRING_STRING);
      } else {
        key_id->clear();
        public_key->clear();
        public_key_sig->clear();
        private_key->clear();
      }
      break;
    case PUBLIC_SHARE:
      *key_id = ss->Id(MPID);
      *public_key = ss->PublicKey(MPID);
      *public_key_sig = ss->SignedPublicKey(MPID);
      *private_key = ss->PrivateKey(MPID);
      break;
    case ANONYMOUS:
      *key_id = " ";
      *public_key = " ";
      *public_key_sig = " ";
      *private_key = "";
      break;
    case PRIVATE:
    default:
      *key_id = ss->Id(PMID);
      *public_key = ss->PublicKey(PMID);
      *public_key_sig = ss->SignedPublicKey(PMID);
      *private_key = ss->PrivateKey(PMID);
      break;
  }
}

void PdUtils::GetPacketSignatureKeys(PacketType packet_type,
                                     DirType dir_type,
                                     const std::string &msid,
                                     std::string *key_id,
                                     std::string *public_key,
                                     std::string *public_key_sig,
                                     std::string *private_key) {
  key_id->clear();
  public_key->clear();
  public_key_sig->clear();
  private_key->clear();
  SessionSingleton *ss = SessionSingleton::getInstance();
  switch (packet_type) {
    case MID:
    case ANMID:
      *key_id = ss->Id(ANMID);
      *public_key = ss->PublicKey(ANMID);
      *public_key_sig = ss->SignedPublicKey(ANMID);
      *private_key = ss->PrivateKey(ANMID);
      break;
    case SMID:
    case ANSMID:
      *key_id = ss->Id(ANSMID);
      *public_key = ss->PublicKey(ANSMID);
      *public_key_sig = ss->SignedPublicKey(ANSMID);
      *private_key = ss->PrivateKey(ANSMID);
      break;
    case TMID:
    case ANTMID:
      *key_id = ss->Id(ANTMID);
      *public_key = ss->PublicKey(ANTMID);
      *public_key_sig = ss->SignedPublicKey(ANTMID);
      *private_key = ss->PrivateKey(ANTMID);
      break;
    case MPID:
    case ANMPID:
      *key_id = ss->Id(ANMPID);
      *public_key = ss->PublicKey(ANMPID);
      *public_key_sig = ss->SignedPublicKey(ANMPID);
      *private_key = ss->PrivateKey(ANMPID);
      break;
    case MAID:
    case ANMAID:
      *key_id = ss->Id(ANMAID);
      *public_key = ss->PublicKey(ANMAID);
      *public_key_sig = ss->SignedPublicKey(ANMAID);
      *private_key = ss->PrivateKey(ANMAID);
      break;
    case PMID:
      *key_id = ss->Id(MAID);
      *public_key = ss->PublicKey(MAID);
      *public_key_sig = ss->SignedPublicKey(MAID);
      *private_key = ss->PrivateKey(MAID);
      break;
    case PD_DIR:
    case MSID:
      GetChunkSignatureKeys(dir_type, msid, key_id, public_key, public_key_sig,
                            private_key);
      break;
    default:
      break;
  }
}

}  // namespace maidsafe
