/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Handles user's list of maidsafe contacts
* Version:      1.0
* Created:      2009-01-28-23.19.56
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

#ifndef MAIDSAFE_CLIENT_PRIVATESHARES_H_
#define MAIDSAFE_CLIENT_PRIVATESHARES_H_

#include <boost/shared_ptr.hpp>

#include <string>
#include <list>
#include <vector>

#include "maidsafe/cppsqlite3.h"
#include "maidsafe/utils.h"
#include "maidsafe/client/messagehandler.h"

namespace maidsafe {

struct ShareParticipants {
  ShareParticipants() : id(""), public_key(), role('R') {}
  bool operator==(const ShareParticipants& other) {
    return static_cast<bool>(id == other.id &&
                             public_key == other.public_key &&
                             role == other.role);
  }
  std::string id;
  std::string public_key;
  char role;
};

struct private_share {
  std::string name_;
  std::string msid_;
  std::string msid_pub_key_;
  std::string msid_priv_key_;

  private_share() : name_(), msid_(), msid_pub_key_(), msid_priv_key_() {}
  private_share(std::string name, std::string msid, std::string msid_pub_key,
                std::string msid_priv_key)
                : name_(name), msid_(msid), msid_pub_key_(msid_pub_key),
                  msid_priv_key_(msid_priv_key) {}
};

struct share_participant {
  std::string msid_;
  std::string public_name_;
  std::string public_key_;
  char role_;
  share_participant() : msid_(), public_name_(), public_key_(), role_('R') {}
  share_participant(std::string msid, std::string public_name,
                    std::string public_key, char role)
                    : msid_(msid), public_name_(public_name),
                      public_key_(public_key), role_(role) {}
};

/* Tags */
struct private_share_name {};
struct private_share_msid {};
struct share_participant_msid {};
struct share_participant_public_name {};

typedef boost::multi_index::multi_index_container<
  private_share,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<private_share_name>,
      BOOST_MULTI_INDEX_MEMBER(private_share, std::string, name_)
    >,
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<private_share_msid>,
      BOOST_MULTI_INDEX_MEMBER(private_share, std::string, msid_)
    >
  >
> private_share_set;

typedef boost::multi_index::multi_index_container<
  share_participant,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<share_participant_public_name>,
      BOOST_MULTI_INDEX_MEMBER(share_participant, std::string, public_name_)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<share_participant_msid>,
      BOOST_MULTI_INDEX_MEMBER(share_participant, std::string, msid_)
    >
  >
> private_share_participant_set;

class PrivateShare {
 private:
  std::string name_;
  std::string msid_;
  std::string msid_pub_key_;
  std::string msid_priv_key_;
  std::list<ShareParticipants> participants_;

 public:
  //  Constructors
  PrivateShare();
  PrivateShare(const std::vector<std::string> &attributes,
               std::list<ShareParticipants> participants);

  //  Getters
  inline std::string Name() { return name_; }
  inline std::string Msid() { return msid_; }
  inline std::string MsidPubKey() { return msid_pub_key_; }
  inline std::string MsidPriKey() { return msid_priv_key_; }
  inline std::list<ShareParticipants> Participants() { return participants_; }
  // Setters
};

class PrivateShareHandler {
 private:
  boost::shared_ptr<CppSQLite3DB> db_;
  private_share_set pss_;
  private_share_participant_set psps_;
  int Connect(const std::string &dbName);
  int Close();

 public:
  PrivateShareHandler() : db_(), pss_(), psps_() { }
  int CreatePrivateShareDB(const std::string &dbName);
  int GetPrivateShareList(const std::string &dbName,
                          std::list<PrivateShare> *participants,
                          const std::string &value, const int &type);
  int AddPrivateShare(const std::string &dbName,
                      const std::vector<std::string> &attributes,
                      std::list<ShareParticipants> *participants);
  int AddReceivedShare(const std::string &dbName,
                       const std::vector<std::string> &attributes);
  int DeletePrivateShare(const std::string &dbName,
                         const std::string &value,
                         const int &field);
  int AddContactsToPrivateShare(const std::string &dbName,
                                std::list<ShareParticipants> *participants,
                                const std::string &value, const int &type);
  int DeleteContactsFromPrivateShare(const std::string &dbName,
                                     std::list<ShareParticipants>
                                                   *participants);

  // Multi Index
  int MI_AddPrivateShare(const std::vector<std::string> &attributes,
                         std::list<ShareParticipants> *participants);
  int MI_DeletePrivateShare(const std::string &value, const int &field);
  int MI_AddContactsToPrivateShare(const std::string &value, const int &field,
                                   std::list<ShareParticipants> *participants);
  int MI_DeleteContactsFromPrivateShare(const std::string &value,
                                        const int &field,
                                        std::list<ShareParticipants>
                                        *participants);
  int MI_GetShareInfo(const std::string &value, const int &field,
                      PrivateShare *ps);
  int MI_GetShareList(std::list<private_share> *ps_list);
  int MI_GetFullShareList(std::list<PrivateShare> *ps_list);
  int MI_GetParticipantsList(const std::string &value, const int &field,
                             std::list<share_participant> *sp_list);
};

}  // namespace

#endif  // MAIDSAFE_CLIENT_PRIVATESHARES_H_
