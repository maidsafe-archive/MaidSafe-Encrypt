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
* Author:       Team maidsafe.net
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

#include <boost/scoped_ptr.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <gtest/gtest_prod.h>

#include <maidsafe/utils.h>
#include <maidsafe/maidsafe-dht_config.h>

#include <string>
#include <list>
#include <vector>

#include "maidsafe/maidsafe.h"

namespace maidsafe {

struct ShareParticipants {
  ShareParticipants() : id(), public_key(), role('R') {}
  ShareParticipants(const std::string &l_id,
                    const std::string &l_public_key,
                    const char &l_role)
                    : id(l_id), public_key(l_public_key), role(l_role) {}
  bool operator==(const ShareParticipants& other) {
    return static_cast<bool>(id == other.id &&
                             public_key == other.public_key &&
                             role == other.role);
  }
  std::string id;
  std::string public_key;
  char role;
};

class PrivateShare {
 private:
  std::string name_;
  std::string msid_;
  std::string msid_pub_key_;
  std::string msid_priv_key_;
  boost::uint32_t rank_;
  boost::uint32_t last_view_;
  std::list<ShareParticipants> participants_;

 public:
  //  Constructors
  PrivateShare();
  PrivateShare(const std::vector<std::string> &attributes,
               std::list<ShareParticipants> participants);
  void Construct(const std::vector<std::string> &attributes,
                 const std::vector<boost::uint32_t> &share_stats,
                 std::list<ShareParticipants> participants);

  //  Getters
  inline std::string Name() { return name_; }
  inline std::string Msid() { return msid_; }
  inline std::string MsidPubKey() { return msid_pub_key_; }
  inline std::string MsidPriKey() { return msid_priv_key_; }
  inline std::list<ShareParticipants> Participants() { return participants_; }
  inline boost::uint32_t Rank() { return rank_; }
  inline boost::uint32_t LastViewed() { return last_view_; }
  // Setters
};

struct private_share {
  std::string name_;
  std::string msid_;
  std::string msid_pub_key_;
  std::string msid_priv_key_;
  boost::uint32_t rank_;
  boost::uint32_t last_view_;

  private_share() : name_(), msid_(), msid_pub_key_(), msid_priv_key_(),
                    rank_(0), last_view_(0) {}
  private_share(std::string name, std::string msid, std::string msid_pub_key,
                std::string msid_priv_key)
                : name_(name), msid_(msid), msid_pub_key_(msid_pub_key),
                  msid_priv_key_(msid_priv_key), rank_(0), last_view_(0) {}
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
struct private_share_rank {};
struct private_share_view {};
struct share_participant_key {};
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
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<private_share_rank>,
      BOOST_MULTI_INDEX_MEMBER(private_share, boost::uint32_t, rank_)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<private_share_view>,
      BOOST_MULTI_INDEX_MEMBER(private_share, boost::uint32_t, last_view_)
    >
  >
> private_share_set;

typedef boost::multi_index::multi_index_container<
  share_participant,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<share_participant_key>,
      boost::multi_index::composite_key<
        share_participant,
        BOOST_MULTI_INDEX_MEMBER(share_participant, std::string, public_name_),
        BOOST_MULTI_INDEX_MEMBER(share_participant, std::string, msid_)
      >
    >,
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

class PrivateShareHandler {
 private:
  private_share_set pss_;
  private_share_participant_set psps_;
  void DecideInclusion(const private_share &ps,
                       const ShareFilter &sf,
                       std::list<maidsafe::private_share> *ps_list);
  FRIEND_TEST(PrivateSharesTest, BEH_MAID_MI_DecideInclusion);
 public:
  PrivateShareHandler() : pss_(), psps_() { }
  // Multi Index
  int MI_AddPrivateShare(const std::vector<std::string> &attributes,
                         const std::vector<boost::uint32_t> &share_stats,
                         std::list<ShareParticipants> *participants);
  int MI_DeletePrivateShare(const std::string &value, const int &field);
  int MI_AddContactsToPrivateShare(const std::string &value, const int &field,
                                   std::list<ShareParticipants> *participants);
  int MI_DeleteContactsFromPrivateShare(const std::string &value,
                                        const int &field,
                                        std::list<std::string> *participants);
  int MI_TouchShare(const std::string &value, const int &field);
  int MI_GetShareInfo(const std::string &value, const int &field,
                      PrivateShare *ps);
  int MI_GetShareList(std::list<maidsafe::private_share> *ps_list,
                      const SortingMode &sm, const ShareFilter &sf);
  int MI_GetFullShareList(const SortingMode &sm, const ShareFilter &sf,
                          std::list<PrivateShare> *ps_list);
  int MI_GetParticipantsList(const std::string &value, const int &field,
                             std::list<share_participant> *sp_list);
  void MI_ClearPrivateShares();
};

}  // namespace

#endif  // MAIDSAFE_CLIENT_PRIVATESHARES_H_
