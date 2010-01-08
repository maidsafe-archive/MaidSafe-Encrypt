/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 13, 2008
 *      Author: Team
 */
#include "maidsafe/client/privateshares.h"
#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

namespace maidsafe {

// PrivateShare
PrivateShare::PrivateShare() : name_(""),
    msid_(""), msid_pub_key_(""), msid_priv_key_(""),
    rank_(0), last_view_(0), participants_(0) {
}

PrivateShare::PrivateShare(const std::vector<std::string> &attributes,
    std::list<ShareParticipants> participants) : name_(attributes[0]),
    msid_(attributes[1]), msid_pub_key_(attributes[2]),
    msid_priv_key_(attributes[3]), rank_(0), last_view_(0),
    participants_(participants) {
}

void PrivateShare::Construct(const std::vector<std::string> &attributes,
                             const std::vector<boost::uint32_t> &share_stats,
                             std::list<ShareParticipants> participants) {
  name_ = attributes[0];
  msid_ = attributes[1];
  msid_pub_key_ = attributes[2];
  msid_priv_key_ = attributes[3];
  rank_ = share_stats[0];
  last_view_ = share_stats[1];
  participants_ = participants;
}

// PrivateShareHandler

// Multi Index
int PrivateShareHandler::MI_AddPrivateShare(
    const std::vector<std::string> &attributes,
    const std::vector<boost::uint32_t> &share_stats,
    std::list<ShareParticipants> *participants) {
  if (attributes.size() != 4)
    return -2010;

  bool ro_participation = false;
  if (attributes[3] == "" && participants->empty())
    ro_participation = true;

  private_share ps(attributes[0], attributes[1], attributes[2], attributes[3]);
  ps.rank_ = share_stats[0];
  ps.last_view_ = share_stats[1];
  std::pair<private_share_set::iterator, bool> result = pss_.insert(ps);
  if (!result.second)
    return -2010;

  if (!ro_participation) {
    while (!participants->empty()) {
      ShareParticipants sps = participants->front();
      share_participant sp(ps.msid_, sps.id, sps.public_key, sps.role);
      participants->pop_front();
      psps_.insert(sp);
    }
  }

  return 0;
}

int PrivateShareHandler::MI_DeletePrivateShare(
    const std::string &value, const int &field) {
  if (field < 0 || field > 1)
    return -2011;
  std::string msid(value);
  if (field == 0) {
    typedef private_share_set::index<private_share_name>::type
            private_share_set_by_name;
    private_share_set_by_name& private_share_index =
        pss_.get<private_share_name>();
    private_share_set_by_name::iterator it = private_share_index.find(value);
    if (it == private_share_index.end())
      return -2011;
    msid = (*it).msid_;
    private_share_index.erase(value);
  } else {
    typedef private_share_set::index<private_share_msid>::type
            private_share_set_by_msid;
    private_share_set_by_msid& private_share_index =
        pss_.get<private_share_msid>();
    private_share_set_by_msid::iterator it = private_share_index.find(msid);
    if (it == private_share_index.end())
      return -2011;
    private_share_index.erase(msid);
  }

  typedef private_share_participant_set::index<share_participant_msid>::type
          private_share_participant_set_by_msid;
  private_share_participant_set_by_msid& private_share_participant_index =
      psps_.get<share_participant_msid>();
  private_share_participant_set_by_msid::iterator it =
      private_share_participant_index.find(msid);
  if (it == private_share_participant_index.end())
    return -2011;
  private_share_participant_index.erase(msid);

  return 0;
}

int PrivateShareHandler::MI_AddContactsToPrivateShare(
    const std::string &value, const int &field,
    std::list<ShareParticipants> *participants) {
  if (field < 0 || field > 1)
    return -2012;
  std::string msid(value);
  if (field == 0) {
    typedef private_share_set::index<private_share_name>::type
            private_share_set_by_name;
    private_share_set_by_name& private_share_index =
        pss_.get<private_share_name>();
    private_share_set_by_name::iterator it = private_share_index.find(value);
    if (it == private_share_index.end())
      return -2012;
    msid = (*it).msid_;
  }

  while (!participants->empty()) {
    ShareParticipants sps = participants->front();
    share_participant sp(msid, sps.id, sps.public_key, sps.role);
    participants->pop_front();
    psps_.insert(sp);
  }

  return 0;
}

int PrivateShareHandler::MI_DeleteContactsFromPrivateShare(
    const std::string &value, const int &field,
    std::list<std::string> *participants) {
  if (field < 0 || field > 1)
    return -2013;
  std::string msid(value);
  if (field == 0) {
    typedef private_share_set::index<private_share_name>::type
            private_share_set_by_name;
    private_share_set_by_name& private_share_index =
        pss_.get<private_share_name>();
    private_share_set_by_name::iterator it = private_share_index.find(value);
    if (it == private_share_index.end())
      return -2013;
    msid = (*it).msid_;
  }

  typedef private_share_participant_set::index<share_participant_key>::type
          private_share_participant_set_key;
  private_share_participant_set_key &private_share_participant_index =
      psps_.get<share_participant_key>();
  if (private_share_participant_index.size() == 0)
    return -2013;

  int deleted = participants->size();
  while (!participants->empty()) {
    std::string public_name(participants->front());
    private_share_participant_set_key::iterator it =
        private_share_participant_index.find(
        boost::make_tuple(public_name, msid));
    if (it != private_share_participant_index.end()) {
      private_share_participant_index.erase(it);
      deleted--;
    }
    participants->pop_front();
  }

  if (deleted != 0)
    return -2013;

  return 0;
}

int PrivateShareHandler::MI_TouchShare(const std::string &value,
                                       const int &field) {
  if (field < 0 || field > 1)
    return -2024;
  std::string name(value);
  if (field == 1) {
    typedef private_share_set::index<private_share_msid>::type
            private_share_set_by_msid;
    private_share_set_by_msid& private_share_index =
        pss_.get<private_share_msid>();
    private_share_set_by_msid::iterator it = private_share_index.find(value);
    if (it == private_share_index.end())
      return -2024;
    name = (*it).name_;
  }
  typedef private_share_set::index<private_share_name>::type
          private_share_set_by_name;
  private_share_set_by_name& private_share_index =
      pss_.get<private_share_name>();
  private_share_set_by_name::iterator it = private_share_index.find(name);
  if (it == private_share_index.end())
    return -2024;
  private_share p_s = *it;
  ++p_s.rank_;
  p_s.last_view_ = base::get_epoch_time();
  pss_.replace(it, p_s);

  return 0;
}

int PrivateShareHandler::MI_GetShareInfo(const std::string &value,
    const int &field, PrivateShare *ps) {
  if (field < 0 || field > 1)
    return -2014;
  std::string msid(value);
  std::vector<std::string> share_attributes;
  std::vector<boost::uint32_t> share_stats;
  if (field == 0) {
    typedef private_share_set::index<private_share_name>::type
            private_share_set_by_name;
    private_share_set_by_name& private_share_index =
        pss_.get<private_share_name>();
    private_share_set_by_name::iterator it = private_share_index.find(value);
    if (it == private_share_index.end())
      return -2014;
    msid = (*it).msid_;
    share_attributes.push_back((*it).name_);
    share_attributes.push_back((*it).msid_);
    share_attributes.push_back((*it).msid_pub_key_);
    share_attributes.push_back((*it).msid_priv_key_);
    share_stats.push_back((*it).rank_);
    share_stats.push_back((*it).last_view_);
  } else {
    typedef private_share_set::index<private_share_msid>::type
            private_share_set_by_msid;
    private_share_set_by_msid& private_share_index =
        pss_.get<private_share_msid>();
    private_share_set_by_msid::iterator it = private_share_index.find(msid);
    if (it == private_share_index.end())
      return -2014;
    share_attributes.push_back((*it).name_);
    share_attributes.push_back((*it).msid_);
    share_attributes.push_back((*it).msid_pub_key_);
    share_attributes.push_back((*it).msid_priv_key_);
    share_stats.push_back((*it).rank_);
    share_stats.push_back((*it).last_view_);
  }
  std::list<ShareParticipants> sps;
  typedef private_share_participant_set::index<share_participant_msid>::type
          private_share_participant_set_msid;
  private_share_participant_set_msid& private_share_participant_index =
      psps_.get<share_participant_msid>();
  private_share_participant_set_msid::iterator it =
       private_share_participant_index.find(msid);

  while (it != private_share_participant_index.end() && (*it).msid_ == msid) {
    ShareParticipants sp;
    sp.id = (*it).public_name_;
    sp.public_key = (*it).public_key_;
    sp.role = (*it).role_;
    sps.push_back(sp);
    it++;
  }

  ps->Construct(share_attributes, share_stats, sps);

  return 0;
}

int PrivateShareHandler::MI_GetShareList(
    std::list<maidsafe::private_share> *ps_list,
    const SortingMode &sm, const ShareFilter &sf) {
  ps_list->clear();
  switch (sm) {
    case ALPHA:
      {
        typedef private_share_set::index<private_share_name>::type
                private_share_set_name;
        private_share_set_name& private_share_index =
            pss_.get<private_share_name>();
        for (private_share_set_name::iterator it = private_share_index.begin();
             it != private_share_index.end(); ++it) {
          private_share pr((*it).name_, (*it).msid_, (*it).msid_pub_key_,
                          (*it).msid_priv_key_);
          pr.rank_ = (*it).rank_;
          pr.last_view_ = (*it).last_view_;
          DecideInclusion(pr, sf, ps_list);
//          ps_list->push_back(pr);
        }
      }
      break;
    case RANK:
      {
        typedef private_share_set::index<private_share_rank>::type
                private_share_set_rank;
        private_share_set_rank& private_share_index =
            pss_.get<private_share_rank>();
        for (private_share_set_rank::iterator it = private_share_index.begin();
             it != private_share_index.end(); ++it) {
          private_share pr((*it).name_, (*it).msid_, (*it).msid_pub_key_,
                          (*it).msid_priv_key_);
          pr.rank_ = (*it).rank_;
          pr.last_view_ = (*it).last_view_;
          DecideInclusion(pr, sf, ps_list);
//          ps_list->push_back(pr);
        }
      }
      break;
    case LAST:
      {
        typedef private_share_set::index<private_share_view>::type
                private_share_set_view;
        private_share_set_view& private_share_index =
            pss_.get<private_share_view>();
        for (private_share_set_view::iterator it = private_share_index.begin();
             it != private_share_index.end(); ++it) {
          private_share pr((*it).name_, (*it).msid_, (*it).msid_pub_key_,
                          (*it).msid_priv_key_);
          pr.rank_ = (*it).rank_;
          pr.last_view_ = (*it).last_view_;
          DecideInclusion(pr, sf, ps_list);
//          ps_list->push_back(pr);
        }
        break;
      }
  }
  return 0;
}

int PrivateShareHandler::MI_GetFullShareList(const SortingMode &sm,
                                              const ShareFilter &sf,
                                             std::list<PrivateShare> *ps_list) {
  ps_list->clear();
  std::list<private_share> share_list;
  MI_GetShareList(&share_list, sm, sf);
  while (!share_list.empty()) {
    PrivateShare ps;
    MI_GetShareInfo(share_list.front().msid_, 1, &ps);
    ps_list->push_back(ps);
    share_list.pop_front();
  }
  return 0;
}

int PrivateShareHandler::MI_GetParticipantsList(const std::string &value,
    const int &field, std::list<share_participant> *sp_list) {
  sp_list->clear();
  if (field < 0 || field > 1)
    return -2015;
  std::string msid(value);
  if (field == 0) {
    typedef private_share_set::index<private_share_name>::type
            private_share_set_by_name;
    private_share_set_by_name& private_share_index =
        pss_.get<private_share_name>();
    private_share_set_by_name::iterator it = private_share_index.find(value);
    if (it == private_share_index.end())
      return -2015;
    msid = (*it).msid_;
  }

  typedef private_share_participant_set::index<share_participant_msid>::type
          private_share_participant_set_msid;
  private_share_participant_set_msid& private_share_participant_index =
      psps_.get<share_participant_msid>();
  private_share_participant_set_msid::iterator it =
      private_share_participant_index.find(msid);

  while (it != private_share_participant_index.end() && (*it).msid_ == msid) {
    share_participant sp((*it).msid_, (*it).public_name_, (*it).public_key_,
                        (*it).role_);
    sp_list->push_back(sp);
    it++;
  }
  if (sp_list->empty())
    return -2015;
  return 0;
}

void PrivateShareHandler::MI_ClearPrivateShares() {
  pss_.clear();
  psps_.clear();
}

void PrivateShareHandler::DecideInclusion(
    const private_share &ps, const ShareFilter &sf,
    std::list<maidsafe::private_share> *ps_list) {
  bool ro(false);
  if (ps.msid_priv_key_ == "")
    ro = true;
  switch (sf) {
    case kAll: ps_list->push_back(ps);
          break;
    case kRo: if (ro)
           ps_list->push_back(ps);
         break;
    case kAdmin: if (!ro)
              ps_list->push_back(ps);
  }
}


}  // namespace maidsafe
