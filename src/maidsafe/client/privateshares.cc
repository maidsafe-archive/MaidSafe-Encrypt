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
    participants_(0) {
}

PrivateShare::PrivateShare(const std::vector<std::string> &attributes,
    std::list<ShareParticipants> participants) : name_(attributes[0]),
    msid_(attributes[1]), msid_pub_key_(attributes[2]),
    msid_priv_key_(attributes[3]),
    participants_(participants) {
}

void PrivateShare::Construct(const std::vector<std::string> &attributes,
                             std::list<ShareParticipants> participants) {
    name_ = attributes[0];
    msid_ = attributes[1];
    msid_pub_key_ = attributes[2];
    msid_priv_key_ = attributes[3];
    participants_ = participants;
}

// PrivateShareHandler

// Multi Index
int PrivateShareHandler::MI_AddPrivateShare(
    const std::vector<std::string> &attributes,
    std::list<ShareParticipants> *participants) {
  if (attributes.size() != 4)
    return -2010;

  bool ro_participation = false;
  if (attributes[3] == "" && participants->empty())
    ro_participation = true;

  private_share ps(attributes[0], attributes[1], attributes[2], attributes[3]);
  pss_.insert(ps);

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

int PrivateShareHandler::MI_GetShareInfo(const std::string &value,
    const int &field, PrivateShare *ps) {
  if (field < 0 || field > 1)
    return -2014;
  std::string msid(value);
  std::vector<std::string> share_attributes;
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

  ps->Construct(share_attributes, sps);

  return 0;
}

int PrivateShareHandler::MI_GetShareList(
    std::list<maidsafe::private_share> *ps_list) {
  ps_list->clear();
  typedef private_share_set::index<private_share_name>::type
          private_share_set_name;
  private_share_set_name& private_share_index =
      pss_.get<private_share_name>();
  for (private_share_set_name::iterator it = private_share_index.begin();
       it != private_share_index.end(); it++) {
    private_share pr((*it).name_, (*it).msid_, (*it).msid_pub_key_,
                    (*it).msid_priv_key_);
    ps_list->push_back(pr);
  }
//  ps_list->reset(new std::list<private_share>(private_share_index.begin(),
//           private_share_index.end()));
  return 0;
}

int PrivateShareHandler::MI_GetFullShareList(std::list<PrivateShare> *ps_list) {
  ps_list->clear();
  std::list<private_share> share_list;
  MI_GetShareList(&share_list);
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

}  // namespace maidsafe
