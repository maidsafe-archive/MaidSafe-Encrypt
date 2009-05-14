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

#include "base/cppsqlite3.h"
#include "base/utils.h"
#include "maidsafe/client/messagehandler.h"

//  Return codes: based on 2200
//   0: Success
//  -2201: Can't connect to private share DB
//  -2202: Didn't delete pointer db_
//  -2203: Wrong parameters for GetPrivateShareList
//  -2204: GetPrivateShareList failed
//  -2205: AddPrivateShare failed
//  -2206: AddReceivedShare failed
//  -2207: DeletePrivateShare failed
//  -2208: AddContactsToPrivateShare failed
//  -2209: DeleteContactsFromPrivateShare failed

namespace maidsafe {

struct ShareParticipants {
  ShareParticipants() : id(""), public_key(), role('R') {}
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
  int Connect(const std::string &dbName);
  int Close();

 public:
  PrivateShareHandler() : db_() { }
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
    const std::string &value, const int &field);
  int AddContactsToPrivateShare(const std::string &dbName,
    std::list<ShareParticipants> *participants,
    const std::string &value, const int &type);
  int DeleteContactsFromPrivateShare(const std::string &dbName,
    std::list<ShareParticipants> *participants);
};

}  // namespace

#endif  // MAIDSAFE_CLIENT_PRIVATESHARES_H_
