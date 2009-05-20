/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Manages data storage to Maidsafe network
* Version:      1.0
* Created:      2009-01-28-23.53.44
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

#ifndef MAIDSAFE_CLIENT_MAIDSTOREMANAGER_H_
#define MAIDSAFE_CLIENT_MAIDSTOREMANAGER_H_

#include <string>
#include <vector>

#include "maidsafe/client/pdclient.h"
#include "maidsafe/client/storemanager.h"
#include "maidsafe/crypto.h"

namespace maidsafe {

class MaidsafeStoreManager : public StoreManagerInterface {
 public:
  explicit MaidsafeStoreManager(boost::recursive_mutex *mutex);
  ~MaidsafeStoreManager();
  void StoreChunk(const std::string &chunk_name,
                  const std::string &content,
                  const std::string &signature,
                  const std::string &public_key,
                  const std::string &signed_public_key,
                  base::callback_func_type cb);
  void LoadChunk(const std::string &chunk_name,
                 base::callback_func_type cb);
  void Init(base::callback_func_type cb);
  void Close(base::callback_func_type cb);
  void IsKeyUnique(const std::string &key,
                   base::callback_func_type cb);
  void StorePacket(const std::string &key,
                   const std::string &value,
                   const std::string &signature,
                   const std::string &public_key,
                   const std::string &signed_public_key,
                   const value_types &type,
                   bool update,
                   base::callback_func_type cb);
  void LoadPacket(const std::string &key, base::callback_func_type cb);
  void DeletePacket(const std::string &key,
                    const std::string &signature,
                    const std::string &public_key,
                    const std::string &signed_public_key,
                    const value_types &type,
                    base::callback_func_type cb);
  void GetMessages(const std::string &key,
                   const std::string &public_key,
                   const std::string &signed_public_key,
                   base::callback_func_type cb);

 private:
  MaidsafeStoreManager &operator=(const MaidsafeStoreManager&) {
    return *this;
  }
  MaidsafeStoreManager(const MaidsafeStoreManager&);
//  bool GetBootstrappingNodes(std::vector<kad::Contact> *bs_contacts);
  void LoadChunk_Callback(const std::string &result,
                          base::callback_func_type cb);
  void SimpleResult_Callback(const std::string &result,
                             base::callback_func_type cb);
  void IsKeyUnique_Callback(const std::string &result,
                            base::callback_func_type cb);
  void GetMsgs_Callback(const std::string &result, base::callback_func_type cb);
  void StoreChunk_Callback(const std::string &result,
                           const bool &update,
                           base::callback_func_type cb);
  void DeleteChunk_Callback(const std::string &result,
                            base::callback_func_type cb);
  std::string datastore_dir_;
  PDClient *pdclient_;
  crypto::Crypto cry_obj;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_MAIDSTOREMANAGER_H_
