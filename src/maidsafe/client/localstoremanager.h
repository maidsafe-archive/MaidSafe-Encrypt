/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Manages data storage to local database (for testing)
* Version:      1.0
* Created:      2009-01-29-00.06.15
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

#ifndef MAIDSAFE_CLIENT_LOCALSTOREMANAGER_H_
#define MAIDSAFE_CLIENT_LOCALSTOREMANAGER_H_

#include <string>

#include "boost/filesystem.hpp"
#include "boost/thread/mutex.hpp"

#include "base/cppsqlite3.h"
#include "maidsafe/client/storemanager.h"
#include "maidsafe/vault/vaultbufferpackethandler.h"

namespace maidsafe {

class LocalStoreManager : public StoreManagerInterface {
 public:
  explicit LocalStoreManager(boost::recursive_mutex *mutex);
  inline LocalStoreManager &operator=(const LocalStoreManager & ) {
    return *this;
    }
  inline LocalStoreManager(const LocalStoreManager & res);


  virtual void StoreChunk(const std::string &chunk_name,
                          const std::string &content,
                          const std::string &signature,
                          const std::string &public_key,
                          const std::string &signed_public_key,
                          base::callback_func_type cb);
  virtual void LoadChunk(const std::string &chunk_name,
                         base::callback_func_type cb);
  virtual void Init(base::callback_func_type cb);
  virtual void Close(base::callback_func_type cb);
  virtual void IsKeyUnique(const std::string &key, base::callback_func_type cb);
  virtual void StorePacket(const std::string &key,
                           const std::string &value,
                           const std::string &signature,
                           const std::string &public_key,
                           const std::string &signed_public_key,
                           const value_types &type,
                           bool update,
                           base::callback_func_type cb);
  virtual void LoadPacket(const std::string &key, base::callback_func_type cb);
  virtual void DeletePacket(const std::string &key,
                            const std::string &signature,
                            const std::string &public_key,
                            const std::string &signed_public_key,
                            const value_types &type,
                            base::callback_func_type cb);
  virtual void GetMessages(const std::string &key,
                           const std::string &public_key,
                           const std::string &signed_public_key,
                           base::callback_func_type cb);

 private:
  CppSQLite3DB db_;
  packethandler::VaultBufferPacketHandler vbph_;
  crypto::Crypto crypto_obj_;
  boost::recursive_mutex *mutex_;
  bool ValidateGenericPacket(std::string ser_gp, std::string public_key);
  // bool AddMessageToBufferPacket(std::string &key,
  //                               std::string &value,
  //                               std::string &public_key);
  bool ModifyBufferPacketInfo(const std::string &key,
                              std::string *value,
                              const std::string &public_key);
  void StorePacket_InsertToDb(const std::string &key,
                              const std::string &value,
                              base::callback_func_type cb);
  std::string GetValue_FromDB(const std::string &key);
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_LOCALSTOREMANAGER_H_
