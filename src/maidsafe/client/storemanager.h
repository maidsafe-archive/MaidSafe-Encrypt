/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Interface allowing storage of data to network or local database
* Version:      1.0
* Created:      2009-01-29-00.49.17
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

#ifndef MAIDSAFE_CLIENT_STOREMANAGER_H_
#define MAIDSAFE_CLIENT_STOREMANAGER_H_

#include <string>

#include "maidsafe/maidsafe.h"
#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/utils.h"

namespace maidsafe {

class StoreManagerInterface {
 public:
  virtual void StoreChunk(const std::string &chunk_name,
                          const std::string &content,
                          const std::string &signature,
                          const std::string &public_key,
                          const std::string &signed_public_key,
                          base::callback_func_type cb)=0;
  virtual void LoadChunk(const std::string &chunk_name,
                         base::callback_func_type cb)=0;
  virtual void Init(base::callback_func_type cb)=0;
  virtual void Close(base::callback_func_type cb)=0;
  virtual void IsKeyUnique(const std::string &key,
                           base::callback_func_type cb)=0;
  virtual void StorePacket(const std::string &key,
                           const std::string &value,
                           const std::string &signature,
                           const std::string &public_key,
                           const std::string &signed_public_key,
                           const value_types &type,
                           bool update,
                           base::callback_func_type cb)=0;
  virtual void LoadPacket(const std::string &key,
                          base::callback_func_type cb)=0;
  virtual void DeletePacket(const std::string &key,
                            const std::string &signature,
                            const std::string &public_key,
                            const std::string &signed_public_key,
                            const value_types &type,
                            base::callback_func_type cb)=0;

  // The public_key is the one of the MPID and is signed by the MPID's
  // private key
  virtual void GetMessages(const std::string &key,
                           const std::string &public_key,
                           const std::string &signed_public_key,
                           base::callback_func_type cb)=0;

  virtual ~StoreManagerInterface() {}
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_STOREMANAGER_H_
