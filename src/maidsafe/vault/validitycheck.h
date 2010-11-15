/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Runs validity checks on chunks stored in vault against their
*               duplicates on the net to ensure they aren't corrupt/missing.
* Version:      1.0
* Created:      2009-03-17-01.49.48
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

#ifndef MAIDSAFE_VAULT_VALIDITYCHECK_H_
#define MAIDSAFE_VAULT_VALIDITYCHECK_H_
/*
#include <boost/filesystem.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/cstdint.hpp>
#include <string>
#include <vector>
#include <list>

#include "maidsafe/common/cppsqlite3.h"
#include "maidsafe/vault/pdvault.h"

typedef boost::tuple<std::string, std::string> str_tuple;

namespace maidsafe {

namespace vault {

struct NodeChunkPair {
  std::string partner_info;
  std::string chunk_name;
};

struct IterativeCheckData {
  std::list<NodeChunkPair> check_list;
};

class ValCheck {
 public:
  ValCheck(const boost::shared_ptr<PDVault> pdvault,
           const std::string &chunkstore_dir);
  // Starts de validity check process
/*  bool Start(bool reuse_database);
  // Stops de validity check process and closes DB
  bool Stop();
  // Callback for receiving the result of the RPCValidityCheck
  void CheckValidity_Callback(const dht::entry &result,
                              const std::string &node_id,
                              const std::string &chunk_name,
                              const std::string &random_data,
                              const int &retry);
  // Get the list of corrupted chunks detected
  // the vector contains entry tuples (id, chunkname)
  bool GetCurruptChunks(std::vector<str_tuple> *corrupt_chunks);
  // Add a chunk to be validated
  void AddChunkToCheck(const std::string &chunk_name);
  // Removes all the partners of a chunk from the DB
  bool RemoveChunkFromList(const std::string &chunk_name);
  // Removes a specific partner of a chunk
  bool RemoveChunkFromList(const std::string &chunk_name,
    const std::string &node_id);
  void AddChunkToCheck_Callback(const dht::entry &result,
    const std::string &chunk_name);
  void ValCheckProcess();  // return later to private
  // Checks if the (node_id, chunk_name) exist in the DB
  bool PartnerExists(const std::string &node_id,
    const std::string &chunk_name);

 private:
  // operation to be called to check the chunks
  bool EnoughCopies(const std::string &chunk_name);
  void DirtyChunkHandler(const std::string &chunk_name,
    const std::string &node_id);
  void AddChunkandParnerToDB(const std::string &node_id,
    const std::string &chunk_name);
  void FindNodeId_Callback(const dht::entry &result,
    const std::string &node_id, const std::string &chunk_name,
    const bool &local);
  boost::filesystem::path db_path_;
  boost::shared_ptr<PDVault> pdvault_;
  CppSQLite3DB db_;
  bool started_;
 private:
  ValCheck(const ValCheck&);
  ValCheck &operator=(const ValCheck&);
};
}  // namespace vault

}  // namespace maidsafe
*/
#endif  // MAIDSAFE_VAULT_VALIDITYCHECK_H_
