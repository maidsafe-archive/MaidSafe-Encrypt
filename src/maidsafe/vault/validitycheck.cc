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

#include "maidsafe/vault/validitycheck.h"
#include <boost/bind.hpp>
#include <maidsafe/base/utils.h>
#include <maidsafe/base/crypto.h>
#include <list>

namespace fs = boost::filesystem;

namespace maidsafe_vault {

ValCheck::ValCheck(
                  const boost::shared_ptr<PDVault> pdvault,
                  const std::string &chunkstore_dir)
        : db_path_(chunkstore_dir, fs::native),
          pdvault_(pdvault),
          db_(), started_(false) {
  db_path_ /= "valchk.db";
}
/*
bool ValCheck::Start(bool reuse_database) {

  std::string fname_str = db_path_.file_string();

  if (!reuse_database) {
    std::cout << "removing old database" << std::endl;
    fs::remove(db_fname_);
  }
  try{
    // creating DB if it doesn't exist
    if (!fs::exists(db_fname_)) {
      db_.open(fname_str.c_str());
      db_.execDML("create table validity_check(partner_info blob, chunk_name blob, \
          last_checked_time integer, interval_check integer, status char(1), \
          primary key(partner_info, chunk_name));");
    }
    else{
      std::cout << "trying to open database" << std::endl;
      db_.open(fname_str.c_str());
    }
  }
  catch (CppSQLite3Exception& e){
    // std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    return false;
  }
  timer_->AddCallLater(kVadilityCheckInterval, \
    boost::bind(&ValCheck::ValCheckProcess, this));
  started_ = true;
  return true;
}

bool ValCheck::Stop() {
  try {
    db_.close();
  }
  catch (CppSQLite3Exception& e){
    // std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    return false;
  }
  started_ = false;
  return true;
}

bool ValCheck::GetCurruptChunks(std::vector<str_tuple> *corrupt_chunks) {
  corrupt_chunks->clear();
  std::string s("select partner_info, chunk_name from validity_check where");
  s += "status='" + DIRTY + "';";
  CppSQLite3Query qcpp = db_.execQuery(s.c_str());
  while (!qcpp.eof()) {
    try {
      CppSQLite3Binary blob_node_id, blob_chunk_name;
      blob_node_id.setEncoded((unsigned char*)qcpp.fieldValue(0));
      blob_chunk_name.setEncoded((unsigned char*)qcpp.fieldValue(1));
      std::string node_id((const char*)blob_node_id.getBinary(),
        blob_node_id.getBinaryLength());
      std::string chunk_name((const char*)blob_chunk_name.getBinary(),
        blob_chunk_name.getBinaryLength());
      str_tuple row(node_id, chunk_name);
      corrupt_chunks->push_back(row);
    }
    catch(std::exception& e){
        qcpp.nextRow();
        continue;
    }
    qcpp.nextRow();
  }
  return true;
}

void ValCheck::AddChunkandParnerToDB(const std::string &partner_info,
  const std::string &chunk_name) {
  try{
    CppSQLite3Binary blob_node_id, blob_chunk_name;
    blob_partner.setBinary((const unsigned char*)partner_info.c_str(),
      node_id.size());
    blob_chunk_name.setBinary((const unsigned char*)chunk_name.c_str(),
      chunk_name.size());
    CppSQLite3Statement stmt;
    stmt = db_.compileStatement("insert into validity_check values(?, ?, ?, ?, ?);");
    stmt.bind(1, (const char*)blob_partner.getEncoded());
    stmt.bind(2, (const char*)blob_chunk_name.getEncoded());
    stmt.bind(3, 0);
    stmt.bind(4, vchMinTime);
    stmt.bind(5, CORRECT.c_str());
    stmt.execDML();
    stmt.reset();
  }
  catch (CppSQLite3Exception& e){
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
  }
}

bool ValCheck::RemoveChunkFromList(const std::string &chunk_name) {
  try{
    CppSQLite3Binary blob_chunk_name;
    blob_chunk_name.setBinary((const unsigned char*)chunk_name.c_str(),
      chunk_name.size());
    CppSQLite3Statement stmt;
    stmt = db_.compileStatement(\
        "delete from validity_check where chunk_name=?;");
    stmt.bind(1, (const char*)blob_chunk_name.getEncoded());
    stmt.execDML();
    stmt.reset();
  }
  catch (CppSQLite3Exception& e){
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    return false;
  }
  return true;
}

bool ValCheck::RemoveChunkFromList(const std::string &chunk_name,
  const std::string &partner_info) {
  try{
    CppSQLite3Binary blob_chunk_name, blob_node_id;
    blob_chunk_name.setBinary((const unsigned char*)chunk_name.c_str(),
      chunk_name.size());
    blob_partner.setBinary((const unsigned char*)partner_info.c_str(),
      node_id.size());
    CppSQLite3Statement stmt;
    stmt = db_.compileStatement("delete from validity_check where partner_info=? and chunk_name=?;");
    stmt.bind(1, (const char*)blob_partner.getEncoded());
    stmt.bind(2, (const char*)blob_chunk_name.getEncoded());
    stmt.execDML();
    stmt.reset();
  }
  catch (CppSQLite3Exception& e){
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    return false;
  }
  return true;
}

void ValCheck::AddChunkToCheck(const std::string &chunk_name) {
  // Add this in a call later --delay for 5 min to make sure all chunk
  // references are there
  base::callback_func cb = boost::bind(&ValCheck::AddChunkToCheck_Callback,this, _1, chunk_name);
  timer_->AddCallLater(kCheckPartnerRefDelay, \
    boost::bind(&KNode::FindValue, node_, _1, chunk_name, cb));
}

void ValCheck::AddChunkToCheck_Callback(const dht::entry &result,
  const std::string &chunk_name) {
  if (result.type != dht::entry::dictionary_t ||\
    result.find_key("result") == NULL) {
    // invalid result
    return;
  }
  if (result["result"].string() == kNack) {
    std::cout << "--RPCResult is Failure" << std::endl;
    return;
  }
  std::list<dht::entry> values = result["values"].list();
  if (values.empty()) {
    std::cout << "--No partners found" << std::endl;
    return;
  }

  while (!values.empty()) {
    std::string partner_info = values.front().string();
    values.pop_front();
    Contact partner;
    if (partner.ParseFromString(partner_info)) {
      if (partner.node_id() != node_->node_id())
        AddChunkandParnerToDB(partner_info, chunk_name);
    }
  }
}

void ValCheck::CheckValidity_Callback(const dht::entry &result,
  const std::string &node_id, const std::string &chunk_name,
  const std::string &random_data, const int &retry) {
  std::string hcontent;
  std::string chunkstatus = DIRTY;
  if (result["result"].string() == kAck) {
    std::string remote_hash = result["hashcontent"].string();
    std::string content;
    crypto::Crypto cry_obj;
    cry_obj.set_symm_algorithm(crypto::AES_256);
    cry_obj.set_hash_algorithm(crypto::SHA_512);
    node_->ReadChunkContent(chunk_name, content);
    hcontent = cry_obj.Hash(content+random_data,"",crypto::STRING_STRING,false);
    if (hcontent == remote_hash)
      chunkstatus = CORRECT;
  }
  // Update the DB only if passed the number of retries
  // retries are only for timeouts, not incorrect hashes
  if ((result["result"].string() == kAck) || retry < vchRetry) {
    try {
      boost::int32_t curr_time = base::GetEpochTime();
      CppSQLite3Statement stmt;
      CppSQLite3Binary blob_node_id, blob_chunk_name;
      blob_node_id.setBinary((const unsigned char*)node_id.c_str(),
        node_id.size());
      blob_chunk_name.setBinary((const unsigned char*)chunk_name.c_str(),
        chunk_name.size());
      stmt = db_.compileStatement("update validity_check set status = ?, \
        last_checked_time = ? where node_id = ? and chunk_name = ?;");
      stmt.bind(1, chunkstatus.c_str());
      stmt.bind(2, (int)curr_time);
      stmt.bind(3, (const char*)blob_node_id.getEncoded());
      stmt.bind(4, (const char*)blob_chunk_name.getEncoded());
      stmt.execDML();
    }
    catch (CppSQLite3Exception& e) {
      std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    }
    DirtyChunkHandler(chunk_name, node_id);
  }
  else {
    // TODO reschedule the send validity check
    int local_retry = retry+1;
  }

}

bool ValCheck::EnoughCopies(const std::string &chunk_name) {
  try {
    CppSQLite3Binary blob_chunk_name;
    blob_chunk_name.setBinary((const unsigned char*)chunk_name.c_str(),
      chunk_name.size());
    CppSQLite3Statement stmt = db_.compileStatement(\
      "select count(*) from validity_check where chunk_name = ? \
       and status = ?;");
    stmt.bind(1, (const char*)blob_chunk_name.getEncoded());
    stmt.bind(2, (const char*)CORRECT.c_str());
    CppSQLite3Query qcpp = stmt.execQuery();
    if (qcpp.getIntField(0) < MinChunkCopies-1)
      return false;
  }
  catch (CppSQLite3Exception& e){
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    return false;
  }
  return true;
}

void ValCheck::DirtyChunkHandler(const std::string &chunk_name,
  const std::string &node_id) {
  if (EnoughCopies(chunk_name)) {
    std::cout << "enough copies" << std::endl;
    return;
  }
  // Getting the partners
  std::vector<std::string> partners;
  try {
    CppSQLite3Binary blob_chunk_name, blob_node_id;
    blob_chunk_name.setBinary((const unsigned char*)chunk_name.c_str(),
      chunk_name.size());
    blob_node_id.setBinary((const unsigned char*)node_id.c_str(),
      chunk_name.size());
    CppSQLite3Statement stmt = db_.compileStatement(\
      "select chunk_name from validity_check where chunk_name=? and node_id <>?;");
    stmt.bind(1, (const char*)blob_chunk_name.getEncoded());
    stmt.bind(2, (const char*)blob_node_id.getEncoded());
    CppSQLite3Query qcpp = stmt.execQuery();
    while(!qcpp.eof()){
      try{
        CppSQLite3Binary blob_node_id;
        blob_node_id.setEncoded((unsigned char*)qcpp.fieldValue(0));
        std::string partner_id((const char*)blob_node_id.getBinary(),
          blob_node_id.getBinaryLength());
        partners.push_back(partner_id);
        qcpp.nextRow();
      }
      catch(std::exception& e){
        qcpp.nextRow();
        continue;
      }
    }
  }
  catch (CppSQLite3Exception& e){
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
  }
  // TODO call duplicate chunk of node_
  // TODO define if from here it calls the supernode or does something
  // with an accusation
  std::cout << "Not enough copies" << std::endl;
  std::cout << "size of CORRECT partner: " << partners.size() << std::endl;
}

void ValCheck::ValCheckProcess() {
  boost::int32_t lastchecked = base::GetEpochTime() - vchMinTime;
  boost::shared_ptr<IterativeCheckData> \
    data(new struct IterativeCheckData);
  try {
    CppSQLite3Statement stmt = db_.compileStatement(\
      "select *from validity_check where last_checked_time < ?;");
    stmt.bind(1, lastchecked);
    CppSQLite3Query qcpp = stmt.execQuery();
    while(!qcpp.eof()){
      try{
        CppSQLite3Binary blob_chunk_name, blob_partner;
        blob_partner.setEncoded((unsigned char*)qcpp.fieldValue(0));
        blob_chunk_name.setEncoded((unsigned char*)qcpp.fieldValue(1));
        std::string partner_info((const char*)blob_node_id.getBinary(),
          blob_node_id.getBinaryLength());
        std::string chunk_name((const char*)blob_chunk_name.getBinary(),
          blob_chunk_name.getBinaryLength());
        // add to the check list
        struct NodeChunkPair node_chunk_pair;
        node_chunk_pair.partner_info = partner_info;
        node_chunk_pair.chunk_name = chunk_name;
        data->check_list.push_back(node_chunk_pair);
        qcpp.nextRow();
      }
      catch(std::exception& e){
        qcpp.nextRow();
        continue;
      }
    }
  }
  catch(CppSQLite3Exception& e){
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
  }
  IterativeCheck(data);
}

void ValCheck::IterativeCheck(boost::shared_ptr<IterativeCheckData> data){
  if (!data->check_list.empty()){
    struct NodeChunkPair node_chunk_pair = data->check_list.back();
    data->check_list.pop_back();
    Contact partner;
    if (partner.ParseFromString(node_chunk_pair.partner_info)){
      node_->ValidityCheck(partner, node_chunk_pair.chunk_name, \
        boost::bind(&ValCheck::IterativeCheck_Callback, this, _1, data));
    }
    else{
      // invalid partner info, go for the next
      IterativeCheck(data);
    }
  }
  else{
    // Checking process done! Schedule the next round
    timer_->AddCallLater(kVadilityCheckInterval, \
      boost::bind(&ValCheck::ValCheckProcess, this));
  }
}

void ValCheck::IterativeCheck_Callback(const dht::entry &result, \
  boost::shared_ptr<IterativeCheckData> data){
  if (result["result"].string() == kAck){
    // valid chunk and partner
    IterativeCheck(data);
  }
  else{
    // invalid chunk
  }
}

bool ValCheck::PartnerExists(const std::string &node_id,
  const std::string &chunk_name) {
  try {
    CppSQLite3Binary blob_node_id, blob_chunk_name;
    blob_chunk_name.setBinary((const unsigned char*)chunk_name.c_str(),
      chunk_name.size());
    blob_node_id.setBinary((const unsigned char*)node_id.c_str(),
      node_id.size());
    CppSQLite3Statement stmt = db_.compileStatement(\
      "select count(*) from validity_check where node_id = ? \
       and chunk_name = ?;");
    stmt.bind(1, (const char*)blob_node_id.getEncoded());
    stmt.bind(2, (const char*)blob_chunk_name.getEncoded());
    CppSQLite3Query qcpp = stmt.execQuery();
    if (qcpp.getIntField(0) < 1)
      return false;
  }
  catch (CppSQLite3Exception& e){
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    return false;
  }
  return true;
}
*/
}  // namespace maidsafe_vault
