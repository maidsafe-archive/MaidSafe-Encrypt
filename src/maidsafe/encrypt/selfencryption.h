/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Self-encrypts/self-decrypts files
* Version:      1.0
* Created:      09/09/2008 12:14:35 PM
* Revision:     none
* Compiler:     gcc
* Author:       David Irvine (di), david.irvine@maidsafe.net
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

#ifndef MAIDSAFE_ENCRYPT_SELFENCRYPTION_H_
#define MAIDSAFE_ENCRYPT_SELFENCRYPTION_H_

#include <boost/filesystem.hpp>

#include <map>
#include <string>

namespace fs = boost::filesystem;

namespace maidsafe {

namespace test {
class SelfEncryptionTest_BEH_MAID_CheckEntry_Test;
class SelfEncryptionTest_BEH_MAID_CreateProcessDirectory_Test;
class SelfEncryptionTest_BEH_MAID_CheckCompressibility_Test;
class SelfEncryptionTest_BEH_MAID_CalculateChunkSizes_Test;
class SelfEncryptionTest_BEH_MAID_ChunkAddition_Test;
class SelfEncryptionTest_BEH_MAID_GeneratePreEncHashes_Test;
class SelfEncryptionTest_BEH_MAID_HashUnique_Test;
class SelfEncryptionTest_BEH_MAID_ResizeObfuscationHash_Test;
class SelfEncryptionTest_BEH_MAID_SelfEncryptFiles_Test;
class SelfEncryptionTest_BEH_MAID_DecryptFile_Test;
}  // namespace test

class DataIOHandler;
class DataMap;

const std::string kNoCompressType[] = { ".jpg", ".jpeg", ".jpe", ".jfif",
  ".gif", ".png", ".mp3", ".mp4", ".0", ".000", ".7z", ".ace", ".ain", ".alz",
  ".apz", ".ar", ".arc", ".ari", ".arj", ".axx", ".ba", ".bh", ".bhx", ".boo",
  ".bz", ".bz2", ".bzip2", ".c00", ".c01", ".c02", ".car", ".cbr", ".cbz",
  ".cp9", ".cpgz", ".cpt", ".dar", ".dd", ".deb", ".dgc", ".dist", ".ecs",
  ".efw", ".fdp", ".gca", ".gz", ".gzi", ".gzip", ".ha", ".hbc", ".hbc2",
  ".hbe", ".hki", ".hki1", ".hki2", ".hki3", ".hpk", ".hyp", ".ice", ".ipg",
  ".ipk", ".ish", ".j", ".jgz", ".jic", ".kgb", ".lbr", ".lha", ".lnx", ".lqr",
  ".lzh", ".lzm", ".lzma", ".lzo", ".lzx", ".md", ".mint", ".mpkg", ".mzp",
  ".p7m", ".package", ".pae", ".pak", ".paq6", ".paq7", ".paq8", ".par",
  ".par2", ".pbi", ".pcv", ".pea", ".pf", ".pim", ".pit", ".piz", ".pkg",
  ".pup", ".puz", ".pwa", ".qda", ".r00", ".r01", ".r02", ".r03", ".rar",
  ".rev", ".rk", ".rnc", ".rpm", ".rte", ".rz", ".rzs", ".s00", ".s01", ".s02",
  ".s7z", ".sar", ".sdn", ".sea", ".sen", ".sfs", ".sfx", ".sh", ".shar",
  ".shk", ".shr", ".sit", ".sitx", ".spt", ".sqx", ".sqz", ".tar", ".tbz2",
  ".tgz", ".tlz", ".uc2", ".uha", ".vsi", ".wad", ".war", ".wot", ".xef",
  ".xez", ".xpi", ".xx", ".y", ".yz", ".z", ".zap", ".zfsendtotarget", ".zip",
  ".zix", ".zoo", ".zz"
};

namespace self_encryption_utils {
  // Generate a string of required_size from input in a repeatable way
  bool ResizeObfuscationHash(const std::string &input,
                             const size_t &required_size,
                             std::string *resized_data);
}  // namespace self_encryption_utils

class SelfEncryption {
 public:
  SelfEncryption();
  ~SelfEncryption() {}
  // encrypt entire file
  int Encrypt(const std::string &entry_str, bool is_string, DataMap *dm);
  // decrypt chunks starting at chunklet spanning offset point
  int Decrypt(const DataMap &dm,
              const std::string &entry_str,
              const boost::uint64_t &offset,
              bool overwrite);
  int Decrypt(const DataMap &dm,
              const boost::uint64_t &offset,
              std::string *decrypted_str);
  std::string SHA512(const fs::path &file_path);
  std::string SHA512(const std::string &content);
  fs::path GetChunkPath(const std::string &chunk_name);
  friend class test::SelfEncryptionTest_BEH_MAID_CheckEntry_Test;
  friend class test::SelfEncryptionTest_BEH_MAID_CreateProcessDirectory_Test;
  friend class test::SelfEncryptionTest_BEH_MAID_CheckCompressibility_Test;
  friend class test::SelfEncryptionTest_BEH_MAID_CalculateChunkSizes_Test;
  friend class test::SelfEncryptionTest_BEH_MAID_ChunkAddition_Test;
  friend class test::SelfEncryptionTest_BEH_MAID_GeneratePreEncHashes_Test;
  friend class test::SelfEncryptionTest_BEH_MAID_HashUnique_Test;
  friend class test::SelfEncryptionTest_BEH_MAID_ResizeObfuscationHash_Test;
  friend class test::SelfEncryptionTest_BEH_MAID_SelfEncryptFiles_Test;
  friend class test::SelfEncryptionTest_BEH_MAID_DecryptFile_Test;
 private:
  int Decrypt(const DataMap &dm,
              const boost::uint64_t &offset,
              const std::string &path,
              boost::shared_ptr<DataIOHandler> iohandler,
              std::string *decrypted_str);
  // check to ensure entry is encryptable
  int CheckEntry(boost::shared_ptr<DataIOHandler> iohandler);
  bool CreateProcessDirectory(fs::path *processing_path);
  bool CheckCompressibility(const std::string &path,
                            boost::shared_ptr<DataIOHandler> iohandler);
  bool CalculateChunkSizes(boost::shared_ptr<DataIOHandler> iohandler,
                           DataMap *dm);
  // returns a positive or negative int based on char passed into it to
  // allow for random chunk sizes '0' returns -8, '1' returns -7, etc...
  // through to 'f' returns 7
  int ChunkAddition(char hex_digit);
  bool GeneratePreEncHashes(boost::shared_ptr<DataIOHandler> iohandler,
                            DataMap *dm);
  // ensure uniqueness of all chunk hashes (unless chunks are identical)
  // if pre_enc is true, hashes relate to pre-encryption, otherwise post-
  bool HashUnique(const DataMap &dm, bool pre_enc, std::string *hash);
  int EncryptContent(const std::string &entry_str,
                     bool is_string,
                     DataMap *dm,
                     fs::path *processing_path,
                     std::map<std::string, fs::path> *to_chunk_store,
                     boost::shared_ptr<DataIOHandler> iohandler);
  int AddToChunkStore(const std::map<std::string, fs::path> &to_chunk_store,
                      const fs::path &processing_path,
                      boost::shared_ptr<DataIOHandler> iohandler);

  const std::string version_;
  const boost::uint16_t min_chunks_;
  const boost::uint16_t max_chunks_;
  const boost::uint64_t default_chunk_size_;
  const boost::uint16_t default_chunklet_size_;
  const boost::uint16_t min_chunklet_size_;
  bool compress_;
  std::string file_hash_;
  int chunk_count_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELFENCRYPTION_H_
