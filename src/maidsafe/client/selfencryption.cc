/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Self-encryption and self-decryption engine
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

// TODO(Fraser#5#):
// 1. Pass small files (<700 bytes either compressed or uncompressed)
//    direct to MDM without encrypting them.
//
// 2. Allow for different types of obfuscation and encryption,
//    including an option for no obf. and/or no enc.
//
//
#include "maidsafe/client/selfencryption.h"

#include <stdint.h>
#include <cstdio>
#include <string>
#include <vector>

#include "boost/filesystem/fstream.hpp"
#include "boost/scoped_ptr.hpp"
#include "cryptopp/gzip.h"

#include "maidsafe/crypto.h"
#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

  SelfEncryption::SelfEncryption()
      : version_("Mk II"),
        min_chunks_(3),
        max_chunks_(40),
        default_chunk_size_(262144),
        default_chunklet_size_(16384),  // static_cast<uint16_t>MUST be a
                                        // multiple of 2*IV for AES encryption,
                                        // i.e. multiple of 32.
        min_chunklet_size_(32),
        compress_(true),
        file_hash_(""),
        chunk_count_(0),
        fsys_() {
#ifdef DEBUG
//          printf("version_ = %s\n", version_);
//          printf("min_chunks_ = %u\n", min_chunks_);
//          printf("max_chunks_ = %u\n", max_chunks_);
//          printf("default_chunk_size_ = %lu\n", default_chunk_size_);
//          printf("default_chunklet_size_ = %u\n", default_chunklet_size_);
//          printf("min_chunklet_size_ = %u\n", min_chunklet_size_);
//          printf("compress_ = %i\n", compress_);
#endif
  }

int SelfEncryption::Encrypt(const std::string &entry_str,
                            maidsafe::DataMap *dm) {
  fs::path entry_path_(entry_str, fs::native);

#ifdef DEBUG
//  printf("Encrypting %s\n", entry_str);
#endif

  // check file is encryptable
  int valid_file_ = CheckEntry(entry_path_);
  if (valid_file_ != 0) {
#ifdef DEBUG
//    printf("\nError \"%i\"...\nCannot process %s\n", valid_file_,
//           entry_path_.string().c_str());
#endif
    return -1;
  }

  file_hash_ = dm->file_hash();
#ifdef DEBUG
//  printf("File hash = %s\n", file_hash_.c_str());
#endif
  dm->set_se_version(version_);

  // create process directory
  fs::path processing_path_;
  if (!CreateProcessDirectory(&processing_path_)) {
#ifdef DEBUG
//      printf("Error - Cannot create process directories.\n");
#endif
    return -1;
  }

  // check file to see if it should get compressed
  bool compress_file_ = compress_;
  if (compress_file_)
    compress_file_ = CheckCompressibility(entry_path_);
#ifdef DEBUG
//  if (compress_file_)
//    printf("Compression ON for '%s'\n", fs::extension(entry_path_).c_str());
//  else
//    printf("Compression OFF for '%s'\n", fs::extension(entry_path_).c_str());
#endif
  if (compress_file_)
    dm->set_compression_on(true);

  // get file and chunk sizes
  CalculateChunkSizes(entry_path_, dm);

  // populate pre-encryption hash vector
  if (!GeneratePreEncHashes(entry_path_, dm)) {
#ifdef DEBUG
//      printf("Error - Cannot create pre-encryption hashes.\n");
#endif
    return -1;
  }

  // Encrypt chunks
  fs::ifstream fin_(entry_path_, std::ifstream::binary);
  if (!fin_.good())
    return -1;
  // loop through each chunk
  for (int chunk_no_ = 0; chunk_no_ != chunk_count_; ++chunk_no_) {
    Chunk chunk_;
    if (dm->compression_on()) {
      int compression_level_ = 9;
      std::string compression_type_ = "gzip"+base::itos(compression_level_);
      chunk_.set_compression_type(compression_type_);
    }
    // initialise counter for amount of data put into chunk
    uint64_t this_chunk_done_ = 0;
    // get index numbers of pre-encryption hashes for use in obfuscation and
    // encryption
    uint32_t obfuscate_hash_no_ = (chunk_no_ + 2) % chunk_count_;
    uint32_t encryption_hash_no_ = (chunk_no_ + 1) % chunk_count_;
    // loop through each chunklet
    while (this_chunk_done_ < dm->chunk_size(chunk_no_)) {
      // retrieve appropriate pre-encryption hashes for use in obfuscation and
      // encryption
      std::string obfuscate_hash_ = dm->chunk_name(obfuscate_hash_no_);
      std::string encryption_hash_ = dm->chunk_name(encryption_hash_no_);
      // set this chunklet's size
      uint16_t this_chunklet_size_ = default_chunklet_size_;
      if (dm->chunk_size(chunk_no_)-this_chunk_done_ < this_chunklet_size_)
        this_chunklet_size_ = static_cast<uint16_t>(dm->chunk_size(chunk_no_)
                                                    -this_chunk_done_);
      // save chunklet's size to chunk_ before compression so that correct
      // offset can be applied if required
      chunk_.add_pre_compression_chunklet_size(this_chunklet_size_);
      // increment chunk size counter before compression
      this_chunk_done_ += this_chunklet_size_;

      // get chunklet from file
      std::string this_chunklet_;
      boost::scoped_ptr<char> bufferlet_(new char[this_chunklet_size_]);
      std::ostringstream this_chunklet_oss_(std::ostringstream::binary);
      fin_.read(bufferlet_.get(), this_chunklet_size_);
      this_chunklet_oss_.write(bufferlet_.get(), this_chunklet_size_);
      // compress if required and reset this chunklet size
      if (compress_file_) {
        try {
          CryptoPP::StringSource(this_chunklet_oss_.str(), true,
            new CryptoPP::Gzip(
              new CryptoPP::StringSink(this_chunklet_), 9));
        }
        catch(const CryptoPP::Exception &exception_) {
#ifdef DEBUG
//          printf("Failed to compress chunklet: %s\n", exception_.what());
#endif
          return -1;
        }
        this_chunklet_size_ = this_chunklet_.size();
      } else {
        this_chunklet_ = this_chunklet_oss_.str();
      }
      // adjust size of obfuscate hash to match size of chunklet
      std::string resized_obs_hash_;
      ResizeObfuscationHash(obfuscate_hash_, this_chunklet_size_,
                            &resized_obs_hash_);
#ifdef DEBUG
      printf("Chunk No. - %i\n\n%u - %s\n%u - %s\n\n",
             chunk_no_, obfuscate_hash_no_, obfuscate_hash_.c_str(),
              encryption_hash_no_, encryption_hash_.c_str());
#endif
      // output encrypted chunklet
      std::string post_enc_;
      maidsafe_crypto::Crypto enc_crypto_;
      enc_crypto_.set_symm_algorithm("AES_256");
      post_enc_ = enc_crypto_.SymmEncrypt((
        enc_crypto_.Obfuscate(
          this_chunklet_, resized_obs_hash_, maidsafe_crypto::XOR)),
          "", maidsafe_crypto::STRING_STRING, encryption_hash_);
#ifdef DEBUG
//      printf("chunklet's orig data     : %s\n", this_chunklet_.c_str());
//      printf("chunklet's orig data size: %lu\n\n", this_chunklet_.size());
//      printf("chunklet's XOR hash      : %s\n", obfuscate_hash_.c_str());
//      printf("chunklet's XOR hash size : %lu\n", obfuscate_hash_.size());
//      printf("chunklet's enc hash      : %s\n", encryption_hash_.c_str());
//      printf("chunklet's enc hash size : %lu\n", encryption_hash_.size());
//      printf("chunklet's enc data      : %s\n", post_enc_.c_str());
//      printf("chunklet's enc data size : %lu\n", post_enc_.size());
#endif
      chunk_.add_chunklet(this_chunklet_);
    }
    // assign temporary name for chunk
    fs::path temp_chunk_name_ = processing_path_;
    temp_chunk_name_ /= dm->chunk_name(chunk_no_);
    // remove any old copies of the chunk
    if (fs::exists(temp_chunk_name_))
      fs::remove(temp_chunk_name_);
    // serialise the chunk to the temp output fstream
    std::ofstream this_chunk_out_(temp_chunk_name_.string().c_str(),
                                  std::ofstream::binary);
    chunk_.SerializeToOstream(&this_chunk_out_);
    this_chunk_out_.close();
    // rename chunk to hash of contents, move to appropriate directory
    // and store post-encryption hash to datamap
    std::string post_enc_hash_ = SHA512(temp_chunk_name_);
    // ensure uniqueness of post-encryption hash
    // HashUnique(post_enc_hash_, dm, false);
    // get chunk's dir and delete chunk if it already exists there
    fs::path chunk_name_ = GetChunkPath(post_enc_hash_);
    if (fs::exists(chunk_name_))
      fs::remove(chunk_name_);
    // move chunk to correct directory
    fs::rename(temp_chunk_name_, chunk_name_);
    dm->add_encrypted_chunk_name(post_enc_hash_);
  }
  fin_.close();
  // delete process dir
  if (fs::exists(processing_path_))
    fs::remove(processing_path_);
  return 0;
}  // end encrypt


int SelfEncryption::Decrypt(const maidsafe::DataMap &dm,
                            const std::string &entry_str,
                            const uint64_t &offset,
                            bool overwrite) {
  if (fs::exists(entry_str)) {
    if (overwrite)
      fs::remove(fs::path(entry_str));
    else
      return 0;
  }

  file_hash_ = dm.file_hash();
  // if there is no file hash, then the file has never been encrypted
  if (file_hash_ == "")
    return -1;

  int chunk_count_ = dm.chunk_name_size();
  if (chunk_count_ == 0) {
    std::ofstream ofstream_;
    ofstream_.open(entry_str.c_str(),
                   std::ofstream::binary | std::ofstream::trunc);
    ofstream_.close();
    return 0;
  }

  if (dm.se_version() != version_) {
#ifdef DEBUG
      printf("Cannot decrypt - incompatible decryption engine (version");
      printf(" %s) being applied to data encrypted with", version_.c_str());
      printf(" version %s\n", dm.se_version().c_str());
#endif
    return -1;
  }

#ifdef DEBUG
//    printf("%s\n\n", file_hash.c_str());
//    for (int i = 0; i < chunk_count_; ++i)
//      printf("%s\n\n", dm->chunk_name(i).c_str());
//    for (int i = 0; i < chunk_count_; ++i)
//      printf("%s\n\n", dm->encrypted_chunk_name(i).c_str());
#endif

  // create process directory
  fs::path processing_path_;
  if (!CreateProcessDirectory(&processing_path_)) {
#ifdef DEBUG
    printf("Error - Cannot create process directories.\n");
#endif
    return -1;
  }

  // TODO(Fraser#5#): implement offset
  if (offset == 0) {
    // Decrypt chunklets
    fs::path temp_file_path_ = processing_path_/(file_hash_.substr(0, 8)
                                                 + ".tmp");
    std::ofstream temp_ofstream_;
    temp_ofstream_.open(temp_file_path_.string().c_str(),
        std::ofstream::binary | std::ofstream::app);
    // loop through each chunk
    for (int chunk_no_ = 0; chunk_no_ != chunk_count_; ++chunk_no_) {
      // get chunk
      Chunk chunk_;
      fs::path this_chunk_path_ = GetChunkPath(
                                      dm.encrypted_chunk_name(chunk_no_));
      fs::ifstream fin_(this_chunk_path_, std::ifstream::binary);
      if (!fin_.good())
        return -1;
      chunk_.ParseFromIstream(&fin_);
      // check if compression was used during encryption
      compress_ = (chunk_.compression_type() != "") ? true : false;
      // get index numbers of pre-encryption hashes for use in obfuscation and
      // encryption
      unsigned int obfuscate_hash_no_ = (chunk_no_ + 2) % chunk_count_;
      unsigned int encryption_hash_no_ = (chunk_no_ + 1) % chunk_count_;
      // retrieve appropriate pre-encryption hashes for use in obfuscation and
      // encryption
      std::string obfuscate_hash_ = dm.chunk_name(obfuscate_hash_no_);
      std::string encryption_hash_ = dm.chunk_name(encryption_hash_no_);
      // loop through each chunklet
      for (int i = 0; i < chunk_.chunklet_size(); ++i) {
        std::string this_chunklet_ = chunk_.chunklet(i);
        // adjust size of obfuscate hash to match size of chunklet
        std::string resized_obs_hash_;
        ResizeObfuscationHash(
            obfuscate_hash_,
            static_cast<uint16_t>(this_chunklet_.size()),
            &resized_obs_hash_);
#ifdef DEBUG
          printf("Chunk No. - %i\n\n%u - %s\n%u - %s\n\n",
                 chunk_no_, obfuscate_hash_no_, obfuscate_hash_.c_str(),
                 encryption_hash_no_, encryption_hash_.c_str());
#endif
        std::string decrypt_;
        maidsafe_crypto::Crypto dec_crypto_;
        dec_crypto_.set_symm_algorithm("AES_256");
        decrypt_ = dec_crypto_.Obfuscate((
                       dec_crypto_.SymmDecrypt(
                       this_chunklet_,
                       "",
                       maidsafe_crypto::STRING_STRING, encryption_hash_)),
                       resized_obs_hash_, maidsafe_crypto::XOR);
#ifdef DEBUG
//          printf("this chunklet's decrypted content: %s", decrypt_.c_str());
//          printf("\nand size: %lu\n", decrypt_.size());
//          printf("this chunklet's XOR hash: %s", obfuscate_hash_.c_str());
//          printf("\nand size: %lu\n", obfuscate_hash_.size());
//          printf("this chunklet's enc hash: %s", encryption_hash_.c_str());
//          printf("\nand size: %lu\n", encryption_hash_.size());
#endif
        // decompress if required
        if (compress_) {
          std::string decompressed_chunklet_;
          CryptoPP::StringSource(this_chunklet_, true,
            new CryptoPP::Gunzip(
              new CryptoPP::StringSink(decompressed_chunklet_)));
          this_chunklet_ = decompressed_chunklet_;
        }
        temp_ofstream_.write(this_chunklet_.c_str(), this_chunklet_.size());
      }
      fin_.close();
    }
    temp_ofstream_.close();
    // move file to correct location and delete process dir
    fs::path final_path_(entry_str, fs::native);
    if (fs::exists(final_path_))
      fs::remove(final_path_);
    fs::rename(temp_file_path_, final_path_);
    fs::remove(processing_path_);
  }
  return 0;
}  // end decrypt


int SelfEncryption::CheckEntry(const fs::path &entry_path) {
  // if file size < 2 bytes, it's too small to chunk
  uint64_t filesize_ = fs::file_size(entry_path);
  if (filesize_ < 2)
    return -1;
  else
    return 0;
}  // end CheckEntry


std::string SelfEncryption::SHA512(const fs::path &file_path) {  // files
  maidsafe_crypto::Crypto filehash_crypto;
  filehash_crypto.set_hash_algorithm("SHA512");
  std::string file_hash_ = filehash_crypto.Hash(file_path.string(),
                                                "",
                                                maidsafe_crypto::FILE_STRING,
                                                true);
  return file_hash_;
}  // end SHA512 for files


std::string SelfEncryption::SHA512(const std::string &content) {  // strings
  maidsafe_crypto::Crypto stringhash_crypto;
  stringhash_crypto.set_hash_algorithm("SHA512");
  std::string string_hash_ = stringhash_crypto.Hash(
                                 content,
                                 "",
                                 maidsafe_crypto::STRING_STRING,
                                 true);
  return string_hash_;
}  // end SHA512 for strings


bool SelfEncryption::CreateProcessDirectory(fs::path *processing_path) {
  *processing_path = fs::path(fsys_.ProcessDir(), fs::native);
  *processing_path /= file_hash_.substr(0, 8);
#ifdef DEBUG
    printf("Removing directory first...\n");
#endif
  try {
    fs::remove_all(*processing_path);
  }
  catch(const std::exception &exception_) {
#ifdef DEBUG
    printf("Error creating process dir in self enc: %s\n", exception_.what());
#endif
    return false;
  }
#ifdef DEBUG
//    printf("Trying to create %s\n", *processing_path.c_str());
#endif
    fs::create_directories(*processing_path);
#ifdef DEBUG
//     printf("Created %s\n", *processing_path.c_str());
#endif
  if (fs::exists(*processing_path))
    return true;
  return false;
}  // end CreateProcessDirectory


fs::path SelfEncryption::GetChunkPath(const std::string &chunk_name) {
  std::string dir_one, dir_two, dir_three;
  dir_one = chunk_name.substr(0, 1);
  dir_two = chunk_name.substr(1, 1);
  dir_three = chunk_name.substr(2, 1);
  fs::path chunk_branch_ = fs::path(fsys_.ApplicationDataDir(), fs::native)
    / "client" / dir_one / dir_two / dir_three;
  if (!fs::exists(chunk_branch_))
    fs::create_directories(chunk_branch_);
  fs::path chunk_path_ = chunk_branch_ / chunk_name;
#ifdef DEBUG
  printf("Chunk path: %s\n\n", chunk_path_.string().c_str());
#endif
  return chunk_path_;
}  // end GetChunkPath


bool SelfEncryption::CheckCompressibility(const fs::path &entry_path) {
  int nElements = sizeof(no_compress_type) / sizeof(no_compress_type[0]);
  std::set<std::string> no_comp(no_compress_type, no_compress_type+nElements);
  std::set<std::string>::iterator it;
  it = no_comp.find(fs::extension(entry_path));
  if (it != no_comp.end())
    return false;
  fs::ifstream fin_comp_test_(entry_path, std::ifstream::binary);
  if (!fin_comp_test_.good())
    return false;
  uint64_t test_chunk_size_ = 256;
  uint64_t pointer_ = 0;
  uint64_t pre_comp_file_size_ = fs::file_size(entry_path);
  if (2*test_chunk_size_ > pre_comp_file_size_)
    test_chunk_size_ = static_cast<uint16_t>(pre_comp_file_size_);
  else
    pointer_ = pre_comp_file_size_/2;
  boost::scoped_ptr<char>buffer_(new char[test_chunk_size_]);
  std::ostringstream test_chunk_(std::ostringstream::binary);
  fin_comp_test_.seekg(static_cast<uint64_t>(pointer_), std::ios::beg);
  fin_comp_test_.read(buffer_.get(), test_chunk_size_);
  test_chunk_.write(buffer_.get(), test_chunk_size_);
  fin_comp_test_.close();
  std::string uncompressed_test_chunk_, compressed_test_chunk_;
  uncompressed_test_chunk_ = test_chunk_.str();
  try {
    CryptoPP::StringSource(uncompressed_test_chunk_, true,
      new CryptoPP::Gzip(new CryptoPP::StringSink(compressed_test_chunk_), 9));
    float ratio_ = static_cast<float>(compressed_test_chunk_.size()
        / test_chunk_size_);
#ifdef DEBUG
//      printf("File size: %lu\nPre comp: %lu\tPost comp: %lu\tRatio: %f\n\n",
//             fs::file_size(path_), test_chunk_size_,
//             compressed_test_chunk_.size(), ratio_);
#endif
    if (ratio_>0.9)
      return false;
    else
      return true;
  }
  catch(const CryptoPP::Exception &exception_) {
#ifdef DEBUG
    printf("Error in checking compressibility: %s\n", exception_.what());
#endif
    return false;
  }
}  // end CheckCompressibility


bool SelfEncryption::CalculateChunkSizes(const fs::path &entry_path,
                                         maidsafe::DataMap *dm) {
#ifdef DEBUG
  printf("file_hash_ = %s\n", file_hash_.c_str());
#endif
  uint64_t file_size_ = fs::file_size(entry_path);
  uint64_t this_avg_chunk_size_ = default_chunk_size_;
#ifdef DEBUG
//    printf("Start CalculateChunkSize...\n");
//    printf("file_size_ = %lu\tthis_avg_chunk_size_ = %lu",
//           file_size_, this_avg_chunk_size_);
//    printf("\t_max_chunks_ = %u\tmin_chunks_ = %u\n\n",
//           max_chunks_, min_chunks_);
#endif

  // If the file is so large it will split into more chunks than max_chunks_,
  // resize chunks to yield no more than max_chunks_
  if (file_size_/max_chunks_ > default_chunk_size_) {
      this_avg_chunk_size_ = file_size_/max_chunks_;
    chunk_count_ = max_chunks_;
  } else if (file_size_ == 4) {
    // set chunk_size for file of size 4 bytes to avoid only 2 chunks being
    // generated
    this_avg_chunk_size_ = 1;
    chunk_count_ = 3;
  } else if (file_size_/min_chunks_ < default_chunk_size_) {
    // If the file is so small it will split into less chunks than min_chunks_,
    // resize chunks to yield no less than min_chunks_
    this_avg_chunk_size_ = file_size_/min_chunks_;
      // If file is not exactly divisible into the minimum number of chunks,
      // add 1 to chunk size
      if (file_size_ % min_chunks_ != 0)
      ++this_avg_chunk_size_;
    chunk_count_ = min_chunks_;
  } else {
    // otherwise, select chunk size to yield roughly same sized chunks (i.e. no
    // tiny last chunk)
    chunk_count_ = static_cast<int>(file_size_/this_avg_chunk_size_);
    this_avg_chunk_size_ = (file_size_/chunk_count_);
  }
#ifdef DEBUG
//    printf("After CalculateChunkSize...\n");
//    printf("file_size_ = %lu\tthis_avg_chunk_size_ = %lu",
//           file_size_, this_avg_chunk_size_);
//    printf("\t_max_chunks_ = %u\tmin_chunks_ = %u\n\n",
//           max_chunks_, min_chunks_);
#endif

  // iterate through each chunk except the last, adding or subtracting bytes
  // based on the file hash
  uint64_t remainder_ = file_size_;

#ifdef DEBUG
//  printf("max_chunks_ = %u\n", max_chunks_);
//  printf("remainder_ = %lu\n", remainder_);
#endif
  for (int this_chunk_ = 0; this_chunk_ < chunk_count_-1; ++this_chunk_) {
    // get maximum ratio to add/subtract from chunks so that we're not left
    // with a negative-sized final chunk should all previous chunks have had
    // maximum bytes added to them.
    float max_ratio_ = static_cast<float>(1)/(max_chunks_*16);
#ifdef DEBUG
//    printf("file hash: %s\n", file_hash_);
//    printf("file_hash_.c_str()[%i] = %s\tChunkAddition = %i\tAdding %i\n",
//           this_chunk_, file_hash_.c_str()[this_chunk_].c_str(),
//           ChunkAddition(file_hash_.c_str()[this_chunk_]),
//           static_cast<int>(max_ratio_
//                            *ChunkAddition(file_hash_.c_str()[this_chunk_])
//                            *this_avg_chunk_size_));
#endif
    uint64_t this_chunk_size_ = static_cast<uint64_t>(
        this_avg_chunk_size_
        *(1+(max_ratio_*ChunkAddition(file_hash_.c_str()[this_chunk_]))));
    if (!this_chunk_size_)  // i.e. size of 0
      ++this_chunk_size_;
    dm->add_chunk_size(this_chunk_size_);
    remainder_ -= this_chunk_size_;
#ifdef DEBUG
//    printf("this_chunk_size_ (%i) = %lu\tremainder_ = %lu\n",
//           this_chunk_, this_chunk_size_, remainder_);
#endif
  }
  // get size of last chunk
  dm->add_chunk_size(remainder_);
  return true;
}  // end CalculateChunkSize


int SelfEncryption::ChunkAddition(const char &hex_digit) {
  if (hex_digit > 47 && hex_digit < 58)
    return hex_digit-56;
  if (hex_digit > 64 && hex_digit < 71)
    return hex_digit-63;
  if (hex_digit > 96 && hex_digit < 103)
    return hex_digit-95;
  return 0;
}  // end ChunkAddition


bool SelfEncryption::GeneratePreEncHashes(const fs::path &entry_path,
                                          maidsafe::DataMap *dm) {
  fs::ifstream fin_;
  fin_.open(entry_path, std::ifstream::binary);
  if (!fin_.good())
    return false;
  uint64_t pointer_ = 0;

#ifdef DEBUG
  printf("file_hash_ = %s\n", file_hash_.c_str());
  printf("chunk_count_ = %i\tmax_chunks_ = %u\n",
         chunk_count_, max_chunks_);
#endif

  for (int i = 0; i < chunk_count_; ++i) {
    std::string pre_enc_hash_;
    uint64_t this_chunk_size_ = dm->chunk_size(i);
    uint16_t buffer_size_ = default_chunklet_size_;
    if (this_chunk_size_ < default_chunklet_size_)
      buffer_size_ = (uint16_t)this_chunk_size_;

    boost::scoped_ptr<char> buffer_(new char[buffer_size_]);
    std::ostringstream this_hash_(std::ostringstream::binary);
    fin_.read(buffer_.get(), buffer_size_);
    this_hash_.write(buffer_.get(), buffer_size_);
    pre_enc_hash_ = SHA512(this_hash_.str());
    pointer_ += this_chunk_size_;
    // ensure uniqueness of all pre-encryption hashes
    // HashUnique(pre_enc_hash_, dm, true);
    dm->add_chunk_name(pre_enc_hash_);
#ifdef DEBUG
      printf("\tfin_.peek() = %c\n\n", fin_.peek());
      printf("pre_enc_hash_%i: %s\n", i, pre_enc_hash_.c_str());
#endif
  }
  fin_.close();
  return true;
}  // end GeneratePreEncHashes


bool SelfEncryption::HashUnique(const maidsafe::DataMap &dm,
                                bool pre_enc,
                                std::string *hash) {
// **************************************************************************
// TODO(Fraser#5#): do validity check or diff (if chunk size > some minimum?)
// **************************************************************************
  int hash_count_;
  if (pre_enc)
    hash_count_ = dm.chunk_name_size();
  else
    hash_count_ = dm.encrypted_chunk_name_size();
#ifdef DEBUG
    printf("In HashUnique: hash_count_ = %i\n\n", hash_count_);
#endif
  // check uniqueness of pre-encryption hash
  if (pre_enc) {
    if (hash_count_>0) {
      for (int i = 0; i < hash_count_; ++i) {
        if (*hash == dm.chunk_name(i)) {
#ifdef DEBUG
//            printf("hash before = %s\nhashes_[%i] before = %s\n\n",
//                  *hash.c_str(), i, dm->chunk_name(i).c_str());
#endif
          char last = hash->at(hash->length()-1);
          hash->resize(hash->length()-1);
          hash->insert(0, 1, last);
#ifdef DEBUG
//            printf("hash after = %s\nhashes_[%i] after = %s\n\n\n",
//                   *hash.c_str(), i, dm->chunk_name(i).c_str());
#endif
          HashUnique(dm, pre_enc, hash);
        }
      }
    }
  } else {  // check uniqueness of post-encryption hash
    if (hash_count_>0) {
      for (int i = 0; i < hash_count_; ++i) {
        if (*hash == dm.encrypted_chunk_name(i)) {
#ifdef DEBUG
//            printf("hash before = %s\nhashes_[%i] before = %s\n\n",
//                   *hash.c_str(), i, dm->encrypted_chunk_name(i).c_str());
#endif
          char last = hash->at(hash->length()-1);
          hash->resize(hash->length()-1);
          hash->insert(0, 1, last);
#ifdef DEBUG
//            printf("hash after = %s\nhashes_[%i] after = %s\n\n\n",
//                   *hash.c_str(), i, dm->encrypted_chunk_name(i).c_str());
#endif
          HashUnique(dm, pre_enc, hash);
        }
      }
    }
  }
return true;
}  // end HashUnique


bool SelfEncryption::ResizeObfuscationHash(const std::string &obfuscate_hash,
                                           const uint16_t &length_,
                                           std::string *resized_obs_hash) {
  *resized_obs_hash = obfuscate_hash;
  int32_t length_difference_ = length_ - obfuscate_hash.size();
#ifdef DEBUG
  printf("hash: %s\tlength: %u\tlength_difference_: %i\n",
         obfuscate_hash.c_str(), length_, length_difference_);
#endif
  std::string appendix_ = obfuscate_hash;
  while (length_difference_ > 0) {
    resized_obs_hash->append(appendix_);
    length_difference_ = length_ - resized_obs_hash->size();
#ifdef DEBUG
  printf("%i\t", length_difference_);
#endif
  }
#ifdef DEBUG
  printf("\n");
#endif
  resized_obs_hash->resize(length_);
  return true;
}  // end ResizeObfuscationHash

}  // namespace maidsafe
