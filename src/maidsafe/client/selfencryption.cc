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

#include <boost/filesystem/fstream.hpp>
#include <boost/scoped_ptr.hpp>
#include <maidsafe/crypto.h>
#include <maidsafe/maidsafe-dht.h>
#include <maidsafe/utils.h>

#include <stdint.h>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

#include "maidsafe/chunkstore.h"
#include "maidsafe/client/dataiohandler.h"

namespace fs = boost::filesystem;

namespace maidsafe {

SelfEncryption::SelfEncryption(boost::shared_ptr<ChunkStore> client_chunkstore)
    : client_chunkstore_(client_chunkstore),
      version_("Mk II"),
      min_chunks_(3),
      max_chunks_(40),
      default_chunk_size_(262144),
      default_chunklet_size_(16384),  // static_cast<uint16_t> MUST be a
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
                            bool is_string,
                            maidsafe::DataMap *dm) {
  boost::shared_ptr<DataIOHandler> iohandler;

  if (is_string)
    iohandler.reset(new StringIOHandler);
  else
    iohandler.reset(new FileIOHandler);

  iohandler->SetData(entry_str, true);

  // check file is encryptable
  if (CheckEntry(iohandler) != 0)
    return -1;

  file_hash_ = dm->file_hash();

  dm->set_se_version(version_);

  // create process directory
  fs::path processing_path;
  if (!CreateProcessDirectory(&processing_path))
    return -1;

  // check file to see if it should get compressed
  bool compress_file = compress_;
  if (compress_file) {
    compress_file = (is_string) ? CheckCompressibility("", iohandler) :
      CheckCompressibility(entry_str, iohandler);
  }
  if (compress_file)
    dm->set_compression_on(true);

  // get file and chunk sizes
  CalculateChunkSizes(iohandler, dm);

  // populate pre-encryption hash vector
  if (!GeneratePreEncHashes(iohandler, dm))
    return -1;

  // Encrypt chunks
  if (!iohandler->Open())
    return -1;
  // loop through each chunk
  for (int chunk_no = 0; chunk_no != chunk_count_; ++chunk_no) {
    Chunk chunk;
    if (dm->compression_on()) {
      int compression_level = 9;
      std::string compression_type = "gzip" + base::itos(compression_level);
      chunk.set_compression_type(compression_type);
    }
    // initialise counter for amount of data put into chunk
    uint64_t this_chunk_done = 0;
    // get index numbers of pre-encryption hashes for use in obfuscation and
    // encryption
    uint32_t obfuscate_hash_no = (chunk_no + 2) % chunk_count_;
    uint32_t encryption_hash_no = (chunk_no + 1) % chunk_count_;
    // loop through each chunklet
    while (this_chunk_done < dm->chunk_size(chunk_no)) {
      // retrieve appropriate pre-encryption hashes for use in obfuscation and
      // encryption
      std::string obfuscate_hash = dm->chunk_name(obfuscate_hash_no);
      std::string encryption_hash = dm->chunk_name(encryption_hash_no);
      // set this chunklet's size
      uint16_t this_chunklet_size = default_chunklet_size_;
      if (dm->chunk_size(chunk_no) - this_chunk_done < this_chunklet_size)
        this_chunklet_size = static_cast<uint16_t>(dm->chunk_size(chunk_no)
                                                   - this_chunk_done);
      // save chunklet's size to chunk_ before compression so that correct
      // offset can be applied if required
      chunk.add_pre_compression_chunklet_size(this_chunklet_size);
      // increment chunk size counter before compression
      this_chunk_done += this_chunklet_size;
      // get chunklet from file
      std::string this_chunklet;
      boost::scoped_ptr<char> bufferlet(new char[this_chunklet_size]);
      std::ostringstream this_chunklet_oss(std::ostringstream::binary);
      if (!iohandler->Read(bufferlet.get(), this_chunklet_size))
        return -1;
      this_chunklet_oss.write(bufferlet.get(), this_chunklet_size);
      // compress if required and reset this chunklet size
      crypto::Crypto enc_crypto;
      enc_crypto.set_symm_algorithm(crypto::AES_256);
      if (compress_file) {
        try {
          this_chunklet = enc_crypto.Compress(this_chunklet_oss.str(), "", 9,
                                              crypto::STRING_STRING);
        }
        catch(const std::exception &e) {
#ifdef DEBUG
          printf("Failed to compress chunklet: %s\n", e.what());
#endif
          return -1;
        }
        this_chunklet_size = this_chunklet.size();
      } else {
        this_chunklet = this_chunklet_oss.str();
      }
      // adjust size of obfuscate hash to match size of chunklet
      std::string resized_obs_hash;
      ResizeObfuscationHash(obfuscate_hash, this_chunklet_size,
                            &resized_obs_hash);
      // output encrypted chunklet
      std::string post_enc;
      post_enc = enc_crypto.SymmEncrypt(
          (enc_crypto.Obfuscate(this_chunklet, resized_obs_hash, crypto::XOR)),
          "",
          crypto::STRING_STRING,
          encryption_hash);
      chunk.add_chunklet(this_chunklet);
    }
    // assign temporary name for chunk
    fs::path temp_chunk_name = processing_path;
    temp_chunk_name /= dm->chunk_name(chunk_no);
    // remove any old copies of the chunk
    try {
      if (fs::exists(temp_chunk_name))
        fs::remove(temp_chunk_name);
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("In SelfEncryption::Encrypt - %s\n", e.what());
#endif
      return -1;
    }
    // serialise the chunk to the temp output fstream
    std::ofstream this_chunk_out(temp_chunk_name.string().c_str(),
                                 std::ofstream::binary);
    chunk.SerializeToOstream(&this_chunk_out);
    this_chunk_out.close();
    // store chunk via client_chunkstore.  If it has already been saved
    // or queued to be saved, StoreChunk does not try to re-store chunk.
    std::string post_enc_hash = SHA512(temp_chunk_name);
    // ensure uniqueness of post-encryption hash
    // HashUnique(post_enc_hash_, dm, false);
    client_chunkstore_->AddChunkToOutgoing(base::DecodeFromHex(post_enc_hash),
                                          temp_chunk_name);
    // store the post-encryption hash to datamap
    dm->add_encrypted_chunk_name(post_enc_hash);
  }
  iohandler->Close();
  // delete process dir
  try {
    if (fs::exists(processing_path))
      fs::remove_all(processing_path);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("In SelfEncryption::Encrypt -- %s\n", e.what());
#endif
  }
  return 0;
}

int SelfEncryption::Decrypt(const maidsafe::DataMap &dm,
                            const std::string &entry_str,
                            const uint64_t &offset,
                            bool overwrite) {
  try {
    if (fs::exists(entry_str)) {
      if (overwrite)
        fs::remove(fs::path(entry_str));
      else
        return 0;
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("In SelfEncryption::Decrypt - %s\n", e.what());
#endif
    return -1;
  }
  boost::shared_ptr<DataIOHandler> iohandler(new FileIOHandler);
  return Decrypt(dm, offset, entry_str, iohandler, NULL);
}

int SelfEncryption::Decrypt(const maidsafe::DataMap &dm,
                            const uint64_t &offset,
                            std::string *decrypted_str) {
  boost::shared_ptr<DataIOHandler> iohandler(new StringIOHandler);
  iohandler->SetData("", false);
  return Decrypt(dm, offset, "", iohandler, decrypted_str);
}

int SelfEncryption::Decrypt(const maidsafe::DataMap &dm,
                            const uint64_t &offset,
                            const std::string &path,
                            boost::shared_ptr<DataIOHandler> iohandler,
                            std::string *decrypted_str) {
  file_hash_ = dm.file_hash();
  // if there is no file hash, then the file has never been encrypted
  if (file_hash_.empty())
    return -1;

  chunk_count_ = dm.chunk_name_size();
  if (chunk_count_ == 0) {
    if (path.empty()) {
      decrypted_str->clear();
    } else {
      iohandler->SetData(path, false);
      iohandler->Open();
      iohandler->Close();
    }
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

  // create process directory
  fs::path processing_path;
  if (!CreateProcessDirectory(&processing_path)) {
#ifdef DEBUG
    printf("Error - Cannot create process directories.\n");
#endif
    return -1;
  }

  // TODO(Fraser#5#): implement offset
  if (offset == 0) {
    // Decrypt chunklets
    fs::path temp_file_path = processing_path / (file_hash_.substr(0, 8) +
                                                 ".tmp");
    if (path.empty())
      iohandler->SetData("", false);
    else
      iohandler->SetData(temp_file_path.string(), false);
    if (!iohandler->Open())
      return -1;
    // loop through each chunk
    for (int chunk_no = 0; chunk_no != chunk_count_; ++chunk_no) {
      // get chunk
      Chunk chunk;
      fs::path this_chunk_path = GetChunkPath(
          dm.encrypted_chunk_name(chunk_no));

      fs::ifstream fin(this_chunk_path, std::ifstream::binary);
      if (!fin.good())
        return -1;
      if (!chunk.ParseFromIstream(&fin))
        return -1;
      // check if compression was used during encryption
      compress_ = (!chunk.compression_type().empty());
      // get index numbers of pre-encryption hashes for use in obfuscation and
      // encryption
      unsigned int obfuscate_hash_no = (chunk_no + 2) % chunk_count_;
      unsigned int encryption_hash_no = (chunk_no + 1) % chunk_count_;
      // retrieve appropriate pre-encryption hashes for use in obfuscation and
      // encryption
      std::string obfuscate_hash = dm.chunk_name(obfuscate_hash_no);
      std::string encryption_hash = dm.chunk_name(encryption_hash_no);
      // loop through each chunklet
      for (int i = 0; i < chunk.chunklet_size(); ++i) {
        std::string this_chunklet = chunk.chunklet(i);
        // adjust size of obfuscate hash to match size of chunklet
        std::string resized_obs_hash;
        ResizeObfuscationHash(obfuscate_hash,
                              static_cast<uint16_t>(this_chunklet.size()),
                              &resized_obs_hash);
        std::string decrypt;
        crypto::Crypto dec_crypto;
        dec_crypto.set_symm_algorithm(crypto::AES_256);
        decrypt = dec_crypto.Obfuscate(
            (dec_crypto.SymmDecrypt(
                this_chunklet, "", crypto::STRING_STRING, encryption_hash)),
            resized_obs_hash,
            crypto::XOR);
        // decompress if required
        if (compress_) {
          this_chunklet = dec_crypto.Uncompress(this_chunklet, "",
                                                crypto::STRING_STRING);
        }
        iohandler->Write(this_chunklet.c_str(), this_chunklet.size());
      }
      fin.close();
    }
    iohandler->Close();
    // move file to correct location and delete process dir
    if (!path.empty()) {
      fs::path final_path(path, fs::native);
      try {
        if (fs::exists(final_path))
          fs::remove(final_path);
        fs::rename(temp_file_path, final_path);
        fs::remove(processing_path);
      }
      catch(const std::exception &e) {
#ifdef DEBUG
        printf("In SelfEncryption::Decrypt -- %s\n", e.what());
#endif
      }
    } else {
      *decrypted_str = iohandler->GetAsString();
    }
  }
  return 0;
}

int SelfEncryption::CheckEntry(boost::shared_ptr<DataIOHandler> iohandler) {
  // if file size < 2 bytes, it's too small to chunk
  uint64_t filesize(0);
  iohandler->Size(&filesize);
  return filesize < 2 ? -1 : 0;
}

std::string SelfEncryption::SHA512(const fs::path &file_path) {  // files
  crypto::Crypto file_crypto;
  file_crypto.set_hash_algorithm(crypto::SHA_512);
  return file_crypto.Hash(file_path.string(), "", crypto::FILE_STRING, true);
}

std::string SelfEncryption::SHA512(const std::string &content) {  // strings
  crypto::Crypto string_crypto;
  string_crypto.set_hash_algorithm(crypto::SHA_512);
  return string_crypto.Hash(content, "", crypto::STRING_STRING, true);
}

bool SelfEncryption::CreateProcessDirectory(fs::path *processing_path) {
  *processing_path = fs::path(fsys_.ProcessDir(), fs::native);
  *processing_path /= file_hash_.substr(0, 8);
  try {
    fs::remove_all(*processing_path);
    fs::create_directories(*processing_path);
    return fs::exists(*processing_path);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("In SelfEncryption::CreateProcessDirectory - %s\n", e.what());
#endif
    return false;
  }
}

fs::path SelfEncryption::GetChunkPath(const std::string &hex_chunk_name) {
  return client_chunkstore_->GetChunkPath(base::DecodeFromHex(hex_chunk_name),
                                          (kHashable | kOutgoing), true);
}

bool SelfEncryption::CheckCompressibility(
    const std::string &path,
    boost::shared_ptr<DataIOHandler> iohandler) {
  int nElements = sizeof(no_compress_type) / sizeof(no_compress_type[0]);
  if (!path.empty()) {
    std::set<std::string> no_comp(no_compress_type, no_compress_type+nElements);
    std::set<std::string>::iterator it;
    try {
      it = no_comp.find(fs::extension(fs::path(path)));
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("In SelfEncryption::CheckCompressibility - %s\n", e.what());
#endif
      return false;
    }
    if (it != no_comp.end())
      return false;
  }

  uint64_t test_chunk_size = 256;
  uint64_t pointer = 0;
  uint64_t pre_comp_file_size = 0;
  if (!iohandler->Size(&pre_comp_file_size))
    return false;

  if (!iohandler->Open())
    return false;

  if (2*test_chunk_size > pre_comp_file_size)
    test_chunk_size = static_cast<uint16_t>(pre_comp_file_size);
  else
    pointer = pre_comp_file_size/2;
  boost::scoped_ptr<char>buffer(new char[test_chunk_size]);
  std::ostringstream test_chunk(std::ostringstream::binary);

  if (!iohandler->SetGetPointer(pointer) ||
      !iohandler->Read(buffer.get(), test_chunk_size))
    return false;

  test_chunk.write(buffer.get(), test_chunk_size);

  iohandler->Close();

  std::string uncompressed_test_chunk, compressed_test_chunk;
  uncompressed_test_chunk = test_chunk.str();
  try {
    crypto::Crypto crypto_obj;
    compressed_test_chunk = crypto_obj.Compress(uncompressed_test_chunk, "",
                                                9, crypto::STRING_STRING);
    float ratio = static_cast<float>(compressed_test_chunk.size()
                                      / test_chunk_size);
    return (ratio <= 0.9);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Error in checking compressibility: %s\n", e.what());
#endif
    return false;
  }
}

bool SelfEncryption::CalculateChunkSizes(
    boost::shared_ptr<DataIOHandler> iohandler,
    maidsafe::DataMap *dm) {
  uint64_t file_size = 0;
  if (!iohandler->Size(&file_size))
    return false;
  uint64_t this_avg_chunk_size = default_chunk_size_;

  // If the file is so large it will split into more chunks than max_chunks_,
  // resize chunks to yield no more than max_chunks_
  if (file_size/max_chunks_ > default_chunk_size_) {
      this_avg_chunk_size = file_size/max_chunks_;
    chunk_count_ = max_chunks_;
  } else if (file_size == 4) {
    // set chunk_size for file of size 4 bytes to avoid only 2 chunks being
    // generated
    this_avg_chunk_size = 1;
    chunk_count_ = 3;
  } else if (file_size/min_chunks_ < default_chunk_size_) {
    // If the file is so small it will split into less chunks than min_chunks_,
    // resize chunks to yield no less than min_chunks_
    this_avg_chunk_size = file_size/min_chunks_;
      // If file is not exactly divisible into the minimum number of chunks,
      // add 1 to chunk size
      if (file_size % min_chunks_ != 0)
      ++this_avg_chunk_size;
    chunk_count_ = min_chunks_;
  } else {
    // otherwise, select chunk size to yield roughly same sized chunks (i.e. no
    // tiny last chunk)
    chunk_count_ = static_cast<int>(file_size/this_avg_chunk_size);
    this_avg_chunk_size = (file_size/chunk_count_);
  }

  // iterate through each chunk except the last, adding or subtracting bytes
  // based on the file hash
  uint64_t remainder = file_size;

  for (int this_chunk = 0; this_chunk < chunk_count_-1; ++this_chunk) {
    // get maximum ratio to add/subtract from chunks so that we're not left
    // with a negative-sized final chunk should all previous chunks have had
    // maximum bytes added to them.
    float max_ratio = static_cast<float>(1)/(max_chunks_*16);

    uint64_t this_chunk_size = static_cast<uint64_t>(this_avg_chunk_size
        *(1+(max_ratio*ChunkAddition(file_hash_.c_str()[this_chunk]))));
    if (!this_chunk_size)  // i.e. size of 0
      ++this_chunk_size;
    dm->add_chunk_size(this_chunk_size);
    remainder -= this_chunk_size;
  }
  // get size of last chunk
  dm->add_chunk_size(remainder);
  return true;
}

int SelfEncryption::ChunkAddition(const char &hex_digit) {
  if (hex_digit > 47 && hex_digit < 58)
    return hex_digit-56;
  if (hex_digit > 64 && hex_digit < 71)
    return hex_digit-63;
  if (hex_digit > 96 && hex_digit < 103)
    return hex_digit-95;
  return 0;
}

bool SelfEncryption::GeneratePreEncHashes(
    boost::shared_ptr<DataIOHandler> iohandler,
    maidsafe::DataMap *dm) {
  if (!iohandler->Open())
    return false;
  uint64_t pointer = 0;

  for (int i = 0; i < chunk_count_; ++i) {
    std::string pre_enc_hash;
    uint64_t this_chunk_size = dm->chunk_size(i);
    uint16_t buffer_size = default_chunklet_size_;
    if (this_chunk_size < default_chunklet_size_)
      buffer_size = static_cast<uint16_t>(this_chunk_size);

    boost::scoped_ptr<char> buffer(new char[buffer_size]);
    std::ostringstream this_hash(std::ostringstream::binary);

    if (!iohandler->SetGetPointer(pointer) ||
        !iohandler->Read(buffer.get(), buffer_size))
      return false;
    this_hash.write(buffer.get(), buffer_size);
    pre_enc_hash = SHA512(this_hash.str());
    pointer += this_chunk_size;
    // ensure uniqueness of all pre-encryption hashes
    // HashUnique(pre_enc_hash, dm, true);
    dm->add_chunk_name(pre_enc_hash);
  }
  iohandler->Close();
  return true;
}

bool SelfEncryption::HashUnique(const maidsafe::DataMap &dm,
                                bool pre_enc,
                                std::string *hash) {
// TODO(Fraser#5#): do validity check or diff (if chunk size > some minimum?)
  int hash_count;
  if (pre_enc)
    hash_count = dm.chunk_name_size();
  else
    hash_count = dm.encrypted_chunk_name_size();
  // check uniqueness of pre-encryption hash
  if (pre_enc) {
    if (hash_count>0) {
      for (int i = 0; i < hash_count; ++i) {
        if (*hash == dm.chunk_name(i)) {
          char last = hash->at(hash->length()-1);
          hash->resize(hash->length()-1);
          hash->insert(0, 1, last);
          HashUnique(dm, pre_enc, hash);
        }
      }
    }
  } else {  // check uniqueness of post-encryption hash
    if (hash_count>0) {
      for (int i = 0; i < hash_count; ++i) {
        if (*hash == dm.encrypted_chunk_name(i)) {
          char last = hash->at(hash->length()-1);
          hash->resize(hash->length()-1);
          hash->insert(0, 1, last);
          HashUnique(dm, pre_enc, hash);
        }
      }
    }
  }
  return true;
}

bool SelfEncryption::ResizeObfuscationHash(const std::string &obfuscate_hash,
                                           const uint16_t &length,
                                           std::string *resized_obs_hash) {
  *resized_obs_hash = obfuscate_hash;
  int32_t length_difference = length - obfuscate_hash.size();
  std::string appendix = obfuscate_hash;
  while (length_difference > 0) {
    resized_obs_hash->append(appendix);
    length_difference = length - resized_obs_hash->size();
  }
  resized_obs_hash->resize(length);
  return true;
}

}  // namespace maidsafe
