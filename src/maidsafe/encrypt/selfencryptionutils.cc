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


#include "maidsafe/encrypt/selfencryptionutils.h"

#include <maidsafe/base/crypto.h>
#include <maidsafe/base/utils.h>

#include <set>

#include "maidsafe/encrypt/dataiohandler.h"
#include "maidsafe/encrypt/datamap.pb.h"
#include "maidsafe/encrypt/selfencryptionconfig.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace utils {

int EncryptContent(std::tr1::shared_ptr<DataIOHandler> input_handler,
                   const fs::path &output_dir,
                   DataMap *data_map,
                   std::map<std::string, fs::path> *to_chunk_store) {
  if (!data_map || !to_chunk_store)
    return kNullPointer;
  to_chunk_store->clear();
  if (CheckEntry(input_handler) != kSuccess) {
#ifdef DEBUG
    printf("EncryptContent: CheckEntry failed.\n");
#endif
    return kInputTooSmall;
  }

  std::string file_hash = base::EncodeToHex(data_map->file_hash());
  if (file_hash.empty()) {
    if (input_handler->Type() == DataIOHandler::kFileIOHandler) {
      file_hash = SHA512(std::tr1::static_pointer_cast<FileIOHandler>
                  (input_handler)->FilePath());
    } else {
      file_hash = SHA512(std::tr1::static_pointer_cast<StringIOHandler>
                  (input_handler)->Data());
    }
  }
  data_map->Clear();
  data_map->set_file_hash(file_hash);
  data_map->set_self_encryption_version(kVersion);

  bool compress(CheckCompressibility(input_handler));
  if (compress)
    data_map->set_compression_on(true);

  boost::uint16_t chunk_count(0);
  if (!CalculateChunkSizes(file_hash, input_handler, data_map, &chunk_count)) {
#ifdef DEBUG
    printf("EncryptContent: CalculateChunkSizes failed.\n");
#endif
    return kChunkSizeError;
  }

  if (!GeneratePreEncryptionHashes(input_handler, data_map)) {
#ifdef DEBUG
    printf("EncryptContent: GeneratePreEncryptionHashes failed.\n");
#endif
    return kPreEncryptionHashError;
  }

  if (!input_handler->Open()) {
#ifdef DEBUG
    printf("EncryptContent: Failed to open input.\n");
#endif
    return kIoError;
  }

  // loop through each chunk
  for (boost::uint16_t chunk_no = 0; chunk_no < chunk_count; ++chunk_no) {
    Chunk chunk;
    if (compress) {
      int compression_level = 9;
      std::string compr_type("gzip" + base::IntToString(compression_level));
      chunk.set_compression_type(compr_type);
    }
    // initialise counter for amount of data put into chunk
    boost::uint64_t this_chunk_done = 0;
    // get index numbers of pre-encryption hashes for use in obfuscation and
    // encryption
    boost::uint16_t obfuscate_hash_no = (chunk_no + 2) % chunk_count;
    boost::uint16_t encryption_hash_no = (chunk_no + 1) % chunk_count;
    // loop through each chunklet
    while (this_chunk_done < data_map->chunk_size(chunk_no)) {
      // retrieve appropriate pre-encryption hashes for use in obfuscation and
      // encryption
      std::string obfuscate_hash = data_map->chunk_name(obfuscate_hash_no);
      std::string encryption_hash = data_map->chunk_name(encryption_hash_no);
      // set this chunklet's size
      boost::uint16_t this_chunklet_size = kDefaultChunkletSize;
      if (data_map->chunk_size(chunk_no) - this_chunk_done < this_chunklet_size)
        this_chunklet_size =
            static_cast<boost::uint16_t>(data_map->chunk_size(chunk_no) -
                                         this_chunk_done);
      // save chunklet's size to chunk_ before compression so that correct
      // offset can be applied if required
      chunk.add_pre_compression_chunklet_size(this_chunklet_size);
      // increment chunk size counter before compression
      this_chunk_done += this_chunklet_size;
      // get chunklet from input file/string
      std::string this_chunklet;
      if (!input_handler->Read(this_chunklet_size, &this_chunklet))
        return kIoError;
      // compress if required and reset this chunklet size
      crypto::Crypto encryptor;
      encryptor.set_symm_algorithm(crypto::AES_256);
      if (compress) {
        try {
          this_chunklet = encryptor.Compress(this_chunklet, "", 9,
                                             crypto::STRING_STRING);
        }
        catch(const std::exception &e) {
#ifdef DEBUG
          printf("Failed to compress chunklet: %s\n", e.what());
#endif
          return kCompressionError;
        }
        this_chunklet_size = this_chunklet.size();
      }
      // adjust size of obfuscate hash to match size of chunklet
      std::string resized_obs_hash;
      ResizeObfuscationHash(obfuscate_hash, this_chunklet_size,
                            &resized_obs_hash);
      // output encrypted chunklet
      std::string encrypted_chunklet = encryptor.SymmEncrypt(
          (encryptor.Obfuscate(this_chunklet, resized_obs_hash, crypto::XOR)),
          "", crypto::STRING_STRING, encryption_hash);
      chunk.add_chunklet(encrypted_chunklet);
    }
    // assign temporary name for chunk
    fs::path temp_chunk_name = output_dir;
    temp_chunk_name /= base::EncodeToHex(data_map->chunk_name(chunk_no));
    // remove any old copies of the chunk
    try {
      if (fs::exists(temp_chunk_name))
        fs::remove(temp_chunk_name);
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("In Encrypt - %s\n", e.what());
#endif
      return kFilesystemError;
    }
    // serialise the chunk to the temp output fstream
    std::ofstream this_chunk_out(temp_chunk_name.string().c_str(),
                                 std::ofstream::binary);
    chunk.SerializeToOstream(&this_chunk_out);
    this_chunk_out.close();
    std::string post_enc_hash = SHA512(temp_chunk_name);
    fs::path correct_chunk_name(output_dir / base::EncodeToHex(post_enc_hash));
    try {
      fs::rename(temp_chunk_name, correct_chunk_name);
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("In Encrypt - %s\n", e.what());
#endif
      return kFilesystemError;
    }
    // ensure uniqueness of post-encryption hash
    // HashUnique(post_enc_hash_, data_map, false);
    (*to_chunk_store)[post_enc_hash] = correct_chunk_name;

    // store the post-encryption hash to datamap
    data_map->add_encrypted_chunk_name(post_enc_hash);
  }
  return kSuccess;
}

int DecryptContent(const DataMap &data_map,
                   std::vector<fs::path> chunk_paths,
                   const boost::uint64_t &offset,
                   std::tr1::shared_ptr<DataIOHandler> output_handler) {
  if (!output_handler)
    return kNullPointer;
  std::string file_hash = base::EncodeToHex(data_map.file_hash());
  // if there is no file hash, then the file has never been encrypted
  if (file_hash.empty()) {
#ifdef DEBUG
    printf("DecryptContent - File hash empty.\n");
#endif
    return kNoFileHash;
  }

  boost::uint16_t chunk_count =
      static_cast<boost::uint16_t>(data_map.chunk_name_size());
  if (chunk_count == 0) {
    output_handler->Open();
    output_handler->Close();
    return kSuccess;
  }

  if (data_map.self_encryption_version() != kVersion) {
#ifdef DEBUG
      printf("Cannot decrypt - incompatible decryption engine (version");
      printf(" %s) being applied to data encrypted with", kVersion.c_str());
      printf(" version %s\n", data_map.self_encryption_version().c_str());
#endif
    return kWrongVersion;
  }

  // TODO(Fraser#5#): implement offset
  if (offset == 0) {
    // Decrypt chunklets
    if (!output_handler->Open()) {
#ifdef DEBUG
      printf("Decrypt - IOHandler won't open.\n");
#endif
      return kIoError;
    }
    // loop through each chunk
    for (boost::uint16_t chunk_no = 0; chunk_no < chunk_count; ++chunk_no) {
      // get chunk
      Chunk chunk;
      std::vector<fs::path>::iterator it = chunk_paths.begin();
      while (it != chunk_paths.end()) {
        std::string enc =
            base::EncodeToHex(data_map.encrypted_chunk_name(chunk_no));
        if ((*it).filename().string() ==
            base::EncodeToHex(data_map.encrypted_chunk_name(chunk_no))) {
          break;
        } else {
          ++it;
        }
      }
      if (it == chunk_paths.end()) {
#ifdef DEBUG
        printf("Decrypt - Chunk path not provided.\n");
#endif
        return kChunkPathNotFound;
      }
      fs::path chunk_path(*it);
      chunk_paths.erase(it);
      fs::ifstream fin(chunk_path, std::ifstream::binary);
      if (!fin.good()) {
#ifdef DEBUG
        printf("Decrypt - !fin.good()\n");
#endif
        return kIoError;
      }
      if (!chunk.ParseFromIstream(&fin)) {
#ifdef DEBUG
        printf("Decrypt - !chunk.ParseFromIstream(&fin)\n");
#endif
        return kBadChunk;
      }
      // check if compression was used during encryption
      bool compressed = (!chunk.compression_type().empty());
      // get index numbers of pre-encryption hashes for use in obfuscation and
      // encryption
      boost::uint16_t obfuscate_hash_no = (chunk_no + 2) % chunk_count;
      boost::uint16_t encryption_hash_no = (chunk_no + 1) % chunk_count;
      // retrieve appropriate pre-encryption hashes for use in obfuscation and
      // encryption
      std::string obfuscate_hash = data_map.chunk_name(obfuscate_hash_no);
      std::string encryption_hash = data_map.chunk_name(encryption_hash_no);
      // loop through each chunklet
      for (int i = 0; i < chunk.chunklet_size(); ++i) {
        std::string this_chunklet = chunk.chunklet(i);
        // adjust size of obfuscate hash to match size of chunklet
        std::string resized_obs_hash;
        utils::ResizeObfuscationHash(obfuscate_hash,
            static_cast<boost::uint16_t>(this_chunklet.size()),
            &resized_obs_hash);
        crypto::Crypto decryptor;
        decryptor.set_symm_algorithm(crypto::AES_256);
        std::string decrypted_chunklet = decryptor.Obfuscate(
            (decryptor.SymmDecrypt(this_chunklet, "", crypto::STRING_STRING,
                encryption_hash)), resized_obs_hash, crypto::XOR);
        // decompress if required
        if (compressed) {
          decrypted_chunklet = decryptor.Uncompress(decrypted_chunklet, "",
                                                    crypto::STRING_STRING);
        }
        output_handler->Write(decrypted_chunklet);
      }
      fin.close();
    }
    output_handler->Close();
  }
  return kSuccess;
}

int EncryptDataMap(const DataMap &data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   std::string *encrypted_data_map) {
  if (!encrypted_data_map)
    return kNullPointer;
  encrypted_data_map->clear();
  std::string encrypt_hash = SHA512(parent_directory_key + this_directory_key);
  std::string xor_hash = SHA512(this_directory_key + parent_directory_key);
  std::string serialised_data_map;
  try {
    if (!data_map.SerializeToString(&serialised_data_map))
      return kBadDataMap;
  }
  catch(const std::exception&) {
    return kBadDataMap;
  }
  std::string xor_hash_extended;
  if (!ResizeObfuscationHash(xor_hash, serialised_data_map.size(),
                             &xor_hash_extended))
    return kEncryptError;
  crypto::Crypto encryptor;
  encryptor.set_symm_algorithm(crypto::AES_256);
  *encrypted_data_map = encryptor.SymmEncrypt(
      encryptor.Obfuscate(serialised_data_map, xor_hash_extended, crypto::XOR),
      "", crypto::STRING_STRING, encrypt_hash);
  return encrypted_data_map->empty() ? kEncryptError : kSuccess;
}

int DecryptDataMap(const std::string &encrypted_data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   DataMap *data_map) {
  if (!data_map)
    return kNullPointer;
  data_map->Clear();
  std::string encrypt_hash = SHA512(parent_directory_key + this_directory_key);
  std::string xor_hash = SHA512(this_directory_key + parent_directory_key);
  crypto::Crypto decryptor;
  decryptor.set_symm_algorithm(crypto::AES_256);
  std::string intermediate = decryptor.SymmDecrypt(encrypted_data_map, "",
                             crypto::STRING_STRING, encrypt_hash);
  std::string xor_hash_extended;
  if (intermediate.empty() ||
      !ResizeObfuscationHash(xor_hash, intermediate.size(), &xor_hash_extended))
    return kBadDataMap;
  std::string serialised_data_map = decryptor.Obfuscate(intermediate,
                                    xor_hash_extended, crypto::XOR);
  try {
    if (serialised_data_map.empty() ||
        !data_map->ParseFromString(serialised_data_map)) {
      return kDecryptError;
    }
  }
  catch(const std::exception&) {
    return kDecryptError;
  }
  return kSuccess;
}

int CheckEntry(std::tr1::shared_ptr<DataIOHandler> input_handler) {
  // if file size < 2 bytes, it's too small to chunk
  boost::uint64_t filesize(0);
  input_handler->Size(&filesize);
  return filesize < 2 ? kInputTooSmall : kSuccess;
}

bool CheckCompressibility(std::tr1::shared_ptr<DataIOHandler> input_handler) {
  int nElements = sizeof(kNoCompressType) / sizeof(kNoCompressType[0]);
  if (input_handler->Type() == DataIOHandler::kFileIOHandler) {
    try {
      std::string extension = std::tr1::static_pointer_cast<FileIOHandler>(
          input_handler)->FilePath().extension().string();
      std::set<std::string> no_comp(kNoCompressType,
                                    kNoCompressType + nElements);
      if (no_comp.find(extension) != no_comp.end())
        return false;
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("In CheckCompressibility - %s\n", e.what());
#endif
      return false;
    }
  }

  size_t test_chunk_size = 256;
  size_t pointer = 0;
  boost::uint64_t pre_comp_file_size = 0;
  if (!input_handler->Size(&pre_comp_file_size))
    return false;

  if (!input_handler->Open())
    return false;
  if (2 * test_chunk_size > pre_comp_file_size)
    test_chunk_size = static_cast<boost::uint16_t>(pre_comp_file_size);
  else
    pointer = static_cast<size_t>(pre_comp_file_size / 2);
  std::string uncompressed_test_chunk;
  if (!input_handler->SetGetPointer(pointer) ||
      !input_handler->Read(test_chunk_size, &uncompressed_test_chunk)) {
    return false;
  }
  input_handler->Close();
  try {
    crypto::Crypto crypto_obj;
    std::string compressed_test_chunk =
        crypto_obj.Compress(uncompressed_test_chunk, "", 9,
                            crypto::STRING_STRING);
    double ratio = compressed_test_chunk.size() / test_chunk_size;
    return (ratio <= 0.9);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Error in checking compressibility: %s\n", e.what());
#endif
    return false;
  }
}

bool CalculateChunkSizes(const std::string &file_hash,
                         std::tr1::shared_ptr<DataIOHandler> input_handler,
                         DataMap *data_map,
                         boost::uint16_t *chunk_count) {
  boost::uint64_t file_size = 0;
  if (!input_handler->Size(&file_size))
    return false;
  boost::uint64_t this_avg_chunk_size = kDefaultChunkSize;

  // If the file is so large it will split into more chunks than kMaxChunks,
  // resize chunks to yield no more than kMaxChunks
  if (file_size / kMaxChunks > kDefaultChunkSize) {
    this_avg_chunk_size = file_size / kMaxChunks;
    *chunk_count = kMaxChunks;
  } else if (file_size == 4) {
    // set chunk_size for file of size 4 bytes to avoid only 2 chunks being
    // generated
    this_avg_chunk_size = 1;
    *chunk_count = 3;
  } else if (file_size / kMinChunks < kDefaultChunkSize) {
    // If the file is so small it will split into less chunks than kMinChunks,
    // resize chunks to yield no less than kMinChunks
    this_avg_chunk_size = file_size / kMinChunks;
    // If file is not exactly divisible into the minimum number of chunks,
    // add 1 to chunk size
    if (file_size % kMinChunks != 0)
      ++this_avg_chunk_size;
    *chunk_count = kMinChunks;
  } else {
    // otherwise, select chunk size to yield roughly same sized chunks (i.e. no
    // tiny last chunk)
    *chunk_count =
        static_cast<boost::uint16_t>(file_size / this_avg_chunk_size);
    this_avg_chunk_size = (file_size / *chunk_count);
  }

  // iterate through each chunk except the last, adding or subtracting bytes
  // based on the file hash
  boost::uint64_t remainder = file_size;

  for (int this_chunk = 0; this_chunk < *chunk_count - 1; ++this_chunk) {
    // get maximum ratio to add/subtract from chunks so that we're not left
    // with a negative-sized final chunk should all previous chunks have had
    // maximum bytes added to them.
    double max_ratio = 1.0 / (kMaxChunks * 16);

    boost::uint64_t this_chunk_size =
        static_cast<boost::uint64_t>(this_avg_chunk_size *
        (1 + (max_ratio * ChunkAddition(file_hash.c_str()[this_chunk]))));
    if (this_chunk_size == 0)
      ++this_chunk_size;
    data_map->add_chunk_size(this_chunk_size);
    remainder -= this_chunk_size;
  }
  // get size of last chunk
  data_map->add_chunk_size(remainder);
  return true;
}

int ChunkAddition(char hex_digit) {
  if (hex_digit > 47 && hex_digit < 58)
    return hex_digit - 56;
  if (hex_digit > 64 && hex_digit < 71)
    return hex_digit - 63;
  if (hex_digit > 96 && hex_digit < 103)
    return hex_digit - 95;
  return 0;
}

bool GeneratePreEncryptionHashes(
    std::tr1::shared_ptr<DataIOHandler> input_handler,
    DataMap *data_map) {
  if (!input_handler->Open())
    return false;
  boost::uint64_t pointer = 0;

  int chunk_count = data_map->chunk_size_size();
  for (int i = 0; i < chunk_count; ++i) {
    boost::uint64_t this_chunk_size = data_map->chunk_size(i);
    size_t buffer_size = kDefaultChunkletSize;
    if (this_chunk_size < kDefaultChunkletSize)
      buffer_size = static_cast<boost::uint16_t>(this_chunk_size);
    std::string buffer;
    if (!input_handler->SetGetPointer(pointer) ||
        !input_handler->Read(buffer_size, &buffer)) {
      return false;
    }
    std::string pre_encryption_hash = SHA512(buffer);
    pointer += this_chunk_size;
    // ensure uniqueness of all pre-encryption hashes
    // HashUnique(pre_encryption_hash, data_map, true);
    data_map->add_chunk_name(pre_encryption_hash);
  }
  input_handler->Close();
  return true;
}

bool ResizeObfuscationHash(const std::string &input,
                           const size_t &required_size,
                           std::string *resized_data) {
  if (!resized_data)
    return false;
  resized_data->clear();
  resized_data->reserve(required_size);
  std::string hash(input);
  while (resized_data->size() < required_size) {
    hash = SHA512(hash);
    resized_data->append(hash);
  }
  resized_data->resize(required_size);
  return true;
}

bool HashUnique(const DataMap &data_map,
                bool pre_encryption,
                std::string *hash) {
// TODO(Fraser#5#): do validity check or diff (if chunk size > some minimum?)
  int hash_count;
  if (pre_encryption)
    hash_count = data_map.chunk_name_size();
  else
    hash_count = data_map.encrypted_chunk_name_size();
  // check uniqueness of pre-encryption hash
  if (pre_encryption) {
    if (hash_count>0) {
      for (int i = 0; i < hash_count; ++i) {
        if (*hash == data_map.chunk_name(i)) {
          char last = hash->at(hash->length() - 1);
          hash->resize(hash->length() - 1);
          hash->insert(0, 1, last);
          HashUnique(data_map, pre_encryption, hash);
        }
      }
    }
  } else {  // check uniqueness of post-encryption hash
    if (hash_count>0) {
      for (int i = 0; i < hash_count; ++i) {
        if (*hash == data_map.encrypted_chunk_name(i)) {
          char last = hash->at(hash->length() - 1);
          hash->resize(hash->length() - 1);
          hash->insert(0, 1, last);
          HashUnique(data_map, pre_encryption, hash);
        }
      }
    }
  }
  return true;
}

std::string SHA512(const fs::path &file_path) {  // files
  crypto::Crypto file_crypto;
  file_crypto.set_hash_algorithm(crypto::SHA_512);
  return file_crypto.Hash(file_path.string(), "", crypto::FILE_STRING, false);
}

std::string SHA512(const std::string &content) {  // strings
  crypto::Crypto string_crypto;
  string_crypto.set_hash_algorithm(crypto::SHA_512);
  return string_crypto.Hash(content, "", crypto::STRING_STRING, false);
}

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe
