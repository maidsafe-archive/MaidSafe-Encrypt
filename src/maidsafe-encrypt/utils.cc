/*******************************************************************************
 *  Copyright 2008 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  utils.cc
 * @brief Helper functions for self-encryption engine.
 * @date  2008-09-09
 *
 * @todo  Pass small files (<700 bytes either compressed or uncompressed)
 *        directly to MDM without encrypting them.
 * @todo  Allow for different types of obfuscation and encryption, including an
 *        option for no obf. and/or no enc.
 * @todo  Compress DataMaps as well. If they are too big, chunk them and
 *        generate recursive DataMaps.
 */

#include "maidsafe-encrypt/utils.h"

#include <set>

#include "maidsafe-dht/common/crypto.h"
#include "maidsafe-dht/common/log.h"
#include "maidsafe-dht/common/utils.h"
#include "maidsafe-encrypt/data_io_handler.h"
#include "maidsafe-encrypt/data_map.pb.h"
#include "maidsafe-encrypt/config.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace utils {

int EncryptContent(std::shared_ptr<DataIOHandler> input_handler,
                   const fs::path &output_dir,
                   protobuf::DataMap *data_map,
                   std::map<std::string, fs::path> *to_chunk_store) {
  if (!data_map || !to_chunk_store || !input_handler.get()) {
    DLOG(ERROR) << "EncryptContent: One of the pointers is null." << std::endl;
    return kNullPointer;
  }
  to_chunk_store->clear();
  if (CheckEntry(input_handler) != kSuccess) {
    DLOG(ERROR) << "EncryptContent: CheckEntry failed." << std::endl;
    return kInputTooSmall;
  }

  std::string file_hash(EncodeToHex(data_map->file_hash()));
  if (file_hash.empty()) {
    if (input_handler->Type() == DataIOHandler::kFileIOHandler) {
      file_hash = crypto::HashFile<crypto::SHA512>(
          std::static_pointer_cast<FileIOHandler>(input_handler)->FilePath());
    } else {
      file_hash = crypto::Hash<crypto::SHA512>(
          std::static_pointer_cast<StringIOHandler>(input_handler)->Data());
    }
  }
  data_map->Clear();
  data_map->set_file_hash(file_hash);
  data_map->set_self_encryption_version(kVersion);

  bool compress(CheckCompressibility(input_handler));
  if (compress)
    data_map->set_compression_on(true);

  std::uint16_t chunk_count(0);
  if (!CalculateChunkSizes(file_hash, input_handler, data_map, &chunk_count)) {
    DLOG(ERROR) << "EncryptContent: CalculateChunkSizes failed." << std::endl;
    return kChunkSizeError;
  }

  if (!GeneratePreEncryptionHashes(input_handler, data_map)) {
    DLOG(ERROR) << "EncryptContent: GeneratePreEncryptionHashes failed."
                << std::endl;
    return kPreEncryptionHashError;
  }

  if (!input_handler->Open()) {
    DLOG(ERROR) << "EncryptContent: Failed to open input." << std::endl;
    return kIoError;
  }

  // loop through each chunk
  for (std::uint16_t chunk_no = 0; chunk_no < chunk_count; ++chunk_no) {
    protobuf::Chunk chunk;
    if (compress) {
      int compression_level = 9;
      std::string compr_type("gzip" + IntToString(compression_level));
      chunk.set_compression_type(compr_type);
    }

    // initialise counter for amount of data put into chunk
    std::uint64_t this_chunk_done(0);

    // get pre-encryption hashes for use in obfuscation and encryption
    std::string obfuscate_name = data_map->chunk_name((chunk_no + 2) %
                                                      chunk_count);
    std::string encryption_name = data_map->chunk_name((chunk_no + 1) %
                                                       chunk_count);
    std::string encryption_key = encryption_name.substr(0,
                                                        crypto::AES256_KeySize);
    std::string encryption_iv = encryption_name.substr(crypto::AES256_KeySize,
                                                       crypto::AES256_IVSize);

    // loop through each chunklet
    while (this_chunk_done < data_map->chunk_size(chunk_no)) {
      // set this chunklet's size
      std::uint16_t this_chunklet_size = kDefaultChunkletSize;
      if (data_map->chunk_size(chunk_no) - this_chunk_done < this_chunklet_size)
        this_chunklet_size =
            static_cast<std::uint16_t>(data_map->chunk_size(chunk_no) -
                                       this_chunk_done);

      // save chunklet's size to chunk_ before compression so that correct
      // offset can be applied if required
      chunk.add_pre_compression_chunklet_size(this_chunklet_size);

      // increment chunk size counter before compression
      this_chunk_done += this_chunklet_size;

      // get chunklet from input file/string
      std::string this_chunklet;
      if (!input_handler->Read(this_chunklet_size, &this_chunklet)) {
        DLOG(ERROR) << "EncryptContent: Failed to read size of a chunklet."
                    << std::endl;
        return kIoError;
      }

      // compress if required and reset this chunklet size
      if (compress) {
        this_chunklet = crypto::Compress(this_chunklet, 9);
        if (this_chunklet.empty()) {
          DLOG(ERROR) << "EncryptContent: Failed to compress chunklet."
                      << std::endl;
          return kCompressionError;
        }
        this_chunklet_size = this_chunklet.size();
      }

      // adjust size of obfuscate hash to match size of chunklet
      std::string resized_obs_hash;
      ResizeObfuscationHash(obfuscate_name, this_chunklet_size,
                            &resized_obs_hash);

      // output encrypted chunklet
      std::string encrypted_chunklet = crypto::SymmEncrypt(
          crypto::XOR(this_chunklet, resized_obs_hash), encryption_key,
          encryption_iv);
      chunk.add_chunklet(encrypted_chunklet);
    }

    // assign temporary name for chunk
    fs::path temp_chunk_name = output_dir;
    temp_chunk_name /= EncodeToHex(data_map->chunk_name(chunk_no));

    // remove any old copies of the chunk
    try {
      if (fs::exists(temp_chunk_name))
        fs::remove(temp_chunk_name);
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "EncryptContent: Removing exception: " << e.what()
                  << std::endl;
      return kFilesystemError;
    }

    // serialise the chunk to the temp output fstream
    std::ofstream this_chunk_out(temp_chunk_name.string().c_str(),
                                 std::ofstream::binary);
    chunk.SerializeToOstream(&this_chunk_out);
    this_chunk_out.close();
    std::string post_enc_hash =
        crypto::HashFile<crypto::SHA512>(temp_chunk_name);
    fs::path correct_chunk_name(output_dir / EncodeToHex(post_enc_hash));
    try {
      fs::rename(temp_chunk_name, correct_chunk_name);
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "EncryptContent: Renaming exception: " << e.what()
                  << std::endl;
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

int DecryptContent(const protobuf::DataMap &data_map,
                   std::vector<fs::path> chunk_paths,
                   const std::uint64_t &offset,
                   std::shared_ptr<DataIOHandler> output_handler) {
  if (!output_handler)
    return kNullPointer;
  std::string file_hash = EncodeToHex(data_map.file_hash());

  // if there is no file hash, then the file has never been encrypted
  if (file_hash.empty()) {
    DLOG(ERROR) << "DecryptContent: File hash empty." << std::endl;
    return kNoFileHash;
  }

  std::uint16_t chunk_count =
      static_cast<std::uint16_t>(data_map.chunk_name_size());
  if (chunk_count == 0) {
    output_handler->Open();
    output_handler->Close();
    return kSuccess;
  }

  if (data_map.self_encryption_version() != kVersion) {
    DLOG(ERROR) << "DecryptContent: Cannot decrypt - incompatible decryption "
                   "engine (version " << kVersion << ") being applied to data "
                   "encrypted with version "
                << data_map.self_encryption_version() << std::endl;
    return kWrongVersion;
  }

  // TODO(Fraser#5#): implement offset
  if (offset != 0) {
    DLOG(ERROR) << "DecryptContent:  non-zero offset not supported."
                << std::endl;
    return kOffsetError;
  } else {
    // Decrypt chunklets
    if (!output_handler->Open()) {
      DLOG(ERROR) << "DecryptContent: Output IOhandler failed to open."
                  << std::endl;
      return kIoError;
    }

    // loop through each chunk
    for (std::uint16_t chunk_no = 0; chunk_no < chunk_count; ++chunk_no) {
      // get chunk
      protobuf::Chunk chunk;
      std::vector<fs::path>::iterator it = chunk_paths.begin();
      while (it != chunk_paths.end()) {
        std::string enc = EncodeToHex(data_map.encrypted_chunk_name(chunk_no));
        if ((*it).filename().string() ==
            EncodeToHex(data_map.encrypted_chunk_name(chunk_no))) {
          break;
        } else {
          ++it;
        }
      }

      if (it == chunk_paths.end()) {
        DLOG(ERROR) << "DecryptContent: Chunk path not provided."
                    << std::endl;
        return kChunkPathNotFound;
      }
      fs::path chunk_path(*it);
      chunk_paths.erase(it);

      fs::ifstream fin(chunk_path, std::ifstream::binary);
      if (!fin.good()) {
        DLOG(ERROR) << "DecryptContent: Failed to open ifstream to chunk path."
                    << std::endl;
        return kIoError;
      }
      if (!chunk.ParseFromIstream(&fin)) {
        DLOG(ERROR) << "DecryptContent: Failed to parse chunk from ifstream."
                    << std::endl;
        return kBadChunk;
      }

      // check if compression was used during encryption
      bool compressed(!chunk.compression_type().empty());

      // get pre-encryption hashes for use in de-obfuscation and decryption
      std::string obfuscate_name(data_map.chunk_name((chunk_no + 2) %
                                                     chunk_count));
      std::string encryption_name(data_map.chunk_name((chunk_no + 1) %
                                                      chunk_count));
      std::string encryption_key(
          encryption_name.substr(0, crypto::AES256_KeySize));
      std::string encryption_iv(encryption_name.substr(crypto::AES256_KeySize,
                                                       crypto::AES256_IVSize));

      // loop through each chunklet
      for (int i = 0; i < chunk.chunklet_size(); ++i) {
        std::string this_chunklet = chunk.chunklet(i);

        // adjust size of obfuscate hash to match size of chunklet
        std::string resized_obs_hash;
        utils::ResizeObfuscationHash(
            obfuscate_name,
            static_cast<boost::uint16_t>(this_chunklet.size()),
            &resized_obs_hash);
        std::string decrypted_chunklet(
            crypto::XOR(crypto::SymmDecrypt(this_chunklet, encryption_key,
                                            encryption_iv),
            resized_obs_hash));

        // decompress if required
        if (compressed)
          decrypted_chunklet = crypto::Uncompress(decrypted_chunklet);
        output_handler->Write(decrypted_chunklet);
      }
      fin.close();
    }
    output_handler->Close();
  }
  return kSuccess;
}

int EncryptDataMap(const protobuf::DataMap &data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   std::string *encrypted_data_map) {
  if (!encrypted_data_map)
    return kNullPointer;
  encrypted_data_map->clear();
  std::string encrypt_hash(crypto::Hash<crypto::SHA512>(parent_directory_key +
                                                        this_directory_key));
  std::string encrypt_key(encrypt_hash.substr(0, crypto::AES256_KeySize));
  std::string encrypt_iv(encrypt_hash.substr(crypto::AES256_KeySize,
                                             crypto::AES256_IVSize));
  std::string xor_hash(crypto::Hash<crypto::SHA512>(this_directory_key +
                                                    parent_directory_key));
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
  *encrypted_data_map = crypto::SymmEncrypt(
      crypto::XOR(serialised_data_map, xor_hash_extended),
      encrypt_key, encrypt_iv);
  return encrypted_data_map->empty() ? kEncryptError : kSuccess;
}

int DecryptDataMap(const std::string &encrypted_data_map,
                   const std::string &this_directory_key,
                   const std::string &parent_directory_key,
                   protobuf::DataMap *data_map) {
  if (!data_map) {
    DLOG(ERROR) << "DecryptDataMap: data_map pointer null." << std::endl;
    return kNullPointer;
  }

  data_map->Clear();
  std::string encrypt_hash(crypto::Hash<crypto::SHA512>(parent_directory_key +
                                                        this_directory_key));
  std::string encrypt_key(encrypt_hash.substr(0, crypto::AES256_KeySize));
  std::string encrypt_iv(encrypt_hash.substr(crypto::AES256_KeySize,
                                             crypto::AES256_IVSize));
  std::string xor_hash(crypto::Hash<crypto::SHA512>(this_directory_key +
                                                    parent_directory_key));
  std::string intermediate(crypto::SymmDecrypt(encrypted_data_map,
                                               encrypt_key, encrypt_iv));
  std::string xor_hash_extended;
  if (intermediate.empty() ||
      !ResizeObfuscationHash(xor_hash, intermediate.size(),
                             &xor_hash_extended)) {
    DLOG(ERROR) << "DecryptDataMap: Intermediate datamap encryption failed "
                   "or resizing of obfuscation hash failed." << std::endl;
    return kBadDataMap;
  }

  std::string serialised_data_map(crypto::XOR(intermediate, xor_hash_extended));
  try {
    if (serialised_data_map.empty() ||
        !data_map->ParseFromString(serialised_data_map)) {
      DLOG(ERROR) << "DecryptDataMap: XORing failed or parsing from datamap "
                     "failed." << std::endl;
      return kDecryptError;
    }
  }
  catch(const std::exception&) {
    DLOG(ERROR) << "DecryptDataMap: Parsing datamap exception." << std::endl;
    return kDecryptError;
  }
  return kSuccess;
}

int CheckEntry(std::shared_ptr<DataIOHandler> input_handler) {
  // if file size < 2 bytes, it's too small to chunk
  boost::uint64_t filesize(0);
  input_handler->Size(&filesize);
  return filesize < 2 ? kInputTooSmall : kSuccess;
}

/**
 * Takes a small part from the middle of the input data and tries to compress
 * it. If that yields a gain of at least 10%, we assume this can be extrapolated
 * to all the data.
 *
 * If the input data is a file, we check its size against a list of known
 * uncompressible file formats to save above step.
 *
 * @param input_handler The data source.
 * @return True if input data is likely compressible.
 */
bool CheckCompressibility(std::shared_ptr<DataIOHandler> input_handler) {
  int nElements = sizeof(kNoCompressType) / sizeof(kNoCompressType[0]);
  if (input_handler->Type() == DataIOHandler::kFileIOHandler) {
    try {
      std::string extension(
          std::static_pointer_cast<FileIOHandler>(
              input_handler)->FilePath().extension().string());
      std::set<std::string> no_comp(kNoCompressType,
                                    kNoCompressType + nElements);
      if (no_comp.find(extension) != no_comp.end())
        return false;
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "CheckCompressibility: " << e.what() << std::endl;
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
  std::string test_chunk(crypto::Compress(uncompressed_test_chunk, 9));
  if (!test_chunk.empty()) {
    double ratio = test_chunk.size() / test_chunk_size;
    return (ratio <= 0.9);
  } else {
    DLOG(ERROR) << "CheckCompressibility: Error checking compressibility."
                << std::endl;
    return false;
  }
}

/**
 * @param file_hash Pre-encryption hash of the input data.
 * @param input_handler The data source.
 * @param data_map Pointer to the DataMap to be populated.
 * @param chunk_count Pointer to the number of chunks to be populated.
 * @return True if operation was successful.
 */
// Limits with fixed 256K chunk size are:
//    <= kMinAcceptableFileSize ---> to DM
//    kMinAcceptableFileSize + 1 to
//        kMinChunks * kDefaultChunkSize - 1 ---> size = fsize / kMinChunks
//    >= kMinChunks * kDefaultChunkSize ---> fixed size
bool CalculateChunkSizes(const std::string &file_hash,
                         std::shared_ptr<DataIOHandler> input_handler,
                         protobuf::DataMap *data_map,
                         std::uint16_t *chunk_count) {
  data_map->set_file_hash(file_hash);
  std::uint64_t file_size(0);
  if (!input_handler->Size(&file_size)) {
    DLOG(ERROR) << "CalculateChunkSizes: Error reading handler size."
                << std::endl;
    return false;
  }

  if (file_size <= kMinAcceptableFileSize) {
    DLOG(INFO) << "CalculateChunkSizes: File should go directly into DataMap."
               << std::endl;
    return true;
  }

  std::uint64_t this_chunk_size;
  bool fixed_chunks(false);
  if (file_size < kMinChunks * kDefaultChunkSize) {
    *chunk_count = kMinChunks;
    this_chunk_size = file_size / kMinChunks;
  } else {
    *chunk_count = file_size / kDefaultChunkSize;
    this_chunk_size = kDefaultChunkSize;
    fixed_chunks = true;
  }

  // If the file is so large it will split into more chunks than kMaxChunks,
  // resize chunks to yield no more than kMaxChunks
//  if (file_size / kMaxChunks > kDefaultChunkSize) {
//    this_avg_chunk_size = file_size / kMaxChunks;
//    *chunk_count = kMaxChunks;
//  } else if (file_size == 4) {
//    // set chunk_size for file of size 4 bytes to avoid only 2 chunks being
//    // generated
//    this_avg_chunk_size = 1;
//    *chunk_count = 3;
//  } else if (file_size / kMinChunks < kDefaultChunkSize) {
//    // If the file is so small it will split into less chunks than kMinChunks,
//    // resize chunks to yield no less than kMinChunks
//    this_avg_chunk_size = file_size / kMinChunks;
//    // If file is not exactly divisible into the minimum number of chunks,
//    // add 1 to chunk size
//    if (file_size % kMinChunks != 0)
//      ++this_avg_chunk_size;
//    *chunk_count = kMinChunks;
//  } else {
//    // otherwise, select chunk size to yield roughly same sized chunks (i.e. no
//    // tiny last chunk)
//    *chunk_count =
//        static_cast<std::uint16_t>(file_size / this_avg_chunk_size);
//    this_avg_chunk_size = (file_size / *chunk_count);
//  }

  // iterate through each chunk except the last, adding or subtracting bytes
  // based on the file hash
  std::uint64_t remainder(file_size);
  std::uint16_t limit(fixed_chunks ? *chunk_count : *chunk_count - 1);
  for (int this_chunk = 0; this_chunk < limit; ++this_chunk) {
    // get maximum ratio to add/subtract from chunks so that we're not left
    // with a negative-sized final chunk should all previous chunks have had
    // maximum bytes added to them.
//    double max_ratio = 1.0 / (kMaxChunks * 16);
//
//        static_cast<std::uint64_t>(this_avg_chunk_size *
//        (1 + (max_ratio * ChunkAddition(file_hash.c_str()[this_chunk]))));
//    if (this_chunk_size == 0)
//      ++this_chunk_size;
    data_map->add_chunk_size(this_chunk_size);
    remainder -= this_chunk_size;
  }
  // get size of last chunk
//  std::cout << remainder << " - " << file_size << " - " << *chunk_count
//            << std::endl;
  if (remainder != 0) {
    data_map->add_chunk_size(remainder);
    if (fixed_chunks)
      ++(*chunk_count);
  }

  return true;
}

/**
 * The result is a positive or negative int based on the hex character passed
 * in, to allow for random chunk sizes. '0' returns -8, '1' returns -7, etc...
 * through to 'f', which returns 7.
 *
 * @param hex_digit A hex character, must be between 0 and F.
 * @return Value to be added to the chunk size.
 */
int ChunkAddition(char hex_digit) {
  if (hex_digit > 47 && hex_digit < 58)
    return hex_digit - 56;
  if (hex_digit > 64 && hex_digit < 71)
    return hex_digit - 63;
  if (hex_digit > 96 && hex_digit < 103)
    return hex_digit - 95;
  return 0;
}

bool GeneratePreEncryptionHashes(std::shared_ptr<DataIOHandler> input_handler,
                                 protobuf::DataMap *data_map) {
  if (!input_handler.get() || !input_handler->Open() || !data_map) {
    DLOG(ERROR) << "GeneratePreEncryptionHashes: Handler null or closed or "
                   "data_map null." << std::endl;
    return false;
  }

  std::uint64_t pointer(0);
  int chunk_count = data_map->chunk_size_size();
  for (int i = 0; i < chunk_count; ++i) {
    std::uint64_t this_chunk_size = data_map->chunk_size(i);
    size_t buffer_size = kDefaultChunkletSize;
    if (this_chunk_size < kDefaultChunkletSize)
      buffer_size = static_cast<boost::uint16_t>(this_chunk_size);
    std::string buffer;
    if (!input_handler->SetGetPointer(pointer) ||
        !input_handler->Read(buffer_size, &buffer)) {
      DLOG(ERROR) << "GeneratePreEncryptionHashes: Failed to set pointer or"
                     " to read from the handler." << std::endl;
      return false;
    }
    std::string pre_encryption_hash(crypto::Hash<crypto::SHA512>(buffer));
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
  if (!resized_data) {
    DLOG(ERROR) << "ResizeObfuscationHash: resized_data null." << std::endl;
    return false;
  }
  resized_data->clear();
  resized_data->reserve(required_size);
  std::string hash(input);
  while (resized_data->size() < required_size) {
    hash = crypto::Hash<crypto::SHA512>(hash);
    resized_data->append(hash);
  }
  resized_data->resize(required_size);
  return true;
}

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe
