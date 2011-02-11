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
 * @todo  Allow for different types of obfuscation and encryption, including an
 *        option for no obf. and/or no enc.
 * @todo  Add support for large DataMaps (recursion).
 */

#include "maidsafe-encrypt/utils.h"

#include <set>

#include "maidsafe-dht/common/crypto.h"
#include "maidsafe-dht/common/log.h"
#include "maidsafe-dht/common/utils.h"
#include "maidsafe-encrypt/data_io_handler.h"
#include "maidsafe-encrypt/config.h"

namespace fs = boost::filesystem3;

namespace maidsafe {

namespace encrypt {

namespace utils {

int EncryptContent(std::shared_ptr<DataIOHandler> input_handler,
                   const fs::path &output_dir,
                   bool try_compression,
                   DataMap *data_map) {
  if (!data_map || !input_handler.get()) {
    DLOG(ERROR) << "EncryptContent: One of the pointers is null." << std::endl;
    return kNullPointer;
  }

  std::uint64_t data_size;
  if (!input_handler->Size(&data_size) || data_size < 1 ||
      data_size > kMaxDataSize) {
    DLOG(ERROR) << "EncryptContent: Input data invalid." << std::endl;
    return kInvalidInput;
  }

  if (!input_handler->Open() || !input_handler->SetGetPointer(0)) {
    DLOG(ERROR) << "EncryptContent: Failed to open input." << std::endl;
    return kIoError;
  }

  bool compress(try_compression && CheckCompressibility(input_handler));
  if (compress)
    data_map->compression_type = kGzipCompression;

  if (data_size <= kMaxIncludableDataSize) {
    // No chunking, include data in DataMap
    data_map->chunks.clear();
    if (!input_handler->Read(data_size, &(data_map->content))) {
      DLOG(ERROR) << "EncryptContent: Failed to read content." << std::endl;
      return kIoError;
    }
    input_handler->Close();
    data_map->data_hash = crypto::Hash<crypto::SHA512>(data_map->content);
    if (compress) {
      data_map->content = crypto::Compress(data_map->content,
                                           kCompressionLevel);
      if (data_map->content.empty()) {
        DLOG(ERROR) << "EncryptContent: Failed to compress content."
                    << std::endl;
        return kCompressionError;
      }
    }
    return kSuccess;
  }

  // TODO data hash needed?
  if (input_handler->Type() == DataIOHandler::kFileIOHandler) {
    data_map->data_hash = crypto::HashFile<crypto::SHA512>(
        std::static_pointer_cast<FileIOHandler>(input_handler)->FilePath());
  } else {
    data_map->data_hash = crypto::Hash<crypto::SHA512>(
        std::static_pointer_cast<StringIOHandler>(input_handler)->Data());
  }

  // FIXME find method to guarantee constant chunk size with compression
  compress = false;
  data_map->compression_type = kNoCompression;

  std::vector<std::uint32_t> chunk_sizes;
  if (!CalculateChunkSizes(data_size, &chunk_sizes) || chunk_sizes.size() < 3) {
    DLOG(ERROR) << "EncryptContent: CalculateChunkSizes failed." << std::endl;
    return kChunkSizeError;
  }

  std::uint32_t chunk_count(chunk_sizes.size());
  std::string chunk_content[3], chunk_hash[3];  // sliding window of size 3

  // read the first 2 chunks and calculate their hashes
  if (!input_handler->Read(chunk_sizes[0], &(chunk_content[0])) ||
      !input_handler->Read(chunk_sizes[1], &(chunk_content[1]))) {
    DLOG(ERROR) << "EncryptContent: Failed to read content." << std::endl;
    return kIoError;
  }
  chunk_hash[0] = crypto::Hash<crypto::SHA512>(chunk_content[0]);
  chunk_hash[1] = crypto::Hash<crypto::SHA512>(chunk_content[1]);

  for (std::uint32_t i = 0; i < chunk_count; ++i) {
    // read the second next chunk and calculate its hash
    if (i + 2 < chunk_count) {
      std::uint32_t idx = (i + 2) % 3;
      if (!input_handler->Read(chunk_sizes[i + 2], &(chunk_content[idx]))) {
        DLOG(ERROR) << "EncryptContent: Failed to read content." << std::endl;
        return kIoError;
      }
      chunk_hash[idx] = crypto::Hash<crypto::SHA512>(chunk_content[idx]);
    } else {
      std::uint32_t idx = (i + 2) % chunk_count;
      chunk_hash[idx] = data_map->chunks[idx].pre_hash;
      input_handler->Close();
    }

    if (compress) {
      chunk_content[i % 3] = crypto::Compress(chunk_content[i % 3],
                                              kCompressionLevel);
      if (chunk_content[i % 3].empty()) {
        DLOG(ERROR) << "EncryptContent: Failed to compress chunk content."
                    << std::endl;
        return kCompressionError;
      }
    }

    ChunkDetails chunk;
    chunk.pre_hash = chunk_hash[i % 3];
    chunk.pre_size = chunk_sizes[i];

    if (chunk_sizes[i] <= kMaxIncludableChunkSize) {
      chunk.content = chunk_content[i % 3];
      chunk.size = chunk_content[i % 3].size();
      // sic: chunk.hash left empty
    } else {
      std::string encryption_key(
          chunk_hash[(i + 1) % 3].substr(0, crypto::AES256_KeySize));
      std::string encryption_iv(
          chunk_hash[(i + 1) % 3].substr(crypto::AES256_KeySize,
                                         crypto::AES256_IVSize));
      std::string obfuscation_pad;
      ResizeObfuscationHash(chunk_hash[(i + 2) % 3],
                            chunk_content[i % 3].size(), &obfuscation_pad);

      // obfuscate and encrypt chunk data
      chunk_content[i % 3] = crypto::SymmEncrypt(
          crypto::XOR(chunk_content[i % 3], obfuscation_pad), encryption_key,
          encryption_iv);
      chunk.hash = crypto::Hash<crypto::SHA512>(chunk_content[i % 3]);
      chunk.size = chunk_content[i % 3].size();  // encryption might add padding
      // sic: chunk.content left empty

      // write chunk file
      fs::path chunk_path = output_dir / EncodeToHex(chunk.hash);
      try {
        if (fs::exists(chunk_path))
          fs::remove(chunk_path);
        fs::ofstream chunk_out(chunk_path, fs::ofstream::binary);
        chunk_out << chunk_content[i % 3];
        chunk_out.close();
      }
      catch(const std::exception &e) {
        DLOG(ERROR) << "EncryptContent: Can't write chunk data to "
                    << chunk_path.c_str() << " - " << e.what() << std::endl;
        return kFilesystemError;
      }
    }

    data_map->chunks.push_back(chunk);
  }
  return kSuccess;
}

int DecryptContent(const DataMap &data_map,
                   const fs::path &input_dir,
                   std::shared_ptr<DataIOHandler> output_handler) {
  if (!output_handler)
    return kNullPointer;

  if (!output_handler->Open()) {
    DLOG(ERROR) << "DecryptContent: Output IOhandler failed to open."
                << std::endl;
    return kIoError;
  }

  std::uint32_t chunk_count(data_map.chunks.size());
  if (chunk_count == 0) {
    if (!data_map.content.empty()) {
      if (data_map.compression_type == kNoCompression)
        output_handler->Write(data_map.content);
      else if (data_map.compression_type == kGzipCompression)
        output_handler->Write(crypto::Uncompress(data_map.content));
    }
    output_handler->Close();
    return kSuccess;
  }

  // Decrypt chunklets
  if (!output_handler->Open()) {
    DLOG(ERROR) << "DecryptContent: Output IOhandler failed to open."
                << std::endl;
    return kIoError;
  }

  for (std::uint32_t i = 0; i < chunk_count; ++i) {
    const ChunkDetails &chunk = data_map.chunks[i];
    std::string chunk_content;
    if (!chunk.content.empty()) {
      chunk_content = chunk.content;
    } else {
      // read chunk file
      fs::path chunk_path = input_dir / EncodeToHex(chunk.hash);
      try {
        fs::ifstream chunk_in(chunk_path, fs::ifstream::binary);
        if (!chunk_in.good()) {
          DLOG(ERROR) << "DecryptContent: Failed to open " << chunk_path.c_str()
                      << std::endl;
          return kIoError;
        }
        chunk_in >> chunk_content;
        chunk_in.close();
        if (chunk_content.size() != chunk.size) {
          DLOG(ERROR) << "DecryptContent: Wrong chunk size - "
                      << chunk_path.c_str() << std::endl;
          return kIoError;
        }
      }
      catch(const std::exception &e) {
        DLOG(ERROR) << "DecryptContent: Can't read chunk data from "
                    << chunk_path.c_str() << " - " << e.what() << std::endl;
        return kFilesystemError;
      }

      std::string encryption_hash(data_map.chunks[(i + 1) % chunk_count].hash);
      std::string encryption_key(
          encryption_hash.substr(0, crypto::AES256_KeySize));
      std::string encryption_iv(
          encryption_hash.substr(crypto::AES256_KeySize,
                                 crypto::AES256_IVSize));

      // decrypt and de-obfuscate chunk data
      chunk_content = crypto::SymmDecrypt(chunk_content, encryption_key,
                                          encryption_iv);
      std::string obfuscation_pad;
      ResizeObfuscationHash(data_map.chunks[(i + 2) % chunk_count].hash,
                            chunk_content.size(), &obfuscation_pad);
      chunk_content = crypto::XOR(chunk_content, obfuscation_pad);
    }

    if (data_map.compression_type == kGzipCompression)
      chunk_content = crypto::Uncompress(chunk_content);

    if (chunk_content.size() != chunk.pre_size ||
        crypto::Hash<crypto::SHA512>(chunk_content) != chunk.pre_hash) {
      DLOG(ERROR) << "DecryptContent: Failed restoring chunk data."
                  << std::endl;
      return kDecryptError;
    }

    output_handler->Write(chunk_content);
  }
  output_handler->Close();
  return kSuccess;
}

bool IsCompressedFile(const fs::path &file_path) {
  size_t ext_count = sizeof(kNoCompressType) / sizeof(kNoCompressType[0]);
  std::set<std::string> exts(kNoCompressType, kNoCompressType + ext_count);
  return (exts.find(file_path.extension().string()) != exts.end());
}

/**
 * Takes a small part from the middle of the input data and tries to compress
 * it. If that yields a gain of at least 10%, we assume this can be extrapolated
 * to all the data.
 *
 * @param input_handler The data source.
 * @return True if input data is likely compressible.
 */
bool CheckCompressibility(std::shared_ptr<DataIOHandler> input_handler) {
  size_t test_chunk_size = 256;
  size_t pointer = 0;
  std::uint64_t pre_comp_file_size = 0;
  if (!input_handler->Size(&pre_comp_file_size))
    return false;

  if (!input_handler->Open())
    return false;
  if (2 * test_chunk_size > pre_comp_file_size)
    test_chunk_size = static_cast<size_t>(pre_comp_file_size);
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
 * Limits with fixed 256K chunk size are:
 *   <= kMaxIncludableDataSize ---> to DM
 *   kMaxIncludableDataSize + 1 to kMinChunks * kDefaultChunkSize - 1 --->
 *       size = fsize / kMinChunks
 *   >= kMinChunks * kDefaultChunkSize ---> fixed size + remainder
 *
 * @param data_size Size of the input data.
 * @param chunk_sizes Pointer to a chunk size vector to be populated.
 * @return True if operation was successful.
 */
bool CalculateChunkSizes(std::uint64_t data_size,
                         std::vector<std::uint32_t> *chunk_sizes) {
  if (!chunk_sizes) {
    DLOG(ERROR) << "CalculateChunkSizes: Pointer is NULL."
                << std::endl;
    return false;
  }

  if (data_size <= kMaxIncludableDataSize) {
    DLOG(ERROR) << "CalculateChunkSizes: Data should go directly into DataMap."
                << std::endl;
    return false;
  }

  if (data_size > kMaxDataSize) {
    DLOG(ERROR) << "CalculateChunkSizes: Data too big for chunking."
                << std::endl;
    return false;
  }

  std::uint64_t chunk_count, chunk_size;
  bool fixed_chunks(false);
  if (data_size < kMinChunks * kMaxChunkSize) {
    chunk_count = kMinChunks;
    chunk_size = data_size / kMinChunks;
  } else {
    chunk_count = data_size / kMaxChunkSize;
    chunk_size = kMaxChunkSize;
    fixed_chunks = true;
  }

  std::uint64_t remainder(data_size);
  std::uint64_t limit(fixed_chunks ? chunk_count : chunk_count - 1);
  for (std::uint64_t i = 0; i < limit; ++i) {
    chunk_sizes->push_back(chunk_size);
    remainder -= chunk_size;
  }
  if (remainder != 0)
    chunk_sizes->push_back(remainder);

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
