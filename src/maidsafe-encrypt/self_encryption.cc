/*******************************************************************************
 *  Copyright 2008-2011 maidsafe.net limited                                   *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  self_encryption.cc
 * @brief Provides self-encryption/self-decryption functionality.
 * @date  2008-09-09
 */

#include "maidsafe-encrypt/self_encryption.h"

#include <array>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <vector>

#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-encrypt/config.h"
#include "maidsafe-encrypt/data_map.h"
#include "maidsafe-encrypt/self_encryption_stream.h"
#include "maidsafe-encrypt/utils.h"
#include "boost/filesystem/fstream.hpp"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

/**
 * Splits data from input stream into chunks, compresses them if possible,
 * obfuscates and then encrypts them. Chunk metadata is stored in the DataMap.
 *
 * @param input_stream The stream providing data to self-encrypt.
 * @param try_compression Whether to attempt compression of the data.
 * @param self_encryption_params Parameters for the self-encryption algorithm.
 * @param data_map DataMap to be populated with chunk metadata.
 * @param chunk_store ChunkStore for resulting chunks.
 * @return Result of the operation.
 */
int SelfEncrypt(std::shared_ptr<std::istream> input_stream,
                bool try_compression,
                const SelfEncryptionParams &self_encryption_params,
                std::shared_ptr<DataMap> data_map,
                std::shared_ptr<ChunkStore> chunk_store) {
  if (!input_stream || !data_map || !chunk_store) {
    DLOG(ERROR) << "SelfEncrypt: One of the pointers is null." << std::endl;
    return kNullPointer;
  }

  if (!utils::CheckParams(self_encryption_params)) {
    DLOG(ERROR) << "SelfEncrypt: Invalid parameters passed." << std::endl;
    return kInvalidInput;
  }

  if (!input_stream->good()) {
    DLOG(ERROR) << "SelfEncrypt: Input stream is invalid."
                << std::endl;
    return kIoError;
  }

  SelfEncryptionStream output_stream(data_map, chunk_store,
                                     self_encryption_params);

  std::streamsize buffer_size(io::optimal_buffer_size(output_stream));
  std::streamsize written_size(0);
  char *buffer = new char[buffer_size];
  while (input_stream->good()) {
    input_stream->read(buffer, buffer_size);
    output_stream.write(buffer, input_stream->gcount());
    written_size += input_stream->gcount();
  }
  delete buffer;

  output_stream.flush();

  if (written_size != data_map->size) {
    DLOG(ERROR) << "SelfEncrypt: Amount of data written (" << written_size
                << ") does not match reported data size (" << data_map->size
                << ")." << std::endl;
    return kEncryptError;
  }

  if (!input_stream->eof() || !output_stream.good()) {
    DLOG(ERROR) << "SelfEncrypt: Stream operation failed." << std::endl;
    return kEncryptError;
  }

  return kSuccess;
}

/**
 * Splits data from input string into chunks, compresses them if possible,
 * obfuscates and then encrypts them. Chunk metadata is stored in the DataMap.
 *
 * @param input_string The string providing data to self-encrypt.
 * @param try_compression Whether to attempt compression of the data.
 * @param self_encryption_params Parameters for the self-encryption algorithm.
 * @param data_map DataMap to be populated with chunk metadata.
 * @param chunk_store ChunkStore for resulting chunks.
 * @return Result of the operation.
 */
int SelfEncrypt(const std::string &input_string,
                bool try_compression,
                const SelfEncryptionParams &self_encryption_params,
                std::shared_ptr<DataMap> data_map,
                std::shared_ptr<ChunkStore> chunk_store) {
  std::shared_ptr<std::istringstream> input_stream(new std::istringstream(
      input_string));
  return SelfEncrypt(input_stream, try_compression, self_encryption_params,
                     data_map, chunk_store);
}

/**
 * Splits data from input file into chunks, compresses them if possible,
 * obfuscates and then encrypts them. Chunk metadata is stored in the DataMap.
 *
 * Based on the file extension, a decision is made whether an attempt to
 * compress the data should be undertaken. Use SelfEncrypt for streams if you
 * want to override this behaviour.
 *
 * @param input_file The file providing data to self-encrypt.
 * @param self_encryption_params Parameters for the self-encryption algorithm.
 * @param data_map DataMap to be populated with chunk metadata.
 * @param chunk_store ChunkStore for resulting chunks.
 * @return Result of the operation.
 */
int SelfEncrypt(const fs::path &input_file,
                const SelfEncryptionParams &self_encryption_params,
                std::shared_ptr<DataMap> data_map,
                std::shared_ptr<ChunkStore> chunk_store) {
  std::shared_ptr<fs::ifstream> input_stream(new fs::ifstream(
      input_file, std::ios::in | std::ios::binary));
  int result(SelfEncrypt(input_stream, !utils::IsCompressedFile(input_file),
                         self_encryption_params, data_map, chunk_store));
  input_stream->close();
  return result;
}

/**
 * All required chunks should be available in the given ChunkStore.
 *
 * @param data_map DataMap with chunk information.
 * @param chunk_store ChunkStore providing required chunks.
 * @param output_stream Stream receiving resulting data.
 * @return Result of the operation.
 */
int SelfDecrypt(std::shared_ptr<DataMap> data_map,
                std::shared_ptr<ChunkStore> chunk_store,
                std::shared_ptr<std::ostream> output_stream) {
  if (!data_map || !chunk_store || !output_stream)
    return kNullPointer;

  if (!output_stream->good()) {
    DLOG(ERROR) << "SelfDecrypt: Output stream is invalid."
                << std::endl;
    return kIoError;
  }

  SelfEncryptionStream input_stream(data_map, chunk_store);

  // input_stream >> output_stream->rdbuf();
  std::streamsize buffer_size(io::optimal_buffer_size(input_stream));
  char *buffer = new char[buffer_size];
  while (input_stream.good()) {
    input_stream.read(buffer, buffer_size);
    output_stream->write(buffer, input_stream.gcount());
  }
  delete buffer;

  std::streamsize copied_size(output_stream->tellp());

  if (copied_size != data_map->size) {
    DLOG(ERROR) << "SelfDecrypt: Amount of data read (" << copied_size
                << ") does not match total data size (" << data_map->size
                << ")." << std::endl;
    return kDecryptError;
  }

  if (!input_stream.eof() || !output_stream->good()) {
    DLOG(ERROR) << "SelfDecrypt: Stream operation failed." << std::endl;
    return kDecryptError;
  }

  return kSuccess;
}

/**
 * All required chunks should be available in the given ChunkStore.
 *
 * @param data_map DataMap with chunk information.
 * @param chunk_store ChunkStore providing required chunks.
 * @param output_string String receiving resulting data.
 * @return Result of the operation.
 */
int SelfDecrypt(std::shared_ptr<DataMap> data_map,
                std::shared_ptr<ChunkStore> chunk_store,
                std::string *output_string) {
  if (!output_string)
    return kNullPointer;
  std::shared_ptr<std::ostringstream> output_stream(new std::ostringstream);
  int result(SelfDecrypt(data_map, chunk_store, output_stream));
  *output_string = output_stream->str();
  return result;
}

/**
 * All required chunks should be available in the given ChunkStore.
 *
 * @param data_map DataMap with chunk information.
 * @param chunk_store ChunkStore providing required chunks.
 * @param overwrite Whether to overwrite an already existing output file.
 * @param output_file Path to file receiving resulting data.
 * @return Result of the operation.
 */
int SelfDecrypt(std::shared_ptr<DataMap> data_map,
                std::shared_ptr<ChunkStore> chunk_store,
                bool overwrite,
                const fs::path &output_file) {
  try {
    if (fs::exists(output_file)) {
      if (overwrite)
        fs::remove(output_file);
      else
        return kFileAlreadyExists;
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("SelfDecryptToFile: %s\n", e.what());
#endif
    return kIoError;
  }
  std::shared_ptr<fs::ofstream> output_stream(new fs::ofstream(
      output_file, std::ios::out | std::ios::trunc | std::ios::binary));
  int result(SelfDecrypt(data_map, chunk_store, output_stream));
  output_stream->close();
  return result;
}

/**
 * Looks through the DataMap and checks if it exists in the given ChunkStore.
 *
 * @param data_map DataMap with chunk information.
 * @param chunk_store ChunkStore providing required chunks.
 * @param missing_chunks Pointer to vector to receive list of unavailable
 *                       chunks' names, or NULL if not needed.
 * @return True if all chunks exist, otherwise false.
 */
bool ChunksExist(std::shared_ptr<DataMap> data_map,
                 std::shared_ptr<ChunkStore> chunk_store,
                 std::vector<std::string> *missing_chunks) {
  if (!data_map || !chunk_store)
    return false;
  bool result(true);
  if (missing_chunks)
    missing_chunks->clear();
  for (auto it = data_map->chunks.begin(); it != data_map->chunks.end(); ++it) {
    if (!chunk_store->Has(it->hash)) {
      if (missing_chunks)
        missing_chunks->push_back(it->hash);
      result = false;
    }
  }
  return result;
}

}  // namespace encrypt

}  // namespace maidsafe
