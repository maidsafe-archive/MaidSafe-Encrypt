/*******************************************************************************
 *  Copyright 2009 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  file_io_handler.cc
 * @brief Implementation of interface to handle file IO operations.
 * @date  2009-10-25
 */

#include "maidsafe-encrypt/data_io_handler.h"

#include <algorithm>
#include <limits>
#include <sstream>

#include "boost/filesystem.hpp"
#include "boost/scoped_ptr.hpp"

namespace fs = boost::filesystem3;

namespace maidsafe {

namespace encrypt {

FileIOHandler::FileIOHandler(const fs::path &file_path, bool read)
    : DataIOHandler(read, kFileIOHandler),
      filestream_(),
      kPath_(file_path) {}

bool FileIOHandler::Open() {
  if (filestream_.is_open())
    return true;
  try {
    if (kRead_) {
      filestream_.open(kPath_, fs::fstream::in | fs::fstream::binary);
    } else {
      filestream_.open(kPath_, fs::fstream::out | fs::fstream::trunc |
                       fs::fstream::binary);
    }
    return filestream_.good();
  } catch(...) {
    return false;
  }
}

void FileIOHandler::Close() {
  filestream_.close();
}

bool FileIOHandler::Size(std::uint64_t *size) {
  try {
    *size = fs::file_size(kPath_);
  } catch(...) {
    *size = 0;
    return false;
  }
  return true;
}

bool FileIOHandler::Read(const size_t &size, std::string *output) {
  output->clear();
  if (!kRead_ || !filestream_.is_open() || !filestream_.good())
    return false;
  try {
    std::uint64_t current_position = filestream_.tellg();
    std::uint64_t file_size = fs::file_size(kPath_);
    if (current_position >= file_size)
      return true;
    std::uint64_t amount_to_read = std::min(file_size - current_position,
                                            static_cast<std::uint64_t>(size));
    if (amount_to_read > std::numeric_limits<size_t>::max())
      return false;
    boost::scoped_ptr<char> buffer(
        new char[static_cast<size_t>(amount_to_read)]);
    filestream_.read(buffer.get(), amount_to_read);
    std::ostringstream oss(std::ostringstream::binary);
    oss.write(buffer.get(), amount_to_read);
    *output = oss.str();
  } catch(...) {
    return false;
  }
  return true;
}

bool FileIOHandler::Write(const std::string &input) {
  if (kRead_ || !filestream_.is_open() || !filestream_.good())
    return false;
  try {
    filestream_.write(input.c_str(), input.size());
    filestream_.close();
    filestream_.open(kPath_, std::fstream::out | std::fstream::app |
                     std::fstream::binary);
  } catch(...) {
    return false;
  }
  return true;
}

bool FileIOHandler::SetGetPointer(const std::uint64_t &position) {
  if (!kRead_ || !filestream_.is_open() || !filestream_.good())
    return false;
  try {
    filestream_.seekg(position, std::ifstream::beg);
  } catch(...) {
    return false;
  }
  return true;
}

}  // namespace encrypt

}  // namespace maidsafe
