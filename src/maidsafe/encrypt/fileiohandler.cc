/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Interface to handle IO operations.
* Version:      1.0
* Created:      2009-10-25
* Revision:     none
* Compiler:     gcc
* Author:       Alec Macdonald
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

#include "maidsafe/encrypt/dataiohandler.h"

namespace fs = boost::filesystem;

namespace maidsafe {

FileIOHandler::FileIOHandler() : fd_(), p_(), read_(false) {}

bool FileIOHandler::SetData(const std::string &iput, const bool &read) {
  if (fd_.is_open())
    return false;
  p_ = fs::path(iput, fs::native);
  read_ = read;
  return true;
}

bool FileIOHandler::Open() {
  if (read_) {
    try {
      fd_.open(p_, std::fstream::in | std::fstream::binary);
    } catch(...) {
      return false;
    }
  } else {
    try {
      fd_.open(p_, std::fstream::out | std::fstream::binary);
    } catch(...) {
      return false;
    }
  }
  return true;
}

void FileIOHandler::Close() {
  fd_.close();
}

void FileIOHandler::Reset() {
  if (fd_.is_open())
    fd_.close();
  fd_.clear();
  p_ = fs::path();
}

bool FileIOHandler::Size(boost::uint64_t *size) {
  try {
    *size = fs::file_size(p_);
  } catch(...) {
    *size = 0;
    return false;
  }
  return true;
}

bool FileIOHandler::Read(char *data, const unsigned int &size) {  // NOLINT
  if (!read_ || !fd_.is_open())
    return false;

  try {
    fd_.read(data, size);
  } catch(...) {
    return false;
  }

  return true;
}

bool FileIOHandler::Write(const char *data, const unsigned int &size) {  // NOLINT
  if (read_ || !fd_.is_open())
    return false;

  try {
    fd_.write(data, size);
  } catch(...) {
    return false;
  }
  return true;
}

bool FileIOHandler::SetGetPointer(const unsigned int &pos) {  // NOLINT
  if (!fd_.is_open())
    return false;

  try {
    fd_.seekg(pos, std::ifstream::beg);
  } catch(std::fstream::failure f) {
    return false;
  }
  return true;
}

}  // namespace maidsafe
