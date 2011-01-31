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
 * @file  string_io_handler.cc
 * @brief Implementation of interface to handle string IO operations.
 * @date  2009-10-25
 */

#include "maidsafe-encrypt/data_io_handler.h"

#include <cstring>
#include <limits>

namespace maidsafe {

namespace encrypt {

StringIOHandler::StringIOHandler(std::shared_ptr<std::string> data, bool read)
    : DataIOHandler(read, kStringIOHandler),
      data_(data),
      is_open_(false),
      readptr_(0) {}

bool StringIOHandler::Open() {
  if (is_open_)
    return true;
  is_open_ = true;
  if (!kRead_)
    data_->clear();
  SetGetPointer(0);
  return true;
}

void StringIOHandler::Close() {
  is_open_ = false;
}

bool StringIOHandler::Size(std::uint64_t *size) {
  *size = data_->size();
  return true;
}

bool StringIOHandler::Read(const size_t &size, std::string *output) {
  output->clear();
  // Check we've got read permission
  if (!kRead_ || !is_open_)
    return false;
  try {
    *output = data_->substr(readptr_, size);
  } catch(...) {
  }
  readptr_ += output->size();
  return true;
}

bool StringIOHandler::Write(const std::string &input) {
  if (kRead_ || !is_open_)
    return false;
  data_->append(input);
  return true;
}

bool StringIOHandler::SetGetPointer(const std::uint64_t &position) {
  if (!kRead_ || !is_open_ || position > std::numeric_limits<size_t>::max())
    return false;
  readptr_ = static_cast<size_t>(position);
  return true;
}

}  // namespace encrypt

}  // namespace maidsafe
