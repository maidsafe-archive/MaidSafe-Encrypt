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

#include <cstring>
#include "maidsafe/client/dataiohandler.h"

StringIOHandler::StringIOHandler() : input_(""), read_(false),
  isOpen_(false), readptr_(0) {}

bool StringIOHandler::SetData(const std::string &input, const bool &read) {
  if (isOpen_)
    return false;
  input_ = input;
  read_ = read;
  return true;
}

bool StringIOHandler::Open() {
  isOpen_ = true;
  SetGetPointer(0);
  return true;
}

void StringIOHandler::Close() {
  isOpen_ = false;
}

void StringIOHandler::Reset() {
  isOpen_ = false;
  input_.clear();
  readptr_ = 0;
}

std::string StringIOHandler::GetAsString() const {
  return input_;
}

bool StringIOHandler::Size(boost::uint64_t *size) {
  *size = input_.size();
  return true;
}

bool StringIOHandler::Read(char *data, const unsigned int &size) {  // NOLINT
  // Check we've got read permission
  if (!isOpen_ || !read_)
    return false;

  if (readptr_ == input_.size())
    return true;

  strncpy(data, input_.substr(readptr_, size).c_str(),
    input_.substr(readptr_, size).size());

  readptr_ += size;
  if (readptr_ >= input_.size())
    readptr_ = input_.size();
  return true;
}

bool StringIOHandler::Write(const char *data, const unsigned int &size) {  // NOLINT
  if (!isOpen_ || read_)
    return false;

  input_.append(data, size);
  return true;
}

bool StringIOHandler::SetGetPointer(const unsigned int &pos) {  // NOLINT
  if (!isOpen_ || !read_)
    return false;

  if (pos >= input_.size())
    readptr_ = input_.size() -1;
  else
    readptr_ = pos;
  return true;
}
