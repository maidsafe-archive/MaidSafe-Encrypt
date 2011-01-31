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
 * @file  data_io_handler.h
 * @brief Interfaces to handle IO operations.
 * @date  2009-10-25
 */

#ifndef MAIDSAFE_ENCRYPT_DATA_IO_HANDLER_H_
#define MAIDSAFE_ENCRYPT_DATA_IO_HANDLER_H_

#include <cstdint>
#include <memory>
#include <string>

#include "boost/filesystem/fstream.hpp"
#include "maidsafe-encrypt/version.h"

#if MAIDSAFE_ENCRYPT_VERSION < 1
#error This API is not compatible with the installed library.\
  Please update the maidsafe-encrypt library.
#endif

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

class DataIOHandler {
 public:
  enum IOHandlerType { kFileIOHandler, kStringIOHandler };
  DataIOHandler(bool read, IOHandlerType iohandler_type)
      : kRead_(read), kIOHandlerType_(iohandler_type) {}
  virtual ~DataIOHandler() {}

  /// Opens access to the data
  virtual bool Open() = 0;
  /// Closes access to the data
  virtual void Close() = 0;

  /** Size  get size of data, either a string or a file
   *  size where size is returned
   *  return True if success, false otherwise
   */
  virtual bool Size(std::uint64_t *size) = 0;

  /** Reads block of data of size characters from the position of the
   *  get pointer.  Puts to output.  If EndOfFile or the end of string has been
   *  reached, true is returned but the output is cleared.
   *  size - size of data to be retrieved
   *  ouput - string to output to
   *  return True if success, false otherwise
   */
  virtual bool Read(const size_t &size, std::string *output) = 0;

  /** Append input to data
   *  input - data to be appended
   *  return True if success, false otherwise
   */
  virtual bool Write(const std::string &input) = 0;

  /** SetGetPointer sets the get pointer to position that is relative to the
   *  beginning of the string/file.
   *  position - positon of the pointer
   *  return True if success, false otherwise
   */
  virtual bool SetGetPointer(const std::uint64_t &position) = 0;
  IOHandlerType Type() const { return kIOHandlerType_; }
 protected:
  const bool kRead_;
  const IOHandlerType kIOHandlerType_;
};

class StringIOHandler : public DataIOHandler {
 public:
  StringIOHandler(std::shared_ptr<std::string> data, bool read);
  ~StringIOHandler() {}
  virtual bool Open();
  virtual void Close();
  virtual bool Size(std::uint64_t *size);
  virtual bool Read(const size_t &size, std::string *output);
  virtual bool Write(const std::string &input);
  virtual bool SetGetPointer(const std::uint64_t &position);
  std::string Data() const { return *data_; }
 private:
  std::shared_ptr<std::string> data_;
  bool is_open_;
  size_t readptr_;
};

class FileIOHandler : public DataIOHandler {
 public:
  FileIOHandler(const fs::path &file_path, bool read);
  ~FileIOHandler() { Close(); }
  virtual bool Open();
  virtual void Close();
  virtual bool Size(std::uint64_t *size);
  virtual bool Read(const size_t &size, std::string *output);
  virtual bool Write(const std::string &input);
  virtual bool SetGetPointer(const std::uint64_t &position);
  fs::path FilePath() const { return kPath_; }
 private:
  fs::fstream filestream_;
  const fs::path kPath_;
};

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_DATA_IO_HANDLER_H_

