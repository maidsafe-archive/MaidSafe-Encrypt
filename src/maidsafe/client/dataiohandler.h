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
* Author:       Alec Macdonald, Jose Cisneros
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

#ifndef MAIDSAFE_CLIENT_DATAIOHANDLER_H_
#define MAIDSAFE_CLIENT_DATAIOHANDLER_H_

#include <boost/filesystem/fstream.hpp>
#include <string>

class DataIOHandler {
 public:
  /** SetData sets file path or the string to handle IO operations tos
   *  input - string or path to file
   *  read - True if read, false if write
   *  return True if success, false otherwise
   */
  virtual bool SetData(const std::string &iput = "",
    const bool &read = false) = 0;

  /** Opens access to the data
  */
  virtual bool Open() = 0;

  /** Closes access to the data
   */
  virtual void Close() = 0;

  /** Reset - clears the data being handled
  */
  virtual void Reset() = 0;

  /** GetAsString - return all the data handled as a string
   */
  virtual std::string GetAsString() const {return "";}

  /** Size  get size of input, either a string or a file
   *  size where size is returned
   *  is_file
   *  return True if success, false otherwise
   */
  virtual bool Size(boost::uint64_t *size) = 0;

  /** Reads block of data of size characters from the position of the
   *  get pointer.  No NULL character is put in the end of
   *  the array returned.  If EndOfFile or the end of string has been reached,
   *  True is returned but the array of char is not modified.
   *  data - pointer to block of data
   *  size - size of data to be retrieved
   *  return True if success, false otherwise
   */
  virtual bool Read(char *data, const unsigned int &size) = 0;  // NOLINT

  /** Write to data a block of data of size characters
   *  data - pointer to block of data to be written
   *  size - size of data to be retrieved
   *  return True if success, false otherwise
   */
  virtual bool Write(const char *data, const unsigned int &size) = 0;  // NOLINT

  /** SetGetPointer sets the get pointer to position pos that is relative to
   *  the beginning of the string/file
   *  pos - positon of the pointer
   *  return True if success, false otherwise
   */
  virtual bool SetGetPointer(const unsigned int &pos) = 0;  //NOLINT
};

class StringIOHandler : public DataIOHandler {
 public:
  StringIOHandler();
  virtual bool SetData(const std::string &iput = "", const bool &read = false);  // NOLINT
  virtual bool Open();
  virtual void Close();
  virtual void Reset();
  virtual std::string GetAsString() const;
  virtual bool Size(boost::uint64_t *size);
  virtual bool Read(char *data, const unsigned int &size);  // NOLINT
  virtual bool Write(const char *data, const unsigned int &size);  // NOLINT
  virtual bool SetGetPointer(const unsigned int &pos);  // NOLINT
 private:
  std::string input_;
  bool read_, isOpen_;
  unsigned int readptr_;
};

class FileIOHandler : public DataIOHandler {
 public:
  FileIOHandler();
  virtual bool SetData(const std::string &iput = "", const bool &read = false);  // NOLINT
  virtual bool Open();
  virtual void Close();
  virtual void Reset();
  virtual bool Size(boost::uint64_t *size);
  virtual bool Read(char *data, const unsigned int &size);  // NOLINT
  virtual bool Write(const char *data, const unsigned int &size);  // NOLINT
  virtual bool SetGetPointer(const unsigned int &pos);  // NOLINT
 private:
  boost::filesystem::fstream fd_;
  boost::filesystem::path p_;
  bool read_;
};

#endif  // MAIDSAFE_CLIENT_DATAIOHANDLER_H_

