/*
* ============================================================================
*
* Copyright [2010] Sigmoid Solutions limited
*
* Description:  Filesystem iterator which accumulates hashes and file sizes of
*               all accessible files.
* Version:      1.0
* Created:      24-12-2010
* Revision:     none
* Author:       Fraser Hutchison
* Company:      Sigmoid Solutions
*
* The following source code is property of Sigmoid Solutions and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.sigmoidsolutions.com
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of Sigmoid
* Solutions.
* ============================================================================
*/

#include "filesystem_analyser.h"
#include <maidsafe/base/crypto.h>
//  #include <boost/bind/protect.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/operations.hpp>

namespace fs3 = boost::filesystem3;

namespace maidsafe {

void FilesystemAnalyser::ProcessFile(const fs3::path &file_path) {
  crypto::Crypto crypt;
  crypt.set_hash_algorithm(crypto::SHA_1);
  FileInfo file_info(file_path);
  try {
    file_info.file_hash = crypt.Hash(file_path.string().c_str(),"",
                                     crypto::FILE_STRING, false);
    file_info.file_size = fs3::file_size(file_path);
    if (file_info.file_hash.empty())
      emit OnFailure(file_path.string() + ": hash failed.");
    else
      emit OnFileProcessed(file_info);
  }
  catch(const std::exception &ex) {
    emit OnFailure(ex.what());
  }
}

// from http://stackoverflow.com/questions/1746136/
//      how-do-i-normalize-a-pathname-using-boostfilesystem
fs3::path FilesystemAnalyser::Normalise(const fs3::path &directory_path){
  fs3::path result;
  for (fs3::path::iterator it = directory_path.begin();
       it != directory_path.end(); ++it) {
    if(*it == "..") {
      // /a/b/.. is not necessarily /a if b is a symbolic link
      if(fs3::is_symlink(result))
        result /= *it;
      // /a/b/../.. is not /a/b/.. under most circumstances
      // We can end up with ..s in our result because of symbolic links
      else if(result.filename() == "..")
        result /= *it;
      // Otherwise it should be safe to resolve the parent
      else
        result = result.parent_path();
    } else if(*it == ".") {
      // Ignore
    } else {
      // Just cat other path entries
      result /= *it;
    }
  }
  return result;
}

void FilesystemAnalyser::ProcessDirectory(const fs3::path &directory_path) {
  fs3::path dir_path = Normalise(directory_path);
  boost::system::error_code ec;
  try {
  fs3::directory_iterator it(dir_path, ec);
  emit OnDirectoryEntered(dir_path);
    while (it != fs3::directory_iterator()) {
      fs3::file_status file_stat((*it).status());

      if (fs3::is_symlink(dir_path) || fs3::is_empty(dir_path)
         /*|| fs3::file_size(dir_path) == 0*/ || ec) {
        ++it;
        continue;
      }

      switch (file_stat.type()) {
        case fs3::file_not_found:
        case fs3::symlink_file:
        case fs3::reparse_file:
        case fs3::block_file:
        case fs3::socket_file:
        case fs3::fifo_file:
          break;
        case fs3::regular_file:
  //          io_service_.dispatch(boost::bind
  //              (&maidsafe::FilesystemAnalyser::ProcessFile, this, *it));
          ProcessFile(*it);
          break;
        case fs3::directory_file:
  //         io_service_.dispatch(boost::protect(boost::bind
  //     (&maidsafe::FilesystemAnalyser::ProcessDirectory, this, *it)))

          if (fs3::is_symlink(*it) || fs3::is_other(*it)
              || fs3::path(*it) == "/proc" || fs3::path(*it) == "/dev"
              || fs3::path(*it) == "/sys")
            break;
          ProcessDirectory(*it);
          break;
        default:
          emit OnFailure(ec.message());
      }
      ++it;
    }
  }
  catch(const std::exception &ex) {
    emit OnFailure(ex.what());
  }
}

}  // namespace maidsafe
