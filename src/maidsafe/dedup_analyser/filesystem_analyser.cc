/* Copyright (c) 2010 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "filesystem_analyser.h"
#include <maidsafe/base/crypto.h>
#include <boost/bind/protect.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/operations.hpp>

namespace fs3 = boost::filesystem3;
namespace bs2 = boost::signals2;

namespace maidsafe {

void FilesystemAnalyser::ProcessFile(const fs3::path &file_path) {
      crypto::Crypto crypt;
        crypt.set_hash_algorithm(crypto::SHA_1);
  FileInfo file_info(file_path);
  try {
    file_info.file_hash = crypt.Hash(file_path.c_str(),"",
                                       crypto::FILE_STRING, false);
    file_info.file_size = fs3::file_size(file_path);
    if (file_info.file_hash.empty())
      on_failure_(file_path.string() + ": hash failed.");
    else
      on_file_processed_(file_info);
  }
  catch(const std::exception &ex) {
    on_failure_(ex.what());
  }
}

// from http://stackoverflow.com/questions/1746136/
//      how-do-i-normalize-a-pathname-using-boostfilesystem
boost::filesystem3::path FilesystemAnalyser::normalise(const fs3::path& dir_path){
    boost::filesystem::path result;
    for(boost::filesystem::path::iterator it=dir_path.begin();
        it!=dir_path.end();
        ++it)
    {
        if(*it == "..")
        {
            // /a/b/.. is not necessarily /a if b is a symbolic link
            if(boost::filesystem::is_symlink(result) )
                result /= *it;
            // /a/b/../.. is not /a/b/.. under most circumstances
            // We can end up with ..s in our result because of symbolic links
            else if(result.filename() == "..")
                result /= *it;
            // Otherwise it should be safe to resolve the parent
            else
                result = result.parent_path();
        }
        else if(*it == ".")
        {
            // Ignore
        }
        else
        {
            // Just cat other path entries
            result /= *it;
        }
    }
    return result;
}


void FilesystemAnalyser::ProcessDirectory(const fs3::path &directory_path) {
  fs3::path dir_path = normalise(directory_path);
 // fs3::path dir_path = directory_path;
  boost::system::error_code ec;
  try {
  fs3::directory_iterator it(dir_path, ec);
  on_directory_entered_(dir_path);
    while (it != fs3::directory_iterator()) {
      fs3::file_status file_stat((*it).status());
     
      if (fs3::is_symlink(dir_path) || fs3::is_empty(dir_path)
         /*|| fs3::file_size(dir_path) == 0*/ || ec ) {
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
             || fs3::path(*it) == "/proc"
             || fs3::path(*it) == "/dev"
             || fs3::path(*it) == "/sys"
          )
            break;
          ProcessDirectory(*it);
          break;
        default:
          on_failure_(ec.message());
      }
      ++it;
    }
  } catch(const std::exception &ex) {
    on_failure_(ex.what());
  }
    
}

bs2::connection FilesystemAnalyser::DoOnFileProcessed(
    const OnFileProcessed::slot_type &slot) {
  return on_file_processed_.connect(slot);
}

bs2::connection FilesystemAnalyser::DoOnDirectoryEntered(
    const OnDirectoryEntered::slot_type &slot) {
  return on_directory_entered_.connect(slot);
}

bs2::connection FilesystemAnalyser::DoOnFailure(
    const OnFailure::slot_type &slot) {
  return on_failure_.connect(slot);
}


}  // namespace maidsafe
