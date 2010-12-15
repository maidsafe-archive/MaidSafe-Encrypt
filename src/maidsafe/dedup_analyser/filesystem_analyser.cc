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


namespace fs3 = boost::filesystem3;
namespace bs2 = boost::signals2;

namespace maidsafe {

// std::string SHA1(const fs3::path &file_path) {
//   std::string result;
//   CryptoPP::SHA1 sha1;
//   try {
//     CryptoPP::FileSource(file_path.string().c_str(), true,
//         new CryptoPP::HashFilter(sha1, new CryptoPP::StringSink(result)));
//   }
//   catch(...) {}
//   return result;
// }

void FilesystemAnalyser::ProcessFile(const fs3::path &file_path) {
  FileInfo file_info(file_path);
  crypto::Crypto crypt;
  crypt.set_hash_algorithm(crypto::SHA_1);
  try {
    file_info.file_hash = crypt.Hash(file_path.c_str(),"",
                                       crypto::FILE_STRING, true);
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

void FilesystemAnalyser::ProcessDirectory(const fs3::path &directory_path) {
  boost::system::error_code ec;
  fs3::directory_iterator it(directory_path, ec);
  if (ec) {
    on_failure_(ec.message());
    return;
  }
  on_directory_entered_(directory_path);
  while (it != fs3::directory_iterator()) {
    fs3::file_status file_stat((*it).status());
    switch (file_stat.type()) {
      case fs3::regular_file:
        ProcessFile(*it);
        break;
      case fs3::directory_file:
        ProcessDirectory(*it);
        break;
      case fs3::symlink_file:
      case fs3::reparse_file:
        break;
      default:
        on_failure_(ec.message());
    }
    ++it;
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
