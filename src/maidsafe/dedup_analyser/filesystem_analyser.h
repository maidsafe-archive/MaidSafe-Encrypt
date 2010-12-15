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

#ifndef SRC_FILESYSTEM_ANALYSER_H_
#define SRC_FILESYSTEM_ANALYSER_H_

#include <boost/cstdint.hpp>
#include <boost/filesystem.hpp>
#include <boost/signals2.hpp>
#include <boost/signals2/connection.hpp>
#include <string>
#include <utility>

namespace fs3 = boost::filesystem3;
namespace bs2 = boost::signals2;

namespace maidsafe {

struct FileInfo {
  explicit FileInfo(const fs3::path &file_path_in)
      : file_path(file_path_in), file_hash(), file_size(0) {}
  fs3::path file_path;
  std::string file_hash;
  boost::uintmax_t file_size;
  bool operator < (const FileInfo &r) const { return file_hash < r.file_hash; }
};

typedef bs2::signal<void(FileInfo)> OnFileProcessed;
typedef bs2::signal<void(fs3::path)> OnDirectoryEntered;
typedef bs2::signal<void(std::string)> OnFailure;

std::string SHA1(const fs3::path &file_path);

class FilesystemAnalyser {
 public:
  FilesystemAnalyser() : on_file_processed_(), on_failure_() {}
  void ProcessFile(const fs3::path &file_path);
  void ProcessDirectory(const fs3::path &directory_path);
  bs2::connection DoOnFileProcessed(const OnFileProcessed::slot_type &slot);
  bs2::connection DoOnDirectoryEntered(
      const OnDirectoryEntered::slot_type &slot);
  bs2::connection DoOnFailure(const OnFailure::slot_type &slot);
 private:
  FilesystemAnalyser(const FilesystemAnalyser&);
  FilesystemAnalyser &operator=(const FilesystemAnalyser&);
  OnFileProcessed on_file_processed_;
  OnDirectoryEntered on_directory_entered_;
  OnFailure on_failure_;
};

}  // namespace maidsafe

#endif  // SRC_FILESYSTEM_ANALYSER_H_