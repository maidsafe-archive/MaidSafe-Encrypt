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

#include <iostream>
#include <boost/filesystem.hpp>
#include "filesystem_analyser.h"
#include "in_memory_result_holder.h"
#include "terminal_display.h"

int main(int argc, char* argv[]) {
  if (argc < 2) {
    std::cout << "Usage: Dedup <path to start recursive check>" << std::endl << std::endl;
    return -1;
  }
  boost::filesystem3::path path(argv[1]);
  boost::filesystem3::space_info size = boost::filesystem3::space(path);
  boost::uintmax_t capacity = size.capacity/(1024*1024*1024);
  boost::uintmax_t free_space = size.free/(1024*1024*1024);
  
  std::cout << "Drive capacity is : " << capacity << " GB and of that "
                                      << capacity-free_space << " GB has been used!" << std::endl;

  maidsafe::FilesystemAnalyser filesystem_analyser;
  maidsafe::InMemoryResultHolder in_memory_result_holder;
  in_memory_result_holder.ConnectToFilesystemAnalyser(&filesystem_analyser);
  maidsafe::TerminalDisplay terminal_display;
  terminal_display.ConnectToFilesystemAnalyser(&filesystem_analyser);
  filesystem_analyser.ProcessDirectory(argv[1]);
  filesystem_analyser.Stop(); // make sure all threads completed
  
  std::cout << std::endl << std::endl << "Processing results..." << std::endl << std::endl;
std::cout << "Drive capacity is : " << capacity << " GB and of that "
                                      << capacity-free_space << " GB has been used!" << std::endl;

  std::cout << "Total processed file count:           " << in_memory_result_holder.UniqueFileCount() + in_memory_result_holder.DuplicateFileCount() << std::endl;
  std::cout << "Total of all processed files' sizes:  " << in_memory_result_holder.TotalUniqueSize() + in_memory_result_holder.TotalDuplicateSize() << std::endl;
  std::cout << "Unprocessed file count:               " << in_memory_result_holder.ErrorsCount() << std::endl << std::endl;
  std::cout << "Unique file count:                    " << in_memory_result_holder.UniqueFileCount() << std::endl;
  std::cout << "Total of unique files' sizes:         " << in_memory_result_holder.TotalUniqueSize() << std::endl << std::endl;
  std::cout << "Duplicate file count:                 " << in_memory_result_holder.DuplicateFileCount() << std::endl;
  std::cout << "Total of duplicate files' sizes:      " << in_memory_result_holder.TotalDuplicateSize() << std::endl << std::endl << std::endl;
  std::cout << "Duplicate files as a percentage of all files:  " << static_cast<double>(in_memory_result_holder.DuplicateFileCount()) * 100 / (in_memory_result_holder.UniqueFileCount() + in_memory_result_holder.DuplicateFileCount()) << " %" << std::endl;
  std::cout << "Duplicate size as a percentage of total size:  " << static_cast<float>(in_memory_result_holder.TotalDuplicateSize()) * 100 / (in_memory_result_holder.TotalUniqueSize() + in_memory_result_holder.TotalDuplicateSize()) << " %" <<  std::endl;


  return 0;
}
