/* Copyright 2013 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

#include "maidsafe/encrypt/drive_store.h"

#include <string>
#include <vector>

#include "boost/filesystem/convenience.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {
namespace drive_store {

namespace {

struct UsedSpace {
  UsedSpace() {}
  UsedSpace(UsedSpace&& other)
      : directories(std::move(other.directories)),
        disk_usage(std::move(other.disk_usage)) {}

  std::vector<fs::path> directories;
  DiskUsage disk_usage;
};

UsedSpace GetUsedSpace(fs::path directory) {
  UsedSpace used_space;
  for (fs::directory_iterator it(directory); it != fs::directory_iterator(); ++it) {
    if (fs::is_directory(*it))
      used_space.directories.push_back(it->path());
    else
      used_space.disk_usage.data += fs::file_size(*it);
  }
  return used_space;
}

DiskUsage InitialiseDiskRoot(const fs::path& disk_root) {
  boost::system::error_code error_code;
  DiskUsage disk_usage(0);
  if (!fs::exists(disk_root, error_code)) {
    if (!fs::create_directories(disk_root, error_code)) {
      LOG(kError) << "Can't create disk root at " << disk_root << ": " << error_code.message();
      ThrowError(CommonErrors::uninitialised);
      return disk_usage;
    }
  } else {
    std::vector<fs::path> dirs_to_do;
    dirs_to_do.push_back(disk_root);
    while (!dirs_to_do.empty()) {
      std::vector<std::future<UsedSpace>> futures;
      for (uint32_t i = 0; i < 16 && !dirs_to_do.empty(); ++i) {
        auto future = std::async(&GetUsedSpace, dirs_to_do.back());
        dirs_to_do.pop_back();
        futures.push_back(std::move(future));
      }
      try {
        while (!futures.empty()) {
          auto future = std::move(futures.back());
          futures.pop_back();
          UsedSpace result = future.get();
          disk_usage.data += result.disk_usage.data;
          std::copy(result.directories.begin(),
                    result.directories.end(),
                    std::back_inserter(dirs_to_do));
        }
      }
      catch(std::system_error& exception) {
        LOG(kError) << exception.what();
        ThrowError(CommonErrors::filesystem_io_error);
      }
      catch(...) {
        ThrowError(CommonErrors::invalid_parameter);
      }
    }
  }
  return disk_usage;
}

}  // unnamed namespace

namespace detail {

fs::path GetFileName(const DataNameVariant& data_name_variant) {
  auto result(boost::apply_visitor(GetTagValueAndIdentityVisitor(), data_name_variant));
  return (EncodeToBase32(result.second) + '_' +
          std::to_string(static_cast<uint32_t>(result.first)));
}

DataNameVariant GetDataNameVariant(const fs::path& file_name) {
  std::string file_name_str(file_name.string());
  size_t index(file_name_str.rfind('_'));
  auto id(static_cast<DataTagValue>(std::stoul(file_name_str.substr(index + 1))));
  Identity key_id(DecodeFromBase32(file_name_str.substr(0, index)));
  return GetDataNameVariant(id, key_id);
}

}  // namespace detail

DriveStore::DriveStore(const fs::path& disk_path, const DiskUsage& max_disk_usage)
    : kDiskPath_(disk_path),
      max_disk_usage_(max_disk_usage),
      current_disk_usage_(InitialiseDiskRoot(kDiskPath_)),
      kDepth_(5),
      get_identity_visitor_() {
  if (current_disk_usage_ > max_disk_usage_)
    ThrowError(CommonErrors::cannot_exceed_limit);
}

DriveStore::~DriveStore() {}

void DriveStore::Put(const KeyType& key, const NonEmptyString& value) {
  std::unique_lock<std::mutex> lock(mutex_);
  if (!fs::exists(kDiskPath_))
    ThrowError(CommonErrors::filesystem_io_error);

  fs::path file_path(KeyToFilePath(key));
  uint32_t value_size(static_cast<uint32_t>(value.string().size()));
  uint64_t file_size(0), size(0);
  uint32_t reference_count(GetReferenceCount(file_path));
  boost::system::error_code error_code;

  if (reference_count == 0) {
    if (!HasDiskSpace(value_size)) {
      LOG(kError) << "Cannot store "
                  << HexSubstr(boost::apply_visitor(get_identity_visitor_, key).string())
                  << " since the addition of " << size << " bytes exceeds max of "
                  << max_disk_usage_ << " bytes.";
      ThrowError(CommonErrors::cannot_exceed_limit);
    }
    file_path.replace_extension(".1");
    if (!WriteFile(file_path, value.string())) {
      LOG(kError) << "Failed to write "
                  << HexSubstr(boost::apply_visitor(get_identity_visitor_, key).string())
                  << " to disk.";
      ThrowError(CommonErrors::filesystem_io_error);
    }
    current_disk_usage_.data += value_size;
  } else {
    fs::path old_path(file_path), new_path(file_path);
    old_path.replace_extension("." + std::to_string(reference_count));
    ++reference_count;
    new_path.replace_extension("." + std::to_string(reference_count));

    file_size = fs::file_size(old_path, error_code);
    if (error_code) {
      LOG(kError) << "Error getting file size of " << file_path << ": " << error_code.message();
      ThrowError(CommonErrors::filesystem_io_error);
    }
    if (!fs::remove(old_path, error_code) || error_code) {
      LOG(kError) << "Error removing file " << file_path << ": " << error_code.message();
      ThrowError(CommonErrors::filesystem_io_error);
    }

    if (file_size <= value_size) {
      size = value_size - file_size;
      if (!HasDiskSpace(size)) {
        LOG(kError) << "Cannot store "
                    << HexSubstr(boost::apply_visitor(get_identity_visitor_, key).string())
                    << " since the addition of " << size << " bytes exceeds max of "
                    << max_disk_usage_ << " bytes.";
        ThrowError(CommonErrors::cannot_exceed_limit);
      }
      if (!WriteFile(new_path, value.string())) {
        LOG(kError) << "Failed to write "
                    << HexSubstr(boost::apply_visitor(get_identity_visitor_, key).string())
                    << " to disk.";
        ThrowError(CommonErrors::filesystem_io_error);
      }
      current_disk_usage_.data += size;
    } else {
      size = file_size - value_size;
      if (!WriteFile(new_path, value.string())) {
        LOG(kError) << "Failed to write "
                    << HexSubstr(boost::apply_visitor(get_identity_visitor_, key).string())
                    << " to disk.";
        ThrowError(CommonErrors::filesystem_io_error);
      }
      current_disk_usage_.data -= size;
    }
  }
  return;
}

void DriveStore::Delete(const KeyType& key) {
  std::lock_guard<std::mutex> lock(mutex_);
  fs::path file_path(KeyToFilePath(key));
  boost::system::error_code error_code;
  uint32_t reference_count(GetReferenceCount(file_path));

  if (reference_count == 0)
    return;

  file_path.replace_extension("." + std::to_string(reference_count));
  if (reference_count == 1) {
    uintmax_t file_size(fs::file_size(file_path, error_code));
    if (error_code) {
      LOG(kError) << "Error getting file size of " << file_path << ": " << error_code.message();
      ThrowError(CommonErrors::filesystem_io_error);
    }
    if (!fs::remove(file_path, error_code) || error_code) {
      LOG(kError) << "Error removing " << file_path << ": " << error_code.message();
      ThrowError(CommonErrors::filesystem_io_error);
    }
    current_disk_usage_.data -= file_size;
  } else {
    fs::path new_path(file_path);
    --reference_count;
    new_path.replace_extension("." + std::to_string(reference_count));
    fs::rename(file_path, new_path, error_code);
    if (error_code) {
      LOG(kError) << "Error renaming file " << file_path << ": " << error_code.message();
      ThrowError(CommonErrors::filesystem_io_error);
    }
  }
  return;
}

NonEmptyString DriveStore::Get(const KeyType& key) {
  std::lock_guard<std::mutex> lock(mutex_);
  fs::path file_path(KeyToFilePath(key));
  uint32_t reference_count(GetReferenceCount(file_path));
  file_path.replace_extension("." + std::to_string(reference_count));
  return ReadFile(file_path);
}

void DriveStore::SetMaxDiskUsage(DiskUsage max_disk_usage) {
  if (current_disk_usage_ > max_disk_usage)
    ThrowError(CommonErrors::invalid_parameter);
  max_disk_usage_ = max_disk_usage;
}

DiskUsage DriveStore::GetMaxDiskUsage() {
  return max_disk_usage_;
}

DiskUsage DriveStore::GetCurrentDiskUsage() {
  return current_disk_usage_;
}

fs::path DriveStore::GetFilePath(const KeyType& key) const {
  return kDiskPath_ / detail::GetFileName(key);
}

bool DriveStore::HasDiskSpace(const uint64_t& required_space) const {
  return current_disk_usage_ + required_space <= max_disk_usage_;
}

fs::path DriveStore::KeyToFilePath(const KeyType& key) {
  NonEmptyString file_name(GetFilePath(key).filename().string());

  uint32_t directory_depth = kDepth_;
  if (file_name.string().length() < directory_depth)
    directory_depth = static_cast<uint32_t>(file_name.string().length() - 1);

  fs::path disk_path(kDiskPath_);
  for (uint32_t i = 0; i < directory_depth; ++i)
    disk_path /= file_name.string().substr(i, 1);

  boost::system::error_code ec;
  fs::create_directories(disk_path, ec);

  return fs::path(disk_path / file_name.string().substr(directory_depth));
}

uint32_t DriveStore::GetReferenceCount(const fs::path& path) const {
  boost::system::error_code error_code;
  if (!fs::exists(path.parent_path(), error_code)) {
    LOG(kWarning) << path << " doesn't exist.";
    ThrowError(CommonErrors::no_such_element);
  }

  try {
    std::string file_name(path.filename().string());
    fs::directory_iterator end;
    for (fs::directory_iterator it(path.parent_path()); it != end; ++it) {
      if (it->path().stem().string() == file_name && fs::is_regular_file(it->status()))
        return std::stoul(it->path().extension().string().substr(1));
    }
  }
  catch(const std::exception& e) {
    LOG(kError) << "Exception: " << e.what();
  }

  return 0;
}

}  // namespace drive_store
}  // namespace maidsafe
