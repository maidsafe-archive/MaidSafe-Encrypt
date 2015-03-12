/*  Copyright 2011 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_ENCRYPT_DATA_MAP_ENCRYPTOR_H_
#define MAIDSAFE_ENCRYPT_DATA_MAP_ENCRYPTOR_H_

#include <cstdint>

#include "maidsafe/common/types.h"
#include "maidsafe/common/crypto.h"

#include "maidsafe/encrypt/data_map.h"

namespace maidsafe {

namespace encrypt {

enum class EncryptionAlgorithm : uint32_t {
  kSelfEncryptionVersion0 = 0,
  kDataMapEncryptionVersion0
};

extern const EncryptionAlgorithm kSelfEncryptionVersion;
extern const EncryptionAlgorithm kDataMapEncryptionVersion;

SerialisedData EncryptDataMap(const Identity& parent_id, const Identity& this_id,
                              const DataMap& data_map);

DataMap DecryptDataMap(const Identity& parent_id, const Identity& this_id,
                       const SerialisedData& encrypted_data_map);

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_DATA_MAP_ENCRYPTOR_H_
