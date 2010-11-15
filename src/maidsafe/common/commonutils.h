/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Utility Functions
* Version:      1.0
* Created:      2010-04-29-13.26.25
* Revision:     none
* Compiler:     gcc
* Author:       Team, dev@maidsafe.net
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

#ifndef MAIDSAFE_COMMON_COMMONUTILS_H_
#define MAIDSAFE_COMMON_COMMONUTILS_H_

#include <boost/filesystem.hpp>
#include <string>

namespace kad { class Contact; }

namespace maidsafe {

bool ContactHasId(const std::string &id, const kad::Contact &contact);

// Return the SHA512 hash of the file contents
std::string SHA512File(const boost::filesystem::path &file_path);

// Return the SHA512 hash of the string contents
std::string SHA512String(const std::string &input);

// Return the SHA1 hash of the file contents
std::string SHA1File(const boost::filesystem::path &file_path);

// Return the SHA1 hash of the string contents
std::string SHA1String(const std::string &input);

// Asymmetrically (RSA) signs input
std::string RSASign(const std::string &input, const std::string &private_key);

// Retuns true if signature of input is correct
bool RSACheckSignedData(const std::string &input,
                        const std::string &signature,
                        const std::string &public_key);
}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_COMMONUTILS_H_
