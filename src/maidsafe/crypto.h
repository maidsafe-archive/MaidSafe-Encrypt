/* Copyright (c) 2009 maidsafe.net limited
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

#ifndef BASE_CRYPTO_H_
#define BASE_CRYPTO_H_
#include <string>
#include "maidsafe/rsakeypair.h"

namespace crypto {

const int AES256_KeySize = 32;  // size in bytes
const int AES256_IVSize = 16;   // in bytes

enum operationtype {
  FILE_FILE,
  STRING_FILE,
  FILE_STRING,
  STRING_STRING
};

enum obfuscationtype {
  XOR
};

class Crypto {
 public:
  explicit Crypto()
    : hash_algorithm_(""), symm_algorithm_("") {}
  Crypto(const Crypto&);
  Crypto& operator=(const Crypto&);
  std::string Obfuscate(const std::string &first,
                        const std::string &second,
                        const obfuscationtype &obt);
  std::string SecurePassword(const std::string &password, int pin);

  //  HASH Funtion
  //  Hash Algorithms
  //   -SHA1 = sha 128
  //   -SHA224 = sha 224
  //   -SHA256 = sha 256
  //   -SHA384 = sha 284
  //   -SHA512 = sha 512
  //
  //   The Hash function returns an empty string if the input from a file
  //   could not be read or cannot write the output to a file

  void set_hash_algorithm(const std::string &algorithmtype);
  std::string hash_algorithm() const {return hash_algorithm_;}
  std::string Hash(const std::string &input,
                   const std::string &output,
                   const operationtype &ot,
                   bool hex);

  //  SYNC
  //  Symmetric Encryption Algorithm
  //    -AES_256
  //  Encryption and Decryption return an empty string if the input from
  //  a file could not be read or cannot write the output to a file
  bool set_symm_algorithm(const std::string &algorithmtype);
  std::string symm_algorithm() const { return symm_algorithm_; }

  std::string SymmEncrypt(const std::string &input,
                          const std::string &output,
                          const operationtype &ot,
                          const std::string &key);
  std::string SymmDecrypt(const std::string &input,
                          const std::string &output,
                          const operationtype &ot,
                          const std::string &key);

  //  ASYMMETRIC
  //  Encryption, Decryption and Sign return an empty string if
  //  the string passed for key is not a valid key or the type
  //  (public/private) is incorrect for the operation
  //  It also returns an empty string if the input from
  //  a file could not be read or cannot write the
  //  output to a file
  //  AsymmEncrypt -- key is a public key
  std::string AsymEncrypt(const std::string &input,
                          const std::string &output,
                          const std::string &key,
                          const operationtype &ot);

  // AsymDecrypt -- key is a private key
  std::string AsymDecrypt(const std::string &input,
                          const std::string &output,
                          const std::string &key,
                          const operationtype &ot);

  // AsymSign -- key is a private key
  std::string AsymSign(const std::string &input,
                       const std::string &output,
                       const std::string &key,
                       const operationtype &ot);

  // AsymCheckSig -- key is a public key
  // The operations only take into consideration the INPUT, where
  // both input_data and input_signature
  // must be of the same type (STRING / FILE)
  bool AsymCheckSig(const std::string &input_data,
                    const std::string &input_signature,
                    const std::string &key,
                    const operationtype &ot);

 private:
  std::string XOROperation(const std::string &first,
                           const std::string &second);
  std::string SHA1Hash(const std::string &input,
                       const std::string &output,
                       const operationtype &ot);
  std::string SHA224Hash(const std::string &input,
                         const std::string &output,
                         const operationtype &ot);
  std::string SHA256Hash(const std::string &input,
                         const std::string &output,
                         const operationtype &ot);
  std::string SHA384Hash(const std::string &input,
                         const std::string &output,
                         const operationtype &ot);
  std::string SHA512Hash(const std::string &input,
                         const std::string &output,
                         const operationtype &ot);
  std::string hash_algorithm_;
  std::string symm_algorithm_;
};
}   // namespace crypto
#endif  // BASE_CRYPTO_H_

