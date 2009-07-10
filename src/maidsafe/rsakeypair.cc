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

#include "maidsafe/rsakeypair.h"
#include <cryptopp/hex.h>
#include <cryptopp/integer.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include "maidsafe/maidsafe-dht.h"

namespace maidsafe_crypto {

void RsaKeyPair::GenerateKeys(unsigned int keySize) {
  // CryptoPP::AutoSeededRandomPool rand_pool;
  CryptoPP::RandomPool rand_pool;
  std::string seed = base::RandomString(keySize);
  rand_pool.IncorporateEntropy(reinterpret_cast<const byte *>(seed.c_str()),
                                                              seed.size());

  CryptoPP::RSAES_OAEP_SHA_Decryptor priv(rand_pool, keySize);  // 256 bytes
  CryptoPP::HexEncoder privKey(new CryptoPP::StringSink(private_key_), false);
  priv.DEREncode(privKey);
  privKey.MessageEnd();

  CryptoPP::RSAES_OAEP_SHA_Encryptor pub(priv);
  CryptoPP::HexEncoder pubKey(new CryptoPP::StringSink(public_key_), false);
  pub.DEREncode(pubKey);
  pubKey.MessageEnd();
}

void RsaKeyPair::set_private_key(std::string privatekey) {
  private_key_ = privatekey;
}

void RsaKeyPair::set_public_key(std::string publickey) {
  public_key_ = publickey;
}

void RsaKeyPair::ClearKeys() {
  private_key_ = "";
  public_key_ = "";
}


}  // namespace maidsafe_crypto
