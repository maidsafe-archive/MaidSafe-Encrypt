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

#include "maidsafe/crypto.h"

#include <cryptopp/integer.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>

#include "maidsafe/utils.h"

namespace maidsafe_crypto {

CryptoPP::RandomNumberGenerator & GlobalRNG() {
  static CryptoPP::AutoSeededRandomPool rand_pool;
  return rand_pool;
}

std::string Crypto::XOROperation(const std::string &first,
                                 const std::string &second) {
  std::string result(first);
  for (unsigned int i = 0; i < result.length(); i++) {
    result[i] = first[i] ^ second[i];
  }
  return result;
}

std::string Crypto::Obfuscate(const std::string &first,
                              const std::string &second,
                              const obfuscationtype &obt) {
  std::string result("");
  if ((first.length() != second.length()) || (first.length() == 0))
    return result;
  switch (obt) {
    case XOR:
      result = XOROperation(first, second);
      break;
    default:
      return result;
  }
  return result;
}

std::string Crypto::SecurePassword(const std::string &password, int pin) {
  if ((password == "") || (pin == 0))
      return "";
  byte purpose = 0;
  std::string derived_password;
  std::string salt = "maidsafe_salt";
  unsigned int iter = (pin % 1000)+1000;
  CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf;
  CryptoPP::SecByteBlock derived(32);
  pbkdf.DeriveKey(derived, derived.size(), purpose,
    reinterpret_cast<const byte *>(password.data()),
    password.size(), reinterpret_cast<const byte *>(salt.data()),
    salt.size(), iter);
  CryptoPP::HexEncoder enc(new CryptoPP::StringSink(derived_password));
  enc.Put(derived, derived.size());
  return derived_password;
}

//  HASH
void Crypto::set_hash_algorithm(const std::string &algorithmtype) {
  if ( (algorithmtype == "SHA1") || (algorithmtype == "SHA256") || \
    (algorithmtype == "SHA224") || (algorithmtype == "SHA512") || \
    (algorithmtype == "SHA384") )
      hash_algorithm_ = algorithmtype;
}

std::string Crypto::SHA1Hash(const std::string &input,
                             const std::string &output,
                             const operationtype &ot) {
  std::string buffer;
  CryptoPP::SHA1 hash;
  CryptoPP::StringSource *s_source = new CryptoPP::StringSource;
  CryptoPP::FileSource *f_source = new CryptoPP::FileSource;
  switch (ot) {
    case STRING_STRING:
      s_source = new CryptoPP::StringSource(reinterpret_cast<const byte *>
        (input.c_str()), input.length(), true, new CryptoPP::HashFilter(hash,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(buffer), false)));
      delete s_source;
      break;
    case STRING_FILE:
      buffer = output;
      try {
        s_source = new CryptoPP::StringSource(reinterpret_cast<const byte *>
          (input.c_str()), input.length(), true, new CryptoPP::HashFilter(hash,
          new CryptoPP::HexEncoder(
          new CryptoPP::FileSink(output.c_str()), false)));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete s_source;
      break;
    case FILE_STRING:
      try {
        f_source = new CryptoPP::FileSource(input.c_str(), true,
          new CryptoPP::HashFilter(hash,
          new CryptoPP::HexEncoder(new CryptoPP::StringSink(buffer), false)));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete f_source;
      break;
    case FILE_FILE:
      buffer = output;
      try {
        f_source = new CryptoPP::FileSource(input.c_str(), true,
          new CryptoPP::HashFilter(hash,
          new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str()),
          false)));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete f_source;
      break;
  }
  return buffer;
}

std::string Crypto::SHA224Hash(const std::string &input,
                               const std::string &output,
                               const operationtype &ot) {
  std::string buffer;
  CryptoPP::StringSource *s_source = new CryptoPP::StringSource;
  CryptoPP::FileSource *f_source = new CryptoPP::FileSource;
  CryptoPP::SHA224 hash;
  switch (ot) {
    case STRING_STRING:
      s_source = new CryptoPP::StringSource(reinterpret_cast<const byte *>
        (input.c_str()), input.length(), true, new CryptoPP::HashFilter(hash,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(buffer), false)));
      delete s_source;
      break;
    case STRING_FILE:
      buffer = output;
      try {
        s_source = new CryptoPP::StringSource(reinterpret_cast<const byte *>
          (input.c_str()), input.length(), true, new CryptoPP::HashFilter(hash,
          new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str()),
          false)));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete s_source;
      break;
    case FILE_STRING:
      try {
        f_source = new CryptoPP::FileSource(input.c_str(), true,
          new CryptoPP::HashFilter(hash,
          new CryptoPP::HexEncoder(new CryptoPP::StringSink(buffer), false)));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete f_source;
      break;
    case FILE_FILE:
      buffer = output;
      try {
        f_source = new CryptoPP::FileSource(input.c_str(), true,
            new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str(),
            false))));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete f_source;
      break;
  }
  return buffer;
}

std::string Crypto::SHA256Hash(const std::string &input,
                               const std::string &output,
                               const operationtype &ot) {
  std::string buffer;
  CryptoPP::SHA256 hash;
  CryptoPP::StringSource *s_source = new CryptoPP::StringSource;
  CryptoPP::FileSource *f_source = new CryptoPP::FileSource;
  switch (ot) {
    case STRING_STRING:
      s_source = new CryptoPP::StringSource(reinterpret_cast<const byte *>
        (input.c_str()), input.length(), true, new CryptoPP::HashFilter(hash,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(buffer), false)));
      delete s_source;
      break;
    case STRING_FILE:
      buffer = output;
      try {
        s_source = new CryptoPP::StringSource(reinterpret_cast<const byte *>
          (input.c_str()), input.length(), true, new CryptoPP::HashFilter(hash,
          new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str(),
          false))));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete s_source;
      break;
    case FILE_STRING:
      try {
        f_source = new CryptoPP::FileSource(input.c_str(), true,
          new CryptoPP::HashFilter(hash,
          new CryptoPP::HexEncoder(new CryptoPP::StringSink(buffer), false)));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete f_source;
      break;
    case FILE_FILE:
      buffer = output;
      try {
        f_source = new CryptoPP::FileSource(input.c_str(), true,
            new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str(),
            false))));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete f_source;
      break;
  }
  return buffer;
}

std::string Crypto::SHA384Hash(const std::string &input,
                               const std::string &output,
                               const operationtype &ot) {
  std::string buffer;
  CryptoPP::SHA384 hash;
  CryptoPP::StringSource *s_source = new CryptoPP::StringSource;
  CryptoPP::FileSource *f_source = new CryptoPP::FileSource;
  switch (ot) {
    case STRING_STRING:
      s_source = new CryptoPP::StringSource(reinterpret_cast<const byte *>
          (input.c_str()), input.length(), true,
          new CryptoPP::HashFilter(hash,
          new CryptoPP::HexEncoder(new CryptoPP::StringSink(buffer), false)));
      delete s_source;
      break;
    case STRING_FILE:
      buffer = output;
      try {
        s_source = new CryptoPP::StringSource(reinterpret_cast<const byte *>
          (input.c_str()), input.length(), true,
          new CryptoPP::HashFilter(hash,
          new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str()),
          false)));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete s_source;
      break;
    case FILE_STRING:
      try {
        f_source = new CryptoPP::FileSource(input.c_str(), true,
            new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(buffer), false)));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete f_source;
      break;
    case FILE_FILE:
      buffer = output;
      try {
        f_source = new CryptoPP::FileSource(input.c_str(), true,
          new CryptoPP::HashFilter(hash,
          new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str()),
          false)));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete f_source;
      break;
  }
  return buffer;
}

std::string Crypto::SHA512Hash(const std::string &input,
                               const std::string &output,
                               const operationtype &ot) {
  std::string buffer;
  CryptoPP::SHA512 hash;  // hash transformation
  CryptoPP::StringSource *s_source = new CryptoPP::StringSource;
  CryptoPP::FileSource *f_source = new CryptoPP::FileSource;
  switch (ot) {
    case STRING_STRING:
      s_source = new CryptoPP::StringSource(reinterpret_cast<const byte *>
        (input.c_str()), input.length(), true, new CryptoPP::HashFilter(hash,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(buffer), false)));
      delete s_source;
      break;
    case STRING_FILE:
      buffer = output;
      try {
        s_source = new CryptoPP::StringSource(reinterpret_cast<const byte *>
          (input.c_str()), input.length(), true, new CryptoPP::HashFilter(hash,
          new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str()),
          false)));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete s_source;
      break;
    case FILE_STRING:
      try {
        f_source = new CryptoPP::FileSource(input.c_str(), true,
            new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(buffer),
            false)));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete f_source;
      break;
    case FILE_FILE:
      buffer = output;
      try {
        f_source = new CryptoPP::FileSource(input.c_str(), true,
          new CryptoPP::HashFilter(hash,
          new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str()),
          false)));
      }
      catch(const CryptoPP::Exception &e) {
        buffer = "";
      }
      delete f_source;
      break;
  }
  return buffer;
}

std::string Crypto::Hash(const std::string &input,
                         const std::string &output,
                         const operationtype &ot,
                         bool hex) {
  std::string result;
  if (hash_algorithm_ == "SHA512")
    result = SHA512Hash(input, output, ot);
  else if (hash_algorithm_ == "SHA1")
    result = SHA1Hash(input, output, ot);
  else if (hash_algorithm_ == "SHA256")
    result = SHA256Hash(input, output, ot);
  else if (hash_algorithm_ == "SHA224")
    result = SHA224Hash(input, output, ot);
  else if (hash_algorithm_ == "SHA384")
    result = SHA384Hash(input, output, ot);
  else
    return result;
  if (!hex) {
    std::string dec_result;
    CryptoPP::StringSource(result, true,
      new CryptoPP::HexDecoder(new CryptoPP::StringSink(dec_result)));
    return dec_result;
  }
  return result;
}

//  SYNC
bool Crypto::set_symm_algorithm(const std::string &algorithmtype) {
  if ( algorithmtype == "AES_256")
    symm_algorithm_ = algorithmtype;
  else
    return false;
  return true;
}

std::string Crypto::SymmEncrypt(const std::string &input,
                                const std::string &output,
                                const operationtype &ot,
                                const std::string &key) {
  if (symm_algorithm_ != "AES_256")
      return "";
  std::string hashkey = SHA512Hash(key, "", STRING_STRING);
  byte byte_key[AES256_KeySize], byte_iv[AES256_IVSize];
  CryptoPP::StringSource(hashkey.substr(0, AES256_KeySize), true,
    new CryptoPP::ArraySink(byte_key, sizeof(byte_key)));
  CryptoPP::StringSource(hashkey.substr(AES256_KeySize, AES256_IVSize), \
    true, new CryptoPP::ArraySink(byte_iv, sizeof(byte_iv)));
  std::string result;
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(byte_key,
    sizeof(byte_key), byte_iv);
  switch (ot) {
    case STRING_STRING:
      CryptoPP::StringSource(reinterpret_cast<const byte *>(input.c_str()),
        input.length(), true, \
        new CryptoPP::StreamTransformationFilter(encryptor, \
        new CryptoPP::StringSink(result)));
      break;
    case STRING_FILE:
      result = output;
      try {
        CryptoPP::StringSource(reinterpret_cast<const byte *>(input.c_str()), \
          input.length(), true, \
          new CryptoPP::StreamTransformationFilter(encryptor, \
          new CryptoPP::FileSink(output.c_str())));
      }
      catch(const CryptoPP::Exception &e) {
        result = "";
      }
      break;
      case FILE_STRING:
        try {
          CryptoPP::FileSource(input.c_str(), true, \
            new CryptoPP::StreamTransformationFilter(encryptor, \
            new CryptoPP::StringSink(result)));
        }
        catch(const CryptoPP::Exception &e) {
          result = "";
        }
        break;
      case FILE_FILE:
        result = output;
        try {
          CryptoPP::FileSource(input.c_str(), true, \
            new CryptoPP::StreamTransformationFilter(encryptor, \
            new CryptoPP::FileSink(output.c_str())));
        }
        catch(const CryptoPP::Exception &e) {
          result = "";
        }
        break;
    }
  return result;
}

std::string Crypto::SymmDecrypt(const std::string &input,
                                const std::string &output,
                                const operationtype &ot,
                                const std::string &key) {
  if (symm_algorithm_ != "AES_256")
      return "";
  std::string hashkey = SHA512Hash(key, "", STRING_STRING);
  byte byte_key[ AES256_KeySize ], byte_iv[ AES256_IVSize ];
  CryptoPP::StringSource(hashkey.substr(0, AES256_KeySize), true, \
    new CryptoPP::ArraySink(byte_key, sizeof(byte_key)));
  CryptoPP::StringSource(hashkey.substr(AES256_KeySize, AES256_IVSize),
    true, new CryptoPP::ArraySink(byte_iv, sizeof(byte_iv)));
  std::string result;
  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(byte_key, \
    sizeof(byte_key), byte_iv);
  switch (ot) {
    case STRING_STRING:
      CryptoPP::StringSource(reinterpret_cast<const byte *>(input.c_str()),
        input.length(), true, \
        new CryptoPP::StreamTransformationFilter(decryptor, \
        new CryptoPP::StringSink(result)));
      break;
    case STRING_FILE:
      result = output;
      try {
        CryptoPP::StringSource(reinterpret_cast<const byte *>(input.c_str()),
          input.length(), true, \
          new CryptoPP::StreamTransformationFilter(decryptor, \
          new CryptoPP::FileSink(output.c_str())));
      }
      catch(const CryptoPP::Exception &e) {
        result = "";
      }
      break;
    case FILE_STRING:
      try {
        CryptoPP::FileSource(input.c_str(), true, \
          new CryptoPP::StreamTransformationFilter(decryptor, \
          new CryptoPP::StringSink(result)));
      }
      catch(const CryptoPP::Exception &e) {
        result = "";
      }
      break;
    case FILE_FILE:
      result = output;
      try {
        CryptoPP::FileSource(input.c_str(), true, \
          new CryptoPP::StreamTransformationFilter(decryptor, \
          new CryptoPP::FileSink(output.c_str())));
      }
      catch(const CryptoPP::Exception &e) {
        result = "";
      }
      break;
  }
  return result;
}

std::string Crypto::AsymEncrypt(const std::string &input,
                                const std::string &output,
                                const std::string &key,
                                const operationtype &ot) {
  try {
    CryptoPP::StringSource pubkey(key, true, new CryptoPP::HexDecoder);

    CryptoPP::RSAES_OAEP_SHA_Encryptor pub(pubkey);
    CryptoPP::AutoSeededRandomPool rand_pool;
    std::string result;

    switch (ot) {
      case STRING_STRING:
        CryptoPP::StringSource(reinterpret_cast<const byte *>(input.c_str()),
          input.length(), true,
          new CryptoPP::PK_EncryptorFilter(rand_pool, pub,
          new CryptoPP::HexEncoder(new CryptoPP::StringSink(result))));
        break;
      case STRING_FILE:
        result = output;
        CryptoPP::StringSource(reinterpret_cast<const byte *>(input.c_str()),
          input.length(), true,
          new CryptoPP::PK_EncryptorFilter(rand_pool, pub,
          new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str()))));
        break;
      case FILE_STRING:
        CryptoPP::FileSource(input.c_str(), true,
          new CryptoPP::PK_EncryptorFilter(rand_pool, pub,
          new CryptoPP::HexEncoder(new CryptoPP::StringSink(result))));
        break;
      case FILE_FILE:
        result = output;
        CryptoPP::FileSource(input.c_str(), true,
         new CryptoPP::PK_EncryptorFilter(rand_pool, pub,
         new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str()))));
        break;
    }
    return result;
  }
  catch(const CryptoPP::Exception &e) {
      return "";
  }
}

std::string Crypto::AsymDecrypt(const std::string &input,
                                const std::string &output,
                                const std::string &key,
                                const operationtype &ot) {
  try {
    CryptoPP::StringSource privkey(key, true, new CryptoPP::HexDecoder);
    CryptoPP::RSAES_OAEP_SHA_Decryptor priv(privkey);
    std::string result;
    switch (ot) {
      case STRING_STRING:
        CryptoPP::StringSource(reinterpret_cast<const byte *>(input.c_str()),
          input.length(), true,
          new CryptoPP::HexDecoder(new CryptoPP::PK_DecryptorFilter(GlobalRNG(),
          priv, new CryptoPP::StringSink(result))));
        break;
      case STRING_FILE:
        result = output;
        CryptoPP::StringSource(reinterpret_cast<const byte *>(input.c_str()),
          input.length(), true,
          new CryptoPP::HexDecoder(new CryptoPP::PK_DecryptorFilter(GlobalRNG(),
          priv, new CryptoPP::FileSink(output.c_str()))));
        break;
      case FILE_STRING:
        CryptoPP::FileSource(input.c_str(), true,
          new CryptoPP::HexDecoder(new CryptoPP::PK_DecryptorFilter(GlobalRNG(),
          priv, new CryptoPP::StringSink(result))));
        break;
      case FILE_FILE:
        result = output;
        CryptoPP::FileSource(input.c_str(), true,
          new CryptoPP::HexDecoder(new CryptoPP::PK_DecryptorFilter(GlobalRNG(),
          priv, new CryptoPP::FileSink(output.c_str()))));
        break;
    }
    return result;
  }
  catch(const CryptoPP::Exception &e) {
      return "";
  }
}

std::string Crypto::AsymSign(const std::string &input,
                             const std::string &output,
                             const std::string &key,
                             const operationtype &ot) {
  try {
    CryptoPP::StringSource privkey(key, true, new CryptoPP::HexDecoder);

    CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA>::Signer priv(privkey);
    std::string result;

    switch (ot) {
      case STRING_STRING:
        CryptoPP::StringSource(reinterpret_cast<const byte *>(input.c_str()),
          input.length(), true,
          new CryptoPP::SignerFilter(GlobalRNG(),
          priv, new CryptoPP::HexEncoder(new CryptoPP::StringSink(result))));
        break;
      case STRING_FILE:
        result = output;
        CryptoPP::StringSource(reinterpret_cast<const byte *>(input.c_str()),
          input.length(), true,
          new CryptoPP::SignerFilter(GlobalRNG(), priv,
          new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str()))));
        break;
      case FILE_STRING:
        CryptoPP::FileSource(input.c_str(), true,
        new CryptoPP::SignerFilter(GlobalRNG(), priv,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(result))));
        break;
      case FILE_FILE:
        result = output;
        CryptoPP::FileSource(input.c_str(), true,
          new CryptoPP::SignerFilter(GlobalRNG(), priv,
          new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str()))));
        break;
    }
    return result;
  }
  catch(const CryptoPP::Exception &e) {
      return "";
  }
}

bool Crypto::AsymCheckSig(const std::string &input_data,
                          const std::string &input_signature,
                          const std::string &key,
                          const operationtype &ot) {
  try {
    CryptoPP::StringSource pubkey(key, true, new CryptoPP::HexDecoder);

    CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA>::Verifier pub(pubkey);
    bool result = false;
    CryptoPP::SecByteBlock *signature;
    CryptoPP::VerifierFilter *verifierFilter;

    if ((ot == STRING_STRING) || (ot == STRING_FILE)) {
      CryptoPP::StringSource signatureString(input_signature,
        true, new CryptoPP::HexDecoder);
      if (signatureString.MaxRetrievable() != pub.SignatureLength())
        return result;
      signature = new CryptoPP::SecByteBlock(pub.SignatureLength());
      signatureString.Get(*signature, signature->size());

      verifierFilter = new CryptoPP::VerifierFilter(pub);
      verifierFilter->Put(*signature, pub.SignatureLength());
      CryptoPP::StringSource(input_data, true, verifierFilter);
      result = verifierFilter->GetLastResult();
      delete signature;
      return result;
    } else if ((ot == FILE_FILE) || (ot == FILE_STRING)) {
      CryptoPP::FileSource signatureFile(input_signature.c_str(),
        true, new CryptoPP::HexDecoder);
      if (signatureFile.MaxRetrievable() != pub.SignatureLength())
        return false;
      signature = new CryptoPP::SecByteBlock(pub.SignatureLength());
      signatureFile.Get(*signature, signature->size());

      verifierFilter = new CryptoPP::VerifierFilter(pub);
      verifierFilter->Put(*signature, pub.SignatureLength());
      CryptoPP::FileSource(input_data.c_str(), true, verifierFilter);
      result = verifierFilter->GetLastResult();
      delete signature;
      return result;
    } else {
      return false;
    }
  }
  catch(const CryptoPP::Exception &e) {
    return false;
  }
}

}  // namespace maidsafe_crypto
