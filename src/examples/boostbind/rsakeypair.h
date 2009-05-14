#ifndef RSAKEYPAIR_H_
#define RSAKEYPAIR_H_
#include <string>

class RsaKeyPair {
  public:
      RsaKeyPair();
      std::string public_key() { return public_key_; }
      std::string private_key() { return private_key_; }
      void set_public_key(std::string publickey);
      void set_private_key(std::string privatekey);
      bool GenerateKeys(unsigned int keySize);
      // keySize in bits
      void ClearKeys();
      // Clears the current private and public keys held in the object
  private:
      std::string public_key_;
      std::string private_key_;
};


#endif // RSAKEYPAIR_H_
