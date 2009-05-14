#include <cryptopp/rsa.h>
#include <cryptopp/hex.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>

#include "rsakeypair.h"

RsaKeyPair::RsaKeyPair(){
    private_key_ = "";
    public_key_ = "";
}

bool RsaKeyPair::GenerateKeys(unsigned int keySize){

    CryptoPP::AutoSeededRandomPool rand_pool;
    CryptoPP::RSAES_OAEP_SHA_Decryptor priv(rand_pool, keySize); // 256 bytes length
    CryptoPP::HexEncoder privKey(new CryptoPP::StringSink(private_key_));
    priv.DEREncode(privKey);
    privKey.MessageEnd();

    CryptoPP::RSAES_OAEP_SHA_Encryptor pub(priv);
    CryptoPP::HexEncoder pubKey(new CryptoPP::StringSink(public_key_));
    pub.DEREncode(pubKey);
    pubKey.MessageEnd();
    return true;
}

void RsaKeyPair::set_private_key(std::string privatekey){
    private_key_ = privatekey;
}

void RsaKeyPair::set_public_key(std::string publickey){
    public_key_ = publickey;
}

void RsaKeyPair::ClearKeys(){
    private_key_ = "";
    public_key_ = "";
}

