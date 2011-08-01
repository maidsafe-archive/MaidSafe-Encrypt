#include <iostream>
using std::cout;
using std::endl;

#include <cryptopp/mqueue.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
using CryptoPP::MessageQueue;

int main(int, char**)
{
    byte b1[] = {'a', 'b', 'c', 'd', 'e', 'f'};
    byte b2[70];
    std::string digest;
    CryptoPP::SHA512 hash;

    CryptoPP::HexEncoder decode(new CryptoPP::HexEncoder,(new CryptoPP::StringSink(digest)));

    CryptoPP::HashFilter queue(hash , NULL, true) ;

    queue.Put2(b1, sizeof(b1), -1, true);

    size_t mr = queue.MaxRetrievable();
    cout << "MaxRetrievable: " << mr << endl;

    size_t pk = queue.Peek(b2, sizeof(b2));
    b2[pk] = '\0';
    cout << "Peeked: " << (const char*) b2 << endl;
    
    pk = queue.Peek(b2, 2);
    b2[pk] = '\0';
    decode.Put2(b2, sizeof(b2), -1, true);
    cout << "Peeked: " << (const char*) b2 << endl;
    cout << "digest " << digest << endl;

    mr = queue.MaxRetrievable();
    cout << "MaxRetrievable: " << mr << endl;
}