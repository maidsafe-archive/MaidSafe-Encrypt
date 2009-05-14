// //  testcrypto.cpp
// #define CRYPTOPP_DEFAULT_NO_DLL
// #include "cryptopp/dll.h"
// #include "cryptopp/default.h"
// #include <iostream>
//// #ifdef CRYPTOPP_WIN32_AVAILABLE
////  #include <windows.h>
//// #endif
//
//USING_NAMESPACE(CryptoPP)
//USING_NAMESPACE(std)
//
//// using namespace std;
//// using namespace CryptoPP;
//
//const int MAX_PHRASE_LENGTH=250;
//
//void EncryptFile(const char *in,const char *out,const char *passPhrase);
//void DecryptFile(const char *in,const char *out,const char *passPhrase);
//// CRYPTOPP_CDECL
///*
//int main(int argc, char *argv[])
//{
//    if ( argc < 3 ){
//    std::cout << "\nUsage:" << argv[0] << "filetoenc filenameenc decfilename" << std::endl;
//    exit(255);
//}
//
//   try
//   {
//      char passPhrase[MAX_PHRASE_LENGTH];
//      cout << "Passphrase: " << endl;
//
//      cin.getline(passPhrase, MAX_PHRASE_LENGTH);
//      EncryptFile(argv[1], argv[2], passPhrase);
//      DecryptFile(argv[2], argv[3], passPhrase);
//   }
//   catch(CryptoPP::Exception &e)
//   {
//      cout << "\nCryptoPP::Exception caught: "
//           << e.what() << endl;
//      return -1;
//   }
//   catch(std::exception &e)
//   {
//
//      cout << "\nstd::exception caught: " << e.what() << endl;
//      return -2;
//   }
//}
//
//void EncryptFile(const char *in,const char *out,const char *passPhrase)
//{
//   FileSource f(in, true, new DefaultEncryptorWithMAC(passPhrase,
//                   new FileSink(out)));
//}
//
//void DecryptFile(const char *in,const char *out,const char *passPhrase)
//{
//   FileSource f(in, true,
//         new DefaultDecryptorWithMAC(passPhrase, new FileSink(out)));
//}
//
//RandomPool & GlobalRNG()
//{
//   static RandomPool randomPool;
//   return randomPool;
//}
//int (*AdhocTest)(int argc, char *argv[]) = NULL;
//*/
