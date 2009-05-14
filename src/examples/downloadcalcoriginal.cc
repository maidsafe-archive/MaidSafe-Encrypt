#include "base/rsakeypair.h"
#include "examples/downloadcalc.h"
#include <iostream>

 std::string DownloadCalc::DownloadBangBus() {
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(8192);
  std::cout << "1st" << std::endl;
  rsakp.GenerateKeys(8192);
  std::cout << "2nd" << std::endl;
  return rsakp.private_key();
}

int DownloadCalc::Add(int a, int b) { return a+b; }
int DownloadCalc::Sub(int a, int b) { return a-b; }
int DownloadCalc::Mult(int a, int b) { return a*b; }
int DownloadCalc::Div(int a, int b, int *result) {
  if (b!=0){
    *result = a/b;
    return 1;
  }
  return 0;
}


int main(int argc, char **argv) {
  DownloadCalc dc;
  std::cout << "5+2=" << dc.Add(5,2) << std::endl;
  std::cout << "5-2=" << dc.Sub(5,2) << std::endl;
  std::cout << "pk=" << dc.DownloadBangBus() << std::endl;
  std::cout << "5*2=" << dc.Mult(5,2) << std::endl;
  int result;
  int code = dc.Div(5,2,&result);
  if ( code == 1)
    std::cout << "5*2=" << result << std::endl;
  else
    std::cout << "Zero div" << std::endl;
  code = dc.Div(5,0,&result);
  if ( code == 1)
    std::cout << "5*2=" << result << std::endl;
  else
    std::cout << "Zero div" << std::endl;
  return 0;
}
