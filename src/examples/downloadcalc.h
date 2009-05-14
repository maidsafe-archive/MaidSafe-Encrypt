#ifndef DOWNLOADCALC_H_INCLUDED
#define DOWNLOADCALC_H_INCLUDED
#include <string>

class DownloadCalc {

public:
  std::string DownloadBangBus();
  int Add(int a, int b);
  int Sub(int a, int b);
  int Mult(int a, int b);
  int Div(int a, int b, int *result);

};

#endif //  DOWNLOADCALC_H_INCLUDED
