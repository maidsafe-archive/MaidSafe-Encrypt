#include <iostream>
#include <string>
#include "boost/bind.hpp"
#include "rsakeypair.h"

class some_class {
public:
  typedef void result_type;
  void print_string(const std::string& s) const {
    std::cout << s << '\n';
  }
};

void print_string(const std::string s) {
  std::cout << s << '\n';
}

int main() {
  (boost::bind(&print_string,_1))("Hello func!");
  RsaKeyPair rsakp;
  (boost::bind(&RsaKeyPair::GenerateKeys,_1,_2))
    (rsakp,4096);
}

