#include <boost/config.hpp>

#if defined(BOOST_MSVC)
#pragma warning(disable: 4786)  //  identifier truncated in debug info
#pragma warning(disable: 4710)  //  function not inlined
#pragma warning(disable: 4711)  //  function selected for automatic inline expansion
#pragma warning(disable: 4514)  //  unreferenced inline removed
#endif

#include <boost/thread/thread.hpp>
#include <boost/bind.hpp>
#include <iostream>
#include <string>
#include "rsakeypair.h"

std::string f(std::string const & x) {
    return "f(" + x + ")";
}

std::string g(std::string const & x) {
    return "g(" + x + ")";
}

std::string h(std::string const & x, std::string const & y) {
    return "h(" + x + ", " + y + ")";
}

std::string k() {
    return "k()";
}

template<class F> void test(F f) {
    std::cout << f("x", "y") << '\n';
}

void print_keys(bool done, std::string size) {
    // std::cout << "public key: " << kp.public_key() << std::endl;
    // std::cout << "private key: " << kp.private_key() << std::endl;
    if (done)
      std::cout << "done " << size << std::endl;
    else
      std::cout << "No keys !" << std::endl;
}

int main() {
    using namespace boost;
    RsaKeyPair rsakp;

    //  compose_f_gx
    //  test( bind(f, bind(g, _1)) );

    //  compose_f_hxy
    //  test( bind(f, bind(h, _1, _2)) );

    //  compose_h_fx_gx
    //  test( bind(h, bind(f, _1), bind(g, _1)) );

    //  compose_h_fx_gy
    //  test( bind(h, bind(f, _1), bind(g, _2)) );

    //  compose_f_k
    //  test( bind(f, bind(k)) );

    //  boost::thread my_thread((bind(&RsaKeyPair::GenerateKeys,_1,_2))(rsakp,8192));
    //  boost::thread my_thread(bind(&RsaKeyPair::GenerateKeys,rsakp,8192));
    // boost::thread my_thread(&k);

    std::string size8192 = "8192";
    std::string size4096 = "4096";
    boost::thread my_thread8192( bind(print_keys, bind(&RsaKeyPair::GenerateKeys,rsakp,8192),size8192 ));
    boost::thread my_thread4096(bind(print_keys, bind(&RsaKeyPair::GenerateKeys,rsakp,4096),size4096));
    my_thread8192.join();
    my_thread4096.join();

    //  bind(print_keys, _1, _2)((bind(&RsaKeyPair::GenerateKeys,_1,_2))(rsakp,8192), size8192); 

    // test( bind( (&RsaKeyPair::GenerateKeys,_1,_2)(rsakp,4096), bind(print_keys, _1))  );

    return 0;
}

