#include <boost/bind.hpp>
#include "singleton.h"

const int N = 500;
void finish (int id){
  std::cout << "thread " << id << " finished" << std::endl;
}
void add_thread(TestSingleton *s, int id)
{
  boost::this_thread::at_thread_exit(boost::bind(&finish, id));
  for (int i = 0; i < N; ++i){
    s->AddCounter(id);
   std::cout << "target = " << s->GetCounter() << std::endl;
   std::cout << "iter  = " << i << " of thread " << id << std::endl;
  }
  
}

void create_singleton_add(int id){

  TestSingleton *sing = TestSingleton::getInstance();
  add_thread(sing, id);
}


int main(int argc, char* argv[])
{
  TestSingleton *sing = TestSingleton::getInstance();

  boost::thread thrd1(boost::bind(&add_thread, sing, 1));
  boost::thread thrd2(boost::bind(&create_singleton_add, 2));
  boost::thread thrd3(boost::bind(&create_singleton_add, 3));
  boost::thread thrd4(boost::bind(&create_singleton_add, 4));

  thrd1.join();
  thrd2.join();
  thrd3.join();
  thrd4.join();

  std::cout << "RESULT " << sing->GetCounter() << std::endl;

  return 0;
}
