#include <boost/bind.hpp>
#include "singleton.h"

const int N = 100;
const int P = 4;


void finish (int id){
  std::cout << "thread " << id << " finished" << std::endl;
}

void add_thread(TestSingleton *s, int id)
{
  boost::this_thread::at_thread_exit(boost::bind(&TestSingleton::PrintCounter));
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
  boost::thread_group thr_grp;
  TestSingleton *sing = TestSingleton::getInstance();
  boost::thread *thrd;

  for (int i = 0; i < P ; i++){
    // thr_grp.create_thread(boost::bind(&add_thread, sing, i+1));
    thrd = new boost::thread(boost::bind(&add_thread, sing, i+1));
    thr_grp.add_thread(thrd);
   }

  thr_grp.join_all();

  std::cout << "RESULT " << sing->GetCounter() << std::endl;

  return 0;
}
