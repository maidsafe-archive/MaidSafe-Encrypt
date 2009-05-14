#include <boost/thread/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/bind.hpp>
#include <iostream>

#include <time.h>
 
void sleep_(unsigned int mseconds)
{
    clock_t goal = mseconds + clock();
    while (goal > clock());
}

boost::mutex io_mutex;
const int N = 20000;
int target;

void add_thread(int id)
{
  for (int i = 0; i < N; ++i){
    boost::mutex::scoped_lock lock(io_mutex);
   std::cout << "thread " << id << " adding to target" << std::endl;
   sleep_(1000);
   target =  target +1;
   std::cout << "target = " << target << std::endl;
   std::cout << "iter  = " << i << " of thread " << id << std::endl;
  }
}

int main(int argc, char* argv[])
{
  target = 0;
  boost::thread thrd1(boost::bind(&add_thread, 1));
  boost::thread thrd2(boost::bind(&add_thread, 2));
  // boost::thread thrd3(boost::bind(&add_thread, 3));
  // boost::thread thrd4(boost::bind(&add_thread, 4));

  thrd1.join();
  thrd2.join();
  // thrd3.join();
  // thrd4.join();

  std::cout << "Total = " << target << std::endl;

  return 0;
}
