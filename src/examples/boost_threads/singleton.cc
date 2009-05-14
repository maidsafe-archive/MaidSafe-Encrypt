#include "singleton.h"

#include <time.h>

TestSingleton* TestSingleton::single = NULL;
boost::mutex mutex;

void sleep_()
{
    clock_t goal = 1500 + clock();
    while (goal > clock());
}
TestSingleton::TestSingleton(){
  counter = 0;
}

int TestSingleton::GetCounter(){
  return counter;
}

void TestSingleton::AddCounter(int id){
  boost::mutex::scoped_lock lock(mutex);
  sleep_();
  std::cout << "added by thread " << id << std::endl;
  counter = counter + 1;
}

TestSingleton* TestSingleton::getInstance() {
    if (! TestSingleton::single) {
      boost::mutex::scoped_lock lock(mutex);
      if (! TestSingleton::single) {
        TestSingleton::single = new TestSingleton();
      }
    }
    return TestSingleton::single;
}

