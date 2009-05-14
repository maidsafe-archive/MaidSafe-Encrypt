#include <iostream>
#include <boost/thread/thread.hpp>
#include <boost/thread/mutex.hpp>

class TestSingleton {
  public:
    static TestSingleton* getInstance();
    int GetCounter();
    void AddCounter(int id);
    static void PrintCounter(){std::cout <<"thread finished" ;}

  private:
    int counter;
    static TestSingleton *single;
    TestSingleton();
};

