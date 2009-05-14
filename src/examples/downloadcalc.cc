#include <ace/Task.h>
#include <iostream>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "base/deferred.h"
#include "base/rsakeypair.h"
#include "base/entry.h"
#include "examples/downloadcalc.h"

//  Haiyang's added code. Bit ugly, according to him, but it works.

//  Structure to pass parameters to the thread
struct params{
  dht::Deferred *df;
  DownloadCalc *dc;
};

//  Class that deals with the threading
class ComputationThread: public ACE_Task_Base{
public:
   virtual int svc(){
     std::cout << "Do Sth in Thread" << std::endl;
     //  Call to the function that takes a long time
    std::cout << "pk=" << dc_->DownloadBangBus() << std::endl;
    dht::entry e;
    std::cout << "Before callback" << std::endl;
    //  Callback
    df_->Callback(e);
    //  The code would continue here, if the callback function
    //  didn't have an exit(0). This next message is never printed.
    std::cout << "After callback" << std::endl;
     return 0;
   }
   ComputationThread(struct params *p){
     df_ = p->df;
     dc_ = p->dc;
   }

private:
   dht::Deferred *df_;
   DownloadCalc *dc_;
};

//  Callback function. States download procedure is finished
//  and executes an exit. This prevents the main from executing
//  it's last instructions.
static void CbCalc(void* pt2Object, dht::entry &e){
  std::cout << "Download finished!!!" << std::endl;
  exit(0);
}

//  Member functions from the original code
std::string DownloadCalc::DownloadBangBus() {
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(4096);
  std::cout << "1st" << std::endl;
  rsakp.GenerateKeys(4096);
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
//  End of original member functions

int main(int argc, char **argv) {
  //  Pre callback operations
  DownloadCalc dc;
  std::cout << "5+2=" << dc.Add(5,2) << std::endl;
  std::cout << "5-2=" << dc.Sub(5,2) << std::endl;

  //  Parameters for callback
  dht::callbackFunc func;
  func.pt2Obj = &dc;
  func.pt2Func = CbCalc;
  dht::Deferred *df = new dht::Deferred();
  struct params *p = new struct params;
  p->df  = df;
  p->dc = &dc;

  //  Thread code to start one from the main
  //  Only one parameter can be passed to the thread, hence the
  //  structure p.
  ComputationThread *calc_thread = new ComputationThread(p);
   int result = calc_thread->activate();
   if (result != 0)
    std::cout << "Failed to start calc thread" << std::endl;

  //  Adding the callback
  df->AddCallback(func);

  //  Freezing the main thread for a second so that the other
  //  thread can have time for it's instructions.
  while (1){
    sleep(1);
    std::cout << "I'm alive, you can do any thing!" << std::endl;
    std::cout << "5+2=" << dc.Add(5,2) << std::endl;
    std::cout << "5-2=" << dc.Sub(5,2) << std::endl;
  }

  //  This bit is currently never reached, since the callback function
  //  has an exit(0) call.
  std::cout << "done" << std::endl;
  return 0;
}
