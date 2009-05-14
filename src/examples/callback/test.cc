/*
 * test.cpp
 *
 *  Created on: Jul 4, 2008
 *      Author: haiyang
 */

#include <ace/OS_NS_sys_time.h>
#include <stdio.h>
#include <iostream>
#include <sys/time.h>
#include <map>
#include <list>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include "deferred.h"
#include "bencode.h"
#include "entry.h"

// #include "ace/Log_Msg.h"
using namespace std;
/*
void foo(void){
   ACE_TRACE(ACE_TEXT("foo"));
   ACE_DEBUG((LM_INFO, ACE_TEXT("%IHowdy Partner\n")));
}
int ACE_TMAIN(int argc, ACE_TCHAR *[])
{
   ACE_TRACE(ACE_TEXT("main"));

   ACE_DEBUG((LM_INFO, ACE_TEXT("%IHi Mom\n")));
   foo();
   ACE_DEBUG((LM_INFO, ACE_TEXT("%IGood night\n")));
   return 0;
}*/

class baseobject{
public:
   baseobject(int value):value_(value){

   }
   bool operator >= (baseobject const &a) const{
      if (value_>=a.Value())
         return true;
      else
         return false;
   }
   int Value()const{
      return value_;
   }
   int value_;

};

void test_out_of_class(dht::entry &result){
  std::cout << "test_out_of_class: key="<< std::endl;
}
class haha {
public:
   void test1(dht::entry &result){
      std::string key = result["key"].string();
      int value = result["value"].integer();
      std::cout << "test1: key=" << key << ", value="<<value<< endl;
      return;
   }
   void test2(dht::entry &result){
    std::string key = result["key"].string();
    int value = result["value"].integer();
    std::cout << "test2: key=" << key << ", value="<<value<< endl;
      return;
   }
   static void test1_wrapper(void* pt2Object, dht::entry &result){
      haha *myself = (haha*)pt2Object;
      myself->test1(result);
   }
   static void test2_wrapper(void* pt2Object, dht::entry &result){
      haha *myself = (haha*)pt2Object;
      myself->test2(result);
   }
   void test3(){
     std::cout << "test3"<< endl;
   }
   bool test4(unsigned char* datagram, int len,
       baseobject *value){
     std::string a;
     a.assign((const char*)datagram, len);
     std::cout << "test4: datagram="<<a <<", value="<<value->Value()<<std::endl;
     return true;
   }
   void test5(dht::entry &result, int param){
    std::string key = result["key"].string();
    int value = result["value"].integer();
    std::cout << "test5: key=" << key << ", value="<<value<< " param=" << param <<endl;
    return;
   }
};

dht::Deferred *testDefer(std::string key, int value){
  dht::Deferred *df = new dht::Deferred();
  dht::entry result;
  result["key"] = "abcd";
  result["value"] = 8888;
  // df->Callback(result);
  return df;
}

typedef boost::function<void(dht::entry&)> function_type;
// template <typename Func>
void try_bind(function_type cb){
  // boost::function<void(dht::entry&)> f_ = cb;
  dht::entry result;
  result["key"] = "abcd";
  result["value"] = 8888;
  cb(result);
  // cb();
}

void try_bind4( boost::function<bool(unsigned char*, int, baseobject*)> cb){
  std::string s = "I love programming!";
  baseobject value(100);
  bool result = cb((unsigned char *)s.c_str(), s.size(), &value);
  if (result)
    std::cout << "result is true" << std::endl;
  else
    std::cout << "result is false" << std::endl;
}

void try_bind5(function_type cb){
  // boost::function<void(dht::entry&)> f_ = cb;
  dht::entry result;
  result["key"] = "abcd";
  result["value"] = 8888;
  cb(result);
  // cb();
}
int main(int c, char **v){
  // dht::Deferred *df = new dht::Deferred();
  // haha *xixi = new haha();
  haha xixi;
/*
  dht::callbackFunc func;
  func.pt2Obj = xixi;
  func.pt2Func = haha::test2_wrapper;
  dht::Deferred *df = testDefer("abcd", 888);cb((unsigned char *)s.c_str(), s.size(), &value);
  df->AddCallback(func);
  dht::entry result;
  result["key"] = "abcd";
  result["value"] = 8888;
  df->Callback(result);*/
  // try_bind(boost::bind(&haha::test1, &xixi, _1));
  // try_bind(boost::bind(&test_out_of_class, _1));
  try_bind5(boost::bind(&haha::test5, &xixi, _1, 777));
  // try_bind4(boost::bind(&haha::test4, &xixi, _1, _2, _3));
  std::cout << "done" << std::endl;
  return 0;
}
// typedef int (haha::*pt2Member)();
// typedef char* (*pt2Function)(void* pt2Object, char* text);
// typedef int (*pt2Member)();
// int main(){
/*   struct timeval a;
   ACE_Time_Value t = ACE_OS::gettimeofday();
   gettimeofday(&a, NULL);
   cout << "sec=" << a.tv_sec << endl;
   cout << "usec=" << a.tv_usec << endl;
   cout << "sec=" << t.sec() << endl;
   cout << "usec=" << t.usec() << endl;*/
   // map<char, pt2Function> mymap;
   // map<char, pt2Function>::iterator it;
   // map<char, int> mymap;
   // map<char, int>::iterator it;
   // mymap['a'] = haha::test1_wrapper;
   // mymap['b'] = haha::test2_wrapper;
   // haha *xixi = new haha();
   // it=mymap.find('a');
   // char* res = (it->second)(xixi, "ddddddddd");
   // cout << "test2 = " << res << endl;
   /*haha *xixi = new haha();
   Deferred *df = new Deferred();
   callbackFunc func;
   func.pt2Obj = xixi;
   func.pt2Func = haha::test2_wrapper;
   df->AddCallback(func);
   map<char*, void*> cb_result;
   char a[] = "cccccccccc";
   cb_result["result"] = static_cast<void *>(a);
   df->Callback(&cb_result);*/
   /*typedef list<baseojbect> abc;
   list<abc> def;
   abc kk;
   def.push_back(kk);*/
   /*baseobject a(6), b(5);
   if (a>=b)
      cout<<"a>=b"<<endl;
   else
      cout<<"a<b"<<endl;*/
//    char a[] = "ddddd";
//    string b = (char *)a;
//    cout << "b="<<b<<endl;
//    return 0;
// }
/*
int main(int c, char **v){
   dht::entry e;
   e["result"] = 0;
   e["key"] = "key";
   e["value"] = 5000;
   list<dht::entry> nodes;
   dht::entry n1("abcdefg");
   dht::entry n2("hijklmsfdsfefefeffffffffffffffffffffffccccccccccc");
   nodes.push_back(n1);
   nodes.push_back(n2);
   e["nodes"] = dht::entry(nodes);
   char msg[300];
   int len = dht::bencode(msg, e);
   msg[len] = '\0';
   cout << "bencoded msg: " << msg << "\nlen: " << len << endl;
   dht::entry decoded_msg = dht::bdecode(msg, msg+len);
   string key = decoded_msg["key"].string();
   int value = decoded_msg["value"].integer();
   list<dht::entry> nodes1 = decoded_msg["nodes"].list();
   cout << "decode msg: key=" << key << ", value="<<value << endl;
   while (!nodes1.empty()){
     cout << "nodes: " << nodes1.front().string() << endl;
     nodes1.pop_front();
   }

   return 0;
}
*/
/*int main(int c, char **v){
  long a = rand();
  long b = time(NULL);
  cout << "rand()=" << a << endl;
  cout << "time()=" << b << endl;
  return 0;
}
*/
