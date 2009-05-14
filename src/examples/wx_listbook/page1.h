#ifndef PAGE1_H_INCLUDED
#define PAGE1_H_INCLUDED

#include <wx/wx.h>
#include <cstring>
#include <iostream>


class Page1 : public wxPanel {
public:
  enum{
    idButton1 = 1100,
    idButton2
  };
  Page1(wxWindow *parent);
  std::string GetTxtCtrlVal();
private:
  wxBoxSizer *sizer_;
  wxButton *button1_, *button2_;
  wxTextCtrl *textctrl_;
};

#endif //  PAGE1_H_INCLUDED
