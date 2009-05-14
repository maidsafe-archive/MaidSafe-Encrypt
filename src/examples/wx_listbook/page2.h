#ifndef PAGE2_INCLUDED
#define PAGE2_INCLUDED

#include <wx/wx.h>

class Page2 : public wxPanel {
public:
  enum{
    idButton1 = 1200,
    idButton2
  };
  Page2(wxWindow *parent);
private:
  wxBoxSizer *sizer_;
  wxButton *button1_, *button2_;
};

#endif //  PAGE2_INCLUDED
