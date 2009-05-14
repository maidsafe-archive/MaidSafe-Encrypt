#include "page2.h"

Page2::Page2(wxWindow *parent)
  : wxPanel(parent) {
  sizer_ = new wxBoxSizer(wxHORIZONTAL);
  button1_ = new wxButton(this, idButton1, wxT("Button 1"));
  sizer_->Add(button1_, 0, wxEXPAND);
  button2_ = new wxButton(this, idButton2, wxT("Button 2"));
  sizer_->Add(button2_, 1, wxEXPAND);
  this->SetSizer(sizer_);
}
