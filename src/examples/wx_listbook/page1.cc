#include "page1.h"

Page1::Page1(wxWindow *parent)
  : wxPanel(parent) {
  sizer_ = new wxBoxSizer(wxVERTICAL);
  button1_ = new wxButton(this, idButton1, wxT("First button"));
  sizer_->Add(button1_, 0, wxEXPAND);
  button2_ = new wxButton(this, idButton2, wxT("Second button"));
  sizer_->Add(button2_, 1, wxEXPAND);
  textctrl_ = new wxTextCtrl(this, wxID_ANY);
  sizer_->Add(textctrl_, 2, wxEXPAND);
  this->SetSizer(sizer_);
}

std::string Page1::GetTxtCtrlVal() {
  wxString val = textctrl_->GetValue();
  std::string res = (std::string) val.ToAscii();
  return res;
}



