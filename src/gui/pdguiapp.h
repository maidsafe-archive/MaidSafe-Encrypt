/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 13, 2008
 *      Author: Team
 */
#ifndef GUI_PDGUIAPP_H_
#define GUI_PDGUIAPP_H_
// #ifdef __WXMSW__
//   #undef CreateDialog
//   #include "wx/msw/winundef.h"
// #endif

#include <wx/app.h>
#include "gui/pdguimain.h"

class pdguiapp : public wxApp {
  public:
    virtual bool OnInit();
    pdguiapp() : main_frame(NULL) {}
    pdguiapp(const pdguiapp&);
    pdguiapp& operator=(const pdguiapp&);
    // virtual int OnExit();
    // private:
    pdguiFrame *main_frame;
};
// DECLARE_APP(pdguiapp)
#endif  // GUI_PDGUIAPP_H_
