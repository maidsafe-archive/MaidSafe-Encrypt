/***************************************************************
 * Name:    pdguiApp.cpp
 * Purpose:   Code for Application Class
 * Author:  David Irvine (david.irvine@maidsafe.net)
 * Created:   2008-10-29
 * Copyright: David Irvine (www.maidsafe.net)
 * License:
 **************************************************************/
#include "gui/pdguiapp.h"
#include <wx/image.h>
#include <wx/xrc/xmlres.h>
// #include "gui/images.cc"
#include "gui/pdguimain.h"

// #ifdef DEBUG
// #include <wx/crtdbg.h>
// #define DEBUG_NEW new(_NORMAL_BLOCK ,__FILE__, __LINE__)
// #else
// #define DEBUG_NEW new
// #endif

IMPLEMENT_APP(pdguiapp)

extern void InitXmlResource();
bool pdguiapp::OnInit() {
  bool wxsOK = true;
  wxXmlResource::Get()->InitAllHandlers();
  InitXmlResource();
  wxInitAllImageHandlers();
  if (wxsOK) {
    main_frame = new pdguiFrame(0L);
    main_frame->Show();
    SetTopWindow(main_frame);
  }
  return wxsOK;
}

