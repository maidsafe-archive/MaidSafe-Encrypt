@rem
@rem  Change the following path names if you have installed Visual Studio or the
@rem  Visual C++ Toolkit in non-default locations...
@rem

@if exist "%PROGRAMFILES%\Microsoft Visual Studio 9.0\Common7\Tools\vsvars32.bat" (
  @call "%PROGRAMFILES%\Microsoft Visual Studio 9.0\Common7\Tools\vsvars32.bat"
  @echo.

  @if exist "%PROGRAMFILES%\Microsoft Visual Studio 9.0\vcvars32.bat" (
    @call "%PROGRAMFILES%\Microsoft Visual C++ Toolkit 2003\vcvars32.bat"
    @echo.
    @echo INFO: Visual C++ Toolkit 2003 also found.
    @echo.      Called the toolkit's vcvars32.bat *AFTER* Visual Studio's vsvars32.bat...
    @echo.
  )

  @echo INFO: Build environment successfully set...
  @echo.
) else (
  @echo WARNING: vsvars32.bat not found in "%PROGRAMFILES%\Microsoft Visual Studio .NET 2003\Common7\Tools"...
  @echo.
  @echo.         Install Visual Studio .NET 2003 in its default location or
  @echo.         modify "%~f0" to find vsvars32.bat where it is...
  @echo.
)



cmake ..\..\  -DwxWidgets_LIB_DIR="C:/lib/vc_lib"  -DCMAKE_BUILD_TYPE=Release -DwxWidgets_ROOT_DIR="C:/include" -G"NMake Makefiles"
                
