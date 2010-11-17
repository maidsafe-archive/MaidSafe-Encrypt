@echo off
setlocal
echo Checking files - each "." represents a single file.
dir ..\..\src\maidsafe\*.cc /s /b >filelist.txt
dir ..\..\src\maidsafe\*.h /s /b >>filelist.txt
findstr /i /v "Done Total .pb. sqlite3.h lifestuff\widgets lifestuff\client" filelist.txt > filelist2.txt
set currentpath=%cd%
cd ..\..\
set rootpath=%cd%
cd %currentpath%
echo Setup>code_style_errors.txt
set count=0
for /f %%g in (filelist2.txt) do (
  @"cmd /c %rootpath%\build\tools\cpplint.py "%%g" 2>>code_style_errors.txt"
  <nul (set/p z=".")
)
findstr /i /v /b "Setup Done Total" code_style_errors.txt > code_style_errors2.txt
set count=0
for /f  %%g in (code_style_errors2.txt) do (call :s_do_sums)
cls & echo. & echo.
type code_style_errors2.txt
echo. & echo.
if %count% geq 1 echo There are %count% errors! & call :function & exit /B 1
if %count% equ 0 echo There aren't any errors.
del filelist.txt filelist2.txt code_style_errors.txt code_style_errors2.txt
echo.
:s_do_sums
 set /a count+=1
 goto :eof
:function
 echo.
 del filelist.txt filelist2.txt code_style_errors.txt code_style_errors2.txt
 exit /B 1
 goto :eof