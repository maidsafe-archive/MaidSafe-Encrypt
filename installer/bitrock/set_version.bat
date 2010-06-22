@echo off
if (%1)==() goto help
if (%1)==(-h) goto help
if (%1)==(/h) goto help
if (%1)==(--help) goto help

set NEW_VERSION=%1
for /f "tokens=1-5 delims=." %%G in ("%NEW_VERSION%") do (
  set NEW_VERSION_ID=%%G%%H%%I%%J%%K
)

if exist temp.xml del temp.xml
for /f %%G in ('dir /b *.xml') do (
  echo Updating version for %%G
  copy %%G %%G.temp
  if exist temp.xml del temp.xml
  for /f "eol=` delims=`" %%H in (%%G) do (
    echo %%H> temp_line.txt
    for /f "tokens=1 delims= " %%I in ("%%H") do (
      setlocal ENABLEDELAYEDEXPANSION
      set CHECK_FOR_TAG=%%I
      if "!CHECK_FOR_TAG:~0,1!"=="<" (
        call :update_xml_line
      )
      endlocal
    )
    type temp_line.txt>> temp.xml
  )
  move temp.xml %%G
)

if exist temp.ini del temp.ini
for /f %%G in ('dir /b *.ini') do (
  echo Updating version for %%G
  copy %%G %%G.temp
  setlocal ENABLEDELAYEDEXPANSION
  echo [Update]>temp.ini
  for /f "skip=1 tokens=1,2 delims== " %%H in (%%G) do (
    set UPDATED=False
    call :is_version_tag %%H
    if !UPDATED!==Id (
      echo %%H = %NEW_VERSION_ID%>>temp.ini
    ) else (
      echo %%H = %%I>>temp.ini
    )
  )
  endlocal
  move temp.ini %%G
)
if exist temp_line.txt del temp_line.txt

"C:\Program Files\Git\bin\sh.exe" --login git_tag.sh %1

goto :eof



:update_xml_line
  for /f "tokens=1-4 delims=<>" %%W in ('type temp_line.txt') do (
    rem Case where version tag line has no leading spaces
    set UPDATED=False
    call :is_version_tag %%W
    if !UPDATED!==Normal (
      echo ^<%%W^>%NEW_VERSION%^<%%Y^>> temp_line.txt
      goto :eof
    )
    if !UPDATED!==Id (
      echo ^<%%W^>%NEW_VERSION_ID%^<%%Y^>> temp_line.txt
      goto :eof
    )
    if !UPDATED!==Filename (
      for /f "tokens=1,3 delims=-" %%U in ("%%X") do (
        echo ^<%%W^>%%U-%NEW_VERSION%-%%V^<%%Y^>> temp_line.txt
        goto :eof
      )
    )
    rem Case where version tag line does have leading spaces
    call :is_version_tag %%X
    if !UPDATED!==Normal (
      echo %%W^<%%X^>%NEW_VERSION%^<%%Z^>> temp_line.txt
      goto :eof
    )
    if !UPDATED!==Id (
      echo %%W^<%%X^>%NEW_VERSION_ID%^<%%Z^>> temp_line.txt
      goto :eof
    )
    if !UPDATED!==Filename (
      for /f "tokens=1,3 delims=-" %%U in ("%%Y") do (
        echo %%W^<%%X^>%%U-%NEW_VERSION%-%%V^<%%Z^>> temp_line.txt
        goto :eof
      )
    )
    goto :eof
  )
  goto :eof


:is_version_tag
  if [%1]==[] (goto :eof)
  if /i %1==version (
    set UPDATED=Normal
    goto :eof
  )
  if /i %1==windowsResourceFileVersion (
    set UPDATED=Normal
    goto :eof
  )
  if /i %1==windowsResourceProductVersion (
    set UPDATED=Normal
    goto :eof
  )
  if /i %1==versionId (
    set UPDATED=Id
    goto :eof
  )
  if /i %1==version_id (
    set UPDATED=Id
    goto :eof
  )
  if /i %1==filename (
    set UPDATED=Filename
    goto :eof
  )
  goto :eof



:help
  echo Error: no version text passed.
  echo.
  echo usage: set_version [version text]
  echo e.g. set_version 0.0.001
  echo.
  exit /b 1
