#!/bin/bash
/opt/pd-5/autoupdate-linux.bin --mode unattended > /dev/null 2>&1
if [ $? -eq 0 ]; then
  /opt/pd-5/autoupdate-linux.bin
else
  echo "Nothing to report..";
fi

