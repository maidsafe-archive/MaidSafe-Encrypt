#!/bin/sh
git tag -a -m "Tagged version $1" $1
exit $?
