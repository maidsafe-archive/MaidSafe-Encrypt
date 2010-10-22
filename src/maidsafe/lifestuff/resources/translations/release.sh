#!/bin/bash
lrelease -compress -removeidentical *.ts
echo
echo Don\'t forget to update ../resources.qrc to add new languages!
