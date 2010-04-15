#!/bin/bash
lupdate -no-obsolete -recursive -locations relative ../../.. -ts *.ts
lupdate -no-obsolete -pluralonly -recursive -locations relative -target-language en_GB ../../.. -ts pd_translation_en.ts
