#!/bin/bash
lupdate -recursive -locations relative ../../.. -ts *.ts
lupdate -pluralonly -recursive -locations relative -target-language en_GB ../../.. -ts pd_translation_en.ts
