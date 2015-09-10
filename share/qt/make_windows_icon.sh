#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/cryptoken.ico

convert ../../src/qt/res/icons/cryptoken-16.png ../../src/qt/res/icons/cryptoken-32.png ../../src/qt/res/icons/cryptoken-48.png ${ICON_DST}
