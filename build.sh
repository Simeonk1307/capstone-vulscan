#!/bin/bash

echo "1. Cleaning old builds"
rm -rf build/ dist/
rm ./vulscan.spec

echo "2. Building One-File Executable "
# Using the optimized flags we discussed
pyinstaller \
    --noconfirm \
    --clean \
    --onefile \
    --name vulscan \
    --paths src \
    --add-data "src/models:models" \
    --collect-all onnxruntime \
    --collect-all numpy \
    --hidden-import onnxruntime \
    --hidden-import numpy \
    --hidden-import numpy.core.multiarray \
    --hidden-import numpy.core._multiarray_umath \
    --hidden-import numpy.core._methods \
    --hidden-import numpy.lib.format \
    src/app.py

echo "3. Done! Check the dist/ folder"