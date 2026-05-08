#!/bin/bash

echo "1. Cleaning old builds"
rm -rf build/ dist/
rm ./vulscan.spec

echo "2. Building One-File Executable "
# Using the optimized flags we discussed
pyinstaller --noconfirm --onefile --clean \
    --add-data "src/classes.npy:." \
    --add-data "src/SakBunderan.ttf:." \
    --add-data "src/CWE_Model_1lyr_12hd_GPU2CPU.pt:." \
    --add-data "src/iitpkd_logo.png:." \
    --add-data "src/vulscan_dir.py:." \
    --collect-all "transformers" \
    --collect-all "torch" \
    --copy-metadata "numpy" \
    --copy-metadata "huggingface-hub" \
    src/vulscan.py

echo "3. Done! Check the dist/ folder"