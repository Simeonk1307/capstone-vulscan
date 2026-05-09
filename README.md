# capstone-vulscan
This repository is regarding the capstone project assigned by Vivek Sir.


## Download the zip files and add it to PROJECT_ROOT
[https://drive.google.com/drive/folders/1UL8Df65qS51PTAZmZ1Xfjlh2m22yxpnK]

## Run this once at the start to create old_src and empty src (if any error read the `./setup.sh`)
```bash
    bash setup.sh
```
NOTE: ./src/models/* is not supposed to be pushed to github

## Create a venv, activate and install
```bash
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r all-requirements.txt
```


## Run this to create ./src/models (converts .pt to .onnx format)
```bash
    python3 convert.py
```
NOTE: do this after setup.sh  
NOTE: use `torch` i.e all the libraries mentioned in `all-requirements.txt` is put to use

## Create test files using `create-tests.sh`
```bash
    bash create-tests.sh
```
NOTE: create test files in ./test_samples

## Run this before building
```bash
    python3 ./src/app.py
```
NOTE: use the test files in ./test_samples to check the tool

## Uninstall torch (all its dependencies shd be removed)
```bash
    pip uninstall torch pandas onnxscript scikit-learn
```
OR

```bash
    rm -rf .venv
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r build-requirements.txt
```
NOTE: remove `torch`, `pandas`, `onnxscript` & `scikit-learn` i.e all the libraries mentioned in `build-requirements.txt` are only put to use


## Run this to build the executable
```bash
    bash build.sh
```
NOTE: this is wrt to current state and will change as project changes
