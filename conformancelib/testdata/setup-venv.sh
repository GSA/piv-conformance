#!/usr/bin/bash

python36 -mvenv venv-xlrd
source venv-xlrd/bin/activate
pip install --upgrade pip
pip install xlrd
pip install xlwt
pip install xlsxwriter
source venv-xlrd/bin/activate