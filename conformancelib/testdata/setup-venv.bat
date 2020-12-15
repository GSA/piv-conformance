ECHO OFF
DEL /F /S /Q venv-xlrd
PYTHON -mvenv venv-xlrd
venv-xlrd\Scripts\activate
PIP install --upgrade pip
PIP install xlrd==1.2.0
PIP install xlwt
PIP install xlsxwriter
venv-xlrd\Scripts\activate
