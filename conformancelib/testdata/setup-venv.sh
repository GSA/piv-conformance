#!/usr/bin/bash

UNAME=$(uname)
CYG=$(expr $UNAME : CYG)

cleanCRs() {
	if [ $CYG -eq 3 ]; then
		for F in $(find venv-xlrd -name '*.py'); do
			sed -i.bak 's/\r$//' $F
		done
		sed -i.bak 's/\r$//' venv-xlrd/Scripts/activate
	fi
}

python -mvenv venv-xlrd; cleanCRs
source venv-xlrd/Scripts/activate
pip install --upgrade pip; cleanCRs
pip install xlrd; cleanCRs
pip install xlwt; cleanCRS
pip install xlsxwriter; cleanCRs
source venv-xlrd/Scripts/activate
