#!/usr/bin/bash

#if [ $(expr $(uname) : "^.*CYG") -eq 3 ]; then
if [ 0 -eq 1 ]; then
	echo -n "Hit <ENTER> when ready to invoke Windows Python detour around Cygwin: " 
	read ans
	mkdbParam=""
	if [ ! -d venv-xlrd ]; then #prompt create new
		echo "Forcing a new installation of venv-xlrd..."
		mkdbParam="-f"
	elif [ -d venv-xlrd ] && [ "z$1" == "z-f" ]; then
		echo "You must first manually remove venv-xlrd -- that's above my paygrade"
		exit 1
	elif [ "z$1" != "z-f" ]; then
		echo "Building databases..."
	fi
	cmd /c mk_db.bat $mkdbParam
	echo -n "Hit <ENTER> to close this window: " 
	read ans
	exit 1
fi

PYTHON=${PYTHON:-$(which python)}

# Don't try to parse $PS1, just go for it
$PYTHON -mvenv venv-xlrd
source ./venv-xlrd/bin/activate
pip install --upgrade pip
pip install xlrd==1.2.0
pip install xlwt
pip install xlsxwriter
source ./venv-xlrd/bin/activate

for F in PIV_Production_Cards.xlsx PIV-I_Production_Cards.xlsx PIV_ICAM_Test_Cards.xlsx PIV-I_ICAM_Test_Cards.xlsx PIV-I_Carillon_Cards.xlsx PIV-I_XTec_First_Data_Cards.xlsx PIV-I-GSA_MSO_Cards.xlsx
do
	BASE=$(basename $F .xlsx)
	echo "Processing $F..."
	rm -f $BASE.db
	rm -f $BASE.sql
	if [ -f $BASE.xlsx ]; then 
		python CctDatabasePopulator.py -i $BASE.xlsx -o $BASE.sql
        if [ $? -eq 0 ]; then
		    sqlite3 $BASE.db < $BASE.sql
            if [ $? -eq 0 ]; then
		        cp -p $BASE.db ../../tools/85b-swing-gui/
            fi
        fi
	else
		echo "$BASE.xlsx is missing"
	fi
done

exit 0
