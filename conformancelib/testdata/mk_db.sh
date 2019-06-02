#!/usr/bin/bash

# Note: If this is running out of Cygwin, do NOT use this.
#
# Instead, use mk_db.bat from a true CMD window.  As of 5/7/2019,
# Cygwin's Python 2.7 implementation doesn't have the prequisite
# modules needed to convert .xlsx to .sql, so we must use the
# Windows 64 Python distro.

if [ $(expr $(uname) : "^.*CYG") -eq 3 ]; then
        echo "Please run CMD /c mk_db.bat for Cygwin environments"
        exit 1
fi
PYTHON=${PYTHON:-$(which python)}

# Don't try to parse $PS1, just go for it
$PYTHON -mvenv venv-xlrd
source ./venv-xlrd/bin/activate
pip install --upgrade pip
pip install xlrd
pip install xlwt
pip install xlsxwriter
source ./venv-xlrd/bin/activate

for F in 85b_test_definitions_PIV_ICAM_Test_Cards \
        85b_test_definitions_PIV-I_ICAM_Test_Cards \
        85b_test_definitions_PIV_Production_Cards \
        85b_test_definitions_PIV-I_Production_Cards
do
        BASE=$F
  echo "Processing $F..."
        rm -f $BASE.db
        rm -f $BASE.sql
        if [ -f $BASE.xlsx ]; then 
                python CctDatabasePopulator.py -i $BASE.xlsx -o $BASE.sql
                sqlite3 $BASE.db < $BASE.sql
                cp -p $BASE.db ../../tools/85b-swing-gui/
        else
                echo "$BASE.xlsx is missing"
        fi
done

exit 0
