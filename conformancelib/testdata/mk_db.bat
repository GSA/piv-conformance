@ECHO OFF
REM
REM This Windows batch file sets up a Python environment and 
REM converts the spreadsheets to .db files. Use a Windows CMD
REM window to run this.  Do not use Cygwin with "CMD /c."
REM
REM If this utility runs correctly there will be 4 total files
REM copied to the .\tools\85b-swing-gui directory for testing.
REM

IF "%PYTHONPATH%"=="" (
ECHO PYTHONPATH is NOT defined
EXIT
)

IF "%1"=="-f" (
	PYTHON -mvenv venv-xlrd
	CMD /C .\venv-xlrd\Scripts\activate
	.\venv-xlrd\Scripts\easy_install xlwt
	.\venv-xlrd\Scripts\PIP install --upgrade pip
	.\venv-xlrd\Scripts\PIP install xlrd
	.\venv-xlrd\Scripts\PIP install xlwt
	.\venv-xlrd\Scripts\PIP install xlsxwriter
)


COPY conformance-schema.sql venv-xlrd
COPY *.xlsx venv-xlrd
COPY *.py venv-xlrd

CD venv-xlrd
CMD /C Scripts\Activate

FOR %%x IN (
	PIV_ICAM_Test_Cards
	PIV-I_ICAM_Test_Cards
	PIV_Production_Cards
	PIV-I_Production_Cards
	PIV-I_Carillon_Cards
	PIV-I_IdenTrust_Cards
) do (
	ECHO "Processing %%x.xlsx"
	IF EXIST %%x.db DEL %%x.db
	IF EXIST %%x.sql DEL %%x.sql
	IF EXIST %%x.xlsx (
		PYTHON CctDatabasePopulator.py -i %%x.xlsx -o %%x.sql
		TYPE %%x.sql | sqlite3 %%x.db
		COPY %%x.sql ..
		COPY %%x.db ..
	) ELSE (
		ECHO %%x.xlsx is missing
	)
)
CD ..
COPY *.db ..\..\tools\85b-swing-gui\

REM Remove this when we are in maintenance mode

