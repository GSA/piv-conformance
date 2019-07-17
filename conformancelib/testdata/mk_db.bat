@ECHO OFF
REM
REM This Windows batch file sets up a Python environment and 
REM converts the spreadsheets to .db files. Use a Windows CMD
REM window to run this.  Do not use Cygwin with "CMD /c."
REM
REM If this utility runs correctly there will be 4 total files
REM copied to the .\tools\85b-swing-gui directory for testing.
REM

SET VENV=%PROMPT:~1,4%
echo %VENV%
IF %VENV% NEQ venv (
	PYTHON -mvenv venv-xlrd
	.\venv-xlrd\Scripts\activate
	PIP install --upgrade pip
	PIP install xlrd
	PIP install xlwt
	PIP install xlsxwriter
	.\venv-xlrd\Scripts\activate
)

FOR %%x IN (
	PIV_ICAM_Test_Cards
	PIV-I_ICAM_Test_Cards
	PIV_Production_Cards
	PIV-I_Production_Cards
	PIV-I_Carillon_Cards
	PIV-I_Production_IdenTrust_Cards
) do (
	ECHO "Processing %%x.xlsx"
	IF EXIST %%x.db DEL %%x.db
	IF EXIST %%x.sql DEL %%x.sql
	IF EXIST %%x.xlsx (
		PYTHON CctDatabasePopulator.py -i %%x.xlsx -o %%x.sql
		TYPE %%x.sql | sqlite3 %%x.db
		COPY %%x.db ..\..\tools\85b-swing-gui\
	) ELSE (
		echo %%x.xlsx is missing
	)
)
