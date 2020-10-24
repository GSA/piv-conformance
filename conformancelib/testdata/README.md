### Test Data
This directory contains the 85B requirements expressed in a MS Excel workbook for each of the four profiles.  The .xlsx files are converted via a Python script to a .sql file that can be imported to a database.  This implementation uses sqlite3.

Create a directory, for instance, python_den, and change to it.  

Run `sh ../setup-venv.sh`

This creates a "virtual" Python environment in which all of the classes need to perform the Excel to SQL conversion.

Copy the .py file from the directory above.

Run:
```
python36 CctDatabasePopulator.py -i filename.xlsx -o filename.sql
sqlite3 filename.db < filename.sql
```

That will produce the .sql and .db files for the profile *filename*.

