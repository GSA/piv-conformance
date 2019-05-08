ECHO OFF
DEL expanded.db expanded.sql
PYTHON CctDatabasePopulator.py -i expanded.xlsx -o expanded.sql
TYPE expanded.sql | sqlite3 expanded.db
