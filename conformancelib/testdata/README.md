### Test Data
This directory contains the 85B requirements expressed in a MS Excel workbook for each of the four profiles.  The .xlsx files are converted via a Python script to a .sql file that can be imported to a database.  This implementation uses sqlite3.

Create a directory, for instance, python_den, and change to it.  

Run 
```
sh ../setup-venv.sh
# Activate the virtual environment
# On MacOS do this
source venv-xlrd/bin/activate   

```

This creates a "virtual" Python environment in which all of the classes need to perform the Excel to SQL conversion.

Copy the `CctDatabasePopulator.py` and `conformance-schema.sql` files from the directory above.

Run:
```
python36 CctDatabasePopulator.py -i filename.xlsx -o filename.sql
sqlite3 filename.db < filename.sql
```

That will produce the .sql and .db files for the profile *filename*.

### Weak-key rejection fixtures

`weak-rsa1024-test-only.der` is a public certificate for the RSA key-size rejection cases.
`weak-rsa1024-cms-test-only.zip` contains five public signed objects generated once with the existing regression builder: CHUID (`269.bin`), fingerprints (`286.bin`), face (`306.bin`), Security Object (`324.bin`) and iris (`338.bin`). The CMS signer uses a synthetic 1,024-bit RSA certificate. No private key is stored, and ordinary test runs do not generate weak keys.

`ExistingCctRegressionTest` verifies signatures, signed attributes, CBEFF lengths and Security Object relationships independently of the mapped key-size assertions. The original case routes must reject these objects for their key size; valid generated controls must pass. The biometric payloads only support these CMS tests and do not establish image conformance. Both weak-key fixture files are test inputs and are excluded from runnable release packages.

