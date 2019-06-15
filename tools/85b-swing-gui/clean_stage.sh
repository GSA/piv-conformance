rm 85b-swing-gui/*.csv
rm 85b-swing-gui/*.log
rm 85b-swing-gui/*.html
pushd ../../conformancelib/testdata/
set -e
source venv-xlrd/bin/activate
for f in ls 85b*.db; do
    BASE=$(basename $f .db)
    if [[ -f $BASE.xlsx ]]; then
        set -x
        rm $f
        python CctDatabasePopulator.py -i $BASE.xlsx -o $BASE.sql
        sqlite3 $f <$BASE.sql
        set +x
    fi
done
popd
cp -v ../../conformancelib/testdata/85b*.db 85b-swing-gui/

