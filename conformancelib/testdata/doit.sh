#!/bin/bash

#rm -f exploded.db exploded.sql
#rm -f collapsed.db collapsed.sql
rm -f optimized.db optimized.sql

#sudo cp /media/sf_Downloads/exploded.xlsx /media/sf_Downloads/collapsed.xlsx .
#sudo chown bfontana:bfontana *.xlsx

#python CctDatabasePopulator.py -i collapsed.xlsx -o collapsed.sql
#if [ $? == 0 ]; then
#  sqlite3 collapsed.db < collapsed.sql
#fi

#python CctDatabasePopulator.py -i exploded.xlsx -o exploded.sql
#if [ $? == 0 ]; then
#  sqlite3 exploded.db < exploded.sql
#fi

python CctDatabasePopulator.py -i optimized.xlsx -o optimized.sql
if [ $? == 0 ]; then
  sqlite3 optimized.db < optimized.sql
fi
