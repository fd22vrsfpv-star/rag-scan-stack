#PGPASSWORD='ChangeMe_RW_#1' pg_dump --schema-only --no-owner --no-privileges -U rag-postgres  -d edb_rw -h 127.0.0.1
#
#
echo "########################     app ####################"
PGPASSWORD='app' pg_dumpall -h 127.0.0.1 -p 5432 -U app  -l postgres   --schema-only --no-owner --no-privileges 
echo "########################     scans ####################"
PGPASSWORD='app' pg_dumpall -h 127.0.0.1 -p 5432 -U app  -l scans   --schema-only --no-owner --no-privileges 
#PGPASSWORS='app' pg_dump --schema-only --no-owner --no-privileges -U app -W "app" -d scans  -h 127.0.0.1 --schema-only 
