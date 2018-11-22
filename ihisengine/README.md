-Run the following commands to create odb and cluster database


$ su postgres
$ createuser --no-superuser --no-createdb --no-createrole zato
$ createdb --owner=zato ihiszato
$ psql --dbname ihiszato --command="ALTER ROLE zato WITH PASSWORD 'password'"
$