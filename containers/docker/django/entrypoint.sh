#!/bin/sh

set -e

echo "Waiting for Postgresql to be available.."
/src/docker/wait-for-it.sh -h "$(echo $DATABASE_URL |sed 's/.*\(@[^:]*:\).*/\1/'| cut -c2- | cut -d ':' -f 1)" -p 5432

echo "Wait 5 more seconds"
sleep 5;

cd /src

echo "Running migrations.."
python manage.py migrate

echo "Testing the Django server.."
python manage.py test --keepdb

echo "Running migrations.."
python manage.py migrate

echo "Starting the Django server.."
python manage.py runserver 0.0.0.0:5000

##
##
