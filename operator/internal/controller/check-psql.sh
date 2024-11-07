#!/bin/sh

until [ psql -U postgres -c 'SELECT 1' ]; do
  echo "Waiting for postgres to be ready..."
  sleep 2
done
