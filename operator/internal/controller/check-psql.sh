#!/bin/bash

count=0

until [ $count -ge 3 ]; do
  psql -U postgres -c 'SELECT 1' && count=$((count + 1))
  echo "Waiting for postgres to be ready..."
  sleep 2
done
