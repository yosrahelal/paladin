#!/bin/bash

count=0

until [ $count -ge 3 ]; do
  pg_isready -U postgres && count=$((count + 1))
  echo "Waiting for postgres to be ready..."
  sleep 1
done
