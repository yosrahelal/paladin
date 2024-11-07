#!/bin/sh

echo "check kubectl target is kind-paladin"
currentContext=`kubectl config current-context`
if [ ${currentContext} != "kind-paladin" ]; then
  echo "EXIT kubectl target is not kind-paladin"
  exit 1
fi  