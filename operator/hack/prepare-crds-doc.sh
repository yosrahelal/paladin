#!/bin/bash

pwd=$(pwd)
echo -e "---\ntitle: core.paladin.io\n---\n\n$(cat ${pwd}/../doc-site/docs/reference/crds/core.paladin.io.md)" > ${pwd}/../doc-site/docs/reference/crds/core.paladin.io.md
