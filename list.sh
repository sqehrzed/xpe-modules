#!/usr/bin/env bash

rm -f modules.yml
touch modules.yml

start=$(pwd)
echo "## List of all included modules" >> ${start}/modules.yml
for folder in ${start}/*; do
  if test -d ${folder}; then
    echo "${folder}"
    echo "" >> ${start}/modules.yml
    path=`echo ${folder} | rev | cut -d '/' -f-1 | rev`
    echo "### ${path}" >> ${start}/modules.yml
    echo "" >> ${start}/modules.yml
    # Get list of all modules
    for F in `ls ${folder}/*.ko`; do
      X=`basename ${F}`
      M=${X:0:-3}
      DESC=`modinfo ${F} | awk -F':' '/description:/{ print $2}' | awk '{sub(/^[ ]+/,""); print}'`
      [ -z "${DESC}" ] && DESC="${X}"
      echo "${M} \"${DESC}\""
      echo "* ${M} \"${DESC}\"" >> ${start}/modules.yml
    done
  fi
done
echo "" >> ${start}/modules.yml
date=$(date +'%y.%m.%d')
echo "Update: ${date}" >> ${start}/modules.yml