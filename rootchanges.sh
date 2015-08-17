#!/bin/sh

HOME=$(dirname $0)
NEW=${HOME}/root.new
OLD=${HOME}/root.current
TMP=${HOME}/root.$$

SLACK=${HOME}/send_to_slack.sh

dig @xfr.lax.dns.icann.org . axfr | egrep -v '^;' >"${NEW}"

SOAS=$(egrep -i 'IN[[:space:]]+SOA[[:space:]]+' ${NEW} | wc -l)

if [ ${SOAS} -eq 2 ]; then
  touch "${OLD}"

  diff -u "${OLD}" "${NEW}" | ${HOME}/rootchanges.awk | \
      ${SLACK} rootzone RootChanges

  mv "${NEW}" "${OLD}"
fi

