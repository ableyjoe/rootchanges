#!/bin/sh

HOME=$(dirname $0)
WHOIS="${HOME}/whois"

SLACK=${HOME}/send_to_slack.sh

mkdir -p "${WHOIS}"

for ns in xfr.cjr.dns.icann.org xfr.lax.dns.icann.org; do
  dig @${ns} . axfr | \
    awk '/^[a-zA-Z]+\.[[:space:]]+[0-9]+[[:space:]]+[Ii][Nn][[:space:]]+[Nn][Ss][[:space:]]/ { sub(/\.$/, "", $1); print toupper($1); }'
done | sort | uniq | while read tld; do
  touch "${WHOIS}/${tld}"
done

for f in $(find ${WHOIS} -type f -a \! -name "*.tmp.*" -a \! -name "*.url"); do
  tld=$(basename "${f}")

  TMP="${WHOIS}/${tld}.tmp.$$"
  rm -f "${TMP}"

  url="http://www.iana.org/cgi-bin/whois?q=${tld}" 

  whois -h whois.iana.org "${tld}" >${TMP}
  if egrep -q '^source:' "${TMP}"; then
    diff -u "${WHOIS}/${tld}" "${TMP}" | ${HOME}/whoischanges.awk \
      -v url="${url}" -v tld=${tld} | \
          ${SLACK} rootzone RootChanges
    mv "${TMP}" "${WHOIS}/${tld}"
  else
    rm -f "${TMP}"
  fi
done

