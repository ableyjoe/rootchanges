#!/bin/sh

CHANNEL=$1
USERNAME=$2

WEBHOOK='https://hooks.slack.com/services/<insert your web hook here>'

if [ -z "${CHANNEL}" -o -z "${USERNAME}" ]
then
  echo "Syntax: $(basename $0) channel username" >&2
  exit 1
fi

while read s
do
  curl -s -X POST --data-urlencode "payload={\"text\": \"${s}\", \"channel\": \"#${CHANNEL}\", \"username\": \"${USERNAME}\"}" ${WEBHOOK} >/dev/null 2>&1
done

