#!/usr/bin/awk -f

/^[\+-][a-z]/ {
  key = $1;
  sub(/^[\+-]/, "", key);
  sub(/:$/, "", key);
  changed[key] = 1;
}

END {
  delete changed["changed"];
  for (n in changed) {
    if (!something) {
      tweet = "<" url "|IANA whois data for " tld "> changed (" n;
      something = 1;
    } else
     if (length(tweet) + length(n) +length(url) < 130 && !dots)
       tweet = tweet ", " n;
     else
       if (!dots) {
         tweet = tweet "...";
         dots = 1;
       }
  }
  if (something)
    print tweet ")";
}

