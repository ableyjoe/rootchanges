#!/usr/bin/awk -f
#
# Convert a root zone diff into a series of tweetable observations.

# Derive keytag from DNSKEY canonical presentation format data, RFC4034
function keytag(flags, proto, alg, pubkey) {
  BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  # length of RDATA in octets, count as we go
  rdlength = 0;

  # DNSKEY fixed-field RDATA, RFC4034 section 2
  rdata[rdlength++] = int(flags / 256);
  rdata[rdlength++] = flags % 256;
  rdata[rdlength++] = proto;
  rdata[rdlength++] = alg;

  # DNSKEY public key modulus, decode base64 and store
  while (pubkey) {
    # extract the next four base64 6-bit words into word[]
    for (i = 1; i < 5; i++) {
      w = index(BASE64, substr(pubkey, i, 1));
      word[i] = (w ? w - 1 : 0);
    }

    # derive 3 octets from the 4 base64 6-bit words
    rdata[rdlength++] = (word[1] * 4 + int(word[2] / 16));
    rdata[rdlength++] = (word[2] * 16 + int(word[3] / 4)) % 256;
    rdata[rdlength++] = (word[3] * 64 + word[4]) % 256;

    # decrease incoming string by 4
    pubkey = substr(pubkey, 5);
  }

  # calculate the keytag
  if (alg == 1) {
    # algorithm 1 is special, see RFC 4034 appendix B.1
    return 256*rdata[rdlength - 3] + rdata[rdlength - 2];
  } else {
    # for all other algorithms, follow RFC 4034 appendix B
    ac = 0;

    for (i = 0; i < rdlength; i++)
      ac += (i % 2 ? rdata[i] : 256 * rdata[i]);
    ac += int(ac / 65536) % 65536;
    return ac % 65536;
  }
}

# Simplistic analysis of zone diff

BEGIN {
  algorithm[1] = "RSA-MD5";
  algorithm[3] = "DSA";
  algorithm[5] = "RSA-SHA1";
  algorithm[6] = "DSA-NSEC3-SHA1";
  algorithm[7] = "RSA-SHA1-NSEC3-SHA1";
  algorithm[8] = "RSA-SHA256";
  algorithm[10] = "RSA-SHA512";
  algorithm[12] = "GOST R 34.10-2001";
  algorithm[13] = "ECDSAP256SHA256Y";
  algorithm[14] = "ECDSAP384SHA384Y";

  digest[1] = "SHA-1";
  digest[2] = "SHA-256";
  digest[3] = "GOST R 34.11-94";
  digest[4] = "SHA-384";
}

/^\+\.[[:space:]]+[0-9]+[[:space:]]+[Ii][Nn][[:space:]]+[Ss][Oo][Aa][[:space:]]/ {
  if (!serial) {
    serial = "in root zone serial " $7;
    print "Root Zone serial", $7, "has been published"
  }
}

/^\+/ {
  action = "added";
}

/^-/ {
  action = "dropped";
}

/^[+-][a-zA-Z0-9\.]+[[:space:]]/ {
  owner = toupper($1);
  sub(/^[+-]/, "", owner);
  sub(/\.$/, "", owner);
  if (owner == "") owner = "Root Zone";
}

/^[\+-][a-zA-Z]+\.[[:space:]]+[0-9]+[[:space:]]+[Ii][Nn][[:space:]]+[Nn][Ss][[:space:]]/ {
  ns = $5;
  sub(/\.$/, "", ns);
  print owner, "nameserver", toupper(ns), action, serial;
}

/^[\+-][a-zA-Z]+\.[[:space:]]+[0-9]+[[:space:]]+[Ii][Nn][[:space:]]+[Dd][Ss][[:space:]]/ {
  print owner, "delegation signer", "keytag", $5, \
    "algorithm", (algorithm[$6] ? algorithm[$6] : $6), "digest", \
    (digest[$7] ? digest[$7] : $7), action, serial;
}

/^[\+-][a-zA-Z\.]+[[:space:]]+[0-9]+[[:space:]]+[Ii][Nn][[:space:]]+[Aa]+[[:space:]]/ {
  print owner, "glue record address", $5, action, serial;
}

/^[\+-][a-zA-Z\.]+[[:space:]]+[0-9]+[[:space:]]+[Ii][Nn][[:space:]]+[Dd][Nn][Ss][Kk][Ee][Yy][[:space:]]/ {
  pubkey = "";
  for (i = 8; i <= NF; i++)
    pubkey = pubkey $i;

  print owner, ($5 == 256 ? "ZSK" : "KSK"), \
    "keytag", keytag($5, $6, $7, pubkey), \
    "algorithm", (algorithm[$7] ? algorithm[$7] : $7), \
    action, serial;
}

