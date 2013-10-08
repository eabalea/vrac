#! /bin/sh

if [ -z $1 ]; then
  echo "I want a .pem file in parameter"
  exit
fi

if [ `grep -c "BEGIN X509 CRL" $1` -gt 0 ]; then
  HASH=`openssl crl -hash -noout -inform PEM -in "$1"`
  echo "The hash is: $HASH"

  for i in `seq 0 10`; do
    if [ ! -f $HASH.r$i ]; then
      ln -s "$1" $HASH.r$i
      break
    else
      echo "$HASH.r$i is already taken"
    fi
  done
else
  if [ ` grep -c "BEGIN CERTIFICATE" $1` -gt 0 ]; then
    HASH=`openssl x509 -hash -noout -inform PEM -in "$1"`
    echo "The hash is: $HASH"

    for i in `seq 0 10`; do
      if [ ! -f $HASH.$i ]; then
        ln -s "$1" $HASH.$i
        break
      else
        echo "$HASH.$i is already taken"
      fi
    done
  else
    echo "Error, this file is neither a CRL, nor a certificate."
  fi
fi

