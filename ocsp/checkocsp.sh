#! /bin/sh

GET=0
KEEP=0
NONCE="-no_nonce"
SIGN=""
AUTH=""
TIMEIT=0
ESCAPE=0

# TODO:
#  - have a more precise "time"
#  - be able to add any extension, critical or not
#  - be able to request for several certificates at once, from the same CA or not
#  - be able to request for an arbitrary serial number

TEMP=`getopt -o gpc:kntu:eh --long get,post,cert:,keep,nonce,time,url:,escape,signer:,signkey:,authcert:,authkey:,help -n 'checkocsp.sh' -- "$@"`

eval set -- "$TEMP"

while true ; do
  case "$1" in
    -g|--get) GET=1; shift;;
    -p|--post) GET=0; shift;;
    -c|--cert) CERT=$2; shift 2;;
    -k|--keep) KEEP=1; shift;;
    -n|--nonce) NONCE=""; shift;;
    -t|--time) TIMEIT=1; shift;;
    -u|--url) URL=$2; shift 2;;
    -e|--escape) ESCAPE=1; shift;;
    --signer) SIGNER=$2; shift 2;;
    --signkey) SIGNKEY=$2; shift 2;;
    --authcert) AUTHCERT=$2; shift 2;;
    --authkey) AUTHKEY=$2; shift 2;;
    -h|--help) echo "Options:"
               echo "  -g|--get"
	       echo "  -p|--post (by default)"
	       echo "  -c|--cert <file>"
	       echo "  -k|--keep"
	       echo "  -n|--nonce"
	       echo "  -t|--time"
	       echo "  -u|--url <OCSP URL>"
	       echo "  -e|--escape"
	       echo "  --signer <file>"
	       echo "  --signkey <file>"
	       echo "  --authcert <file>"
	       echo "  --authkey <file>"
	       shift
	       exit 1
	       ;;
    --) shift; break ;;
    *) echo "Internal error!"; exit 1;;
  esac
done

if [ -z $CERT ]; then
  echo "I want a certificate to check."
  exit
fi

if [ ! -z "$SIGNER" -a ! -z "$SIGNKEY" ]; then
  SIGN="-signer $SIGNER -signkey $SIGNKEY"
fi

if [ ! -z "$AUTHKEY" -a -z "$AUTHCERT" ]; then
  echo "--authkey without --authcert isn't a proper combination."
  exit
fi

if [ ! -z "$AUTHCERT" ]; then
  AUTH="$AUTH --certificate=\"$AUTHCERT\""
fi

if [ ! -z "$AUTHKEY" ]; then
  AUTH="$AUTH --private-key=\"$AUTHKEY\""
fi

if [ -z $URL ]; then
  URL=`openssl x509 -text -noout -in "$CERT" | grep "OCSP - URI:" | sed 's/^ *OCSP - URI://'`
  if [ -z $URL ]; then
    echo "No OCSP URL in the proposed certificate."
    exit
  else
    echo "The URL is \"$URL\"."
  fi
fi

SCHEME=`echo $URL | sed 's#\([a-zA-Z]*\)://\([a-zA-Z0-9._\-]*\)\(:[0-9]*\)*\(/.*\)*#\1#' | tr 'A-Z' 'a-z'`
HOST=`echo $URL | sed 's#\([a-zA-Z]*\)://\([a-zA-Z0-9.\-]*\)\(/.*\)*#\2#'`
if [ -z "$SCHEME" ]; then
  echo "No protocol in the URL."
  exit
fi
if [ "$SCHEME" != "http" -a "$SCHEME" != "https" ]; then
  echo "Unsupported protocol in the URL."
  exit
fi
if [ -z "$HOST" ]; then
  echo "No hostname in the URL."
  exit
fi

ISSUER=`openssl x509 -issuer_hash -noout -in "$CERT"`.0
if [ ! -f $ISSUER ]; then
  echo "Issuer certificate not found ($ISSUER)."
  exit
else
  echo "The issuer is found in \"$ISSUER\""
fi

TMPFILE=$$

if [ $GET -eq 0 ]; then
  openssl ocsp -issuer $ISSUER -cert "$CERT" -text -reqout $TMPFILE.req $NONCE $SIGN
  if [ $TIMEIT -eq 1 ]; then
    time -f "%e" -o $TMPFILE.time wget -O $TMPFILE.resp --post-file=$TMPFILE.req -S --header "Content-type: application/ocsp-request" --ca-directory=. $AUTH $URL
  else
    wget -O $TMPFILE.resp --post-file=$TMPFILE.req -S --header "Content-type: application/ocsp-request" --ca-directory=. $AUTH $URL
  fi
  openssl ocsp -issuer $ISSUER -cert "$CERT" -respin $TMPFILE.resp -text -CApath . $NONCE
else
  URL=`echo $URL | sed 's~/$~~'`
  openssl ocsp -issuer $ISSUER -cert "$CERT" -reqout $TMPFILE.req $NONCE $SIGN
  REQOCSP=`openssl base64 -e < $TMPFILE.req | awk '{ printf("%s", $0); }'`
  echo "The OCSP request is: \"$REQOCSP\"."
  if [ $ESCAPE -eq 1 ]; then REQOCSP=`echo $REQOCSP | sed 's/\//%2F/g;s/+/%2B/g;s/=/%3D/g'`; fi
  if [ $TIMEIT -eq 1 ]; then
    time -f "%e" -o $TMPFILE.time wget -O $TMPFILE.resp -S --ca-directory=. $AUTH "$URL"/"$REQOCSP"
  else
    wget -O $TMPFILE.resp -S --ca-directory=. $AUTH "$URL"/"$REQOCSP"
  fi
  openssl ocsp -issuer $ISSUER -cert "$CERT" -respin $TMPFILE.resp -text -CApath . $NONCE
fi

if [ $TIMEIT -eq 1 ]; then
  echo -n "Time taken: "
  cat $TMPFILE.time
fi

if [ $KEEP -eq 0 ]; then
  rm -f $TMPFILE.req $TMPFILE.resp $TMPFILE.time
else
  echo "\nRequest: $TMPFILE.req\nResponse: $TMPFILE.resp\nTIME: $TMPFILE.time"
fi
