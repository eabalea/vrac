#! /bin/bash

declare -A tiles
PARALLEL=1
NORTH=1
SOUTH=1
WEST=1
EAST=1
METHOD=b

TEMP=`getopt -o p:n:s:w:e:rbh --long parallel:,north:,south:,west:,east:,recursive,bruteforce,help -n '$0 downloadparts.sh' -- "$@"`
eval set -- "$TEMP"
while true; do
  case "$1" in
    -n|--north) NORTH="$2"; shift 2;;
    -s|--south) SOUTH="$2"; shift 2;;
    -w|--west) WEST="$2"; shift 2;;
    -e|--east) EAST="$2"; shift 2;;
    -p|--parallel) PARALLEL="$2"; shift 2;;
    -r|--recursive) METHOD=r; shift;;
    -b|--bruteforce) METHOD=b; shift;;
    -h|--help) echo "Options:"
	       echo "  -n|--north <distance>"
	       echo "  -s|--south <distance>"
	       echo "  -w|--west <distance>"
	       echo "  -e|--east <distance>"
	       echo "  -p|--parallel <paralleldownloads>"
	       echo "  -r|--recursive"
	       echo "  -b|--bruteforce"
	       echo
	       echo "Distances are used with bruteforce method."
	       echo "Recursive method starts at 1n1w, but will miss tiles not directly connected to the path formed from 1n1w (13 of them)."
	       echo "Parallel can only be used with bruteforce method."
               shift
               exit 1
               ;;
    --) shift; break;;
    *) echo "internal error"; exit 1;;
  esac
done

if [ $METHOD = r ]; then
  PARALLEL=1
fi

function download() {
  wget -c -q -O tiles/$1 http://imgs.xkcd.com/clickdrag/$1 &
  while (( $(jobs | wc -l) >= $PARALLEL )); do
    sleep 0.1
    jobs > /dev/null
  done
}

function leftof() {
  LOCATION=$1
  COORDX=`echo $LOCATION | sed 's/^\([0-9]*[ns]\)\([0-9]*[ew]\)/\2/'`
  COORDY=`echo $LOCATION | sed 's/^\([0-9]*[ns]\)\([0-9]*[ew]\)/\1/'`
  case $COORDX in
    1w) COORDX=1e
        ;;
    *w) POINT=`echo $COORDX | tr -d 'w'`
        (( POINT-- ))
	COORDX=${POINT}w
        ;;
    *e) POINT=`echo $COORDX | tr -d 'e'`
        (( POINT++ ))
	COORDX=${POINT}e
        ;;
  esac
  echo $COORDY$COORDX
}

function rightof() {
  LOCATION=$1
  COORDX=`echo $LOCATION | sed 's/^\([0-9]*[ns]\)\([0-9]*[ew]\)/\2/'`
  COORDY=`echo $LOCATION | sed 's/^\([0-9]*[ns]\)\([0-9]*[ew]\)/\1/'`
  case $COORDX in
    1e) COORDX=1w
        ;;
    *e) POINT=`echo $COORDX | tr -d 'e'`
        (( POINT-- ))
	COORDX=${POINT}e
        ;;
    *w) POINT=`echo $COORDX | tr -d 'w'`
        (( POINT++ ))
	COORDX=${POINT}w
        ;;
  esac
  echo $COORDY$COORDX
}

function topof() {
  LOCATION=$1
  COORDX=`echo $LOCATION | sed 's/^\([0-9]*[ns]\)\([0-9]*[ew]\)/\2/'`
  COORDY=`echo $LOCATION | sed 's/^\([0-9]*[ns]\)\([0-9]*[ew]\)/\1/'`
  case $COORDY in
    1s) COORDY=1n
        ;;
    *s) POINT=`echo $COORDY | tr -d 's'`
        (( POINT-- ))
	COORDY=${POINT}s
        ;;
    *n) POINT=`echo $COORDY | tr -d 'n'`
        (( POINT++ ))
	COORDY=${POINT}n
        ;;
  esac
  echo $COORDY$COORDX
}

function bottomof() {
  LOCATION=$1
  COORDX=`echo $LOCATION | sed 's/^\([0-9]*[ns]\)\([0-9]*[ew]\)/\2/'`
  COORDY=`echo $LOCATION | sed 's/^\([0-9]*[ns]\)\([0-9]*[ew]\)/\1/'`
  case $COORDY in
    1n) COORDY=1s
        ;;
    *n) POINT=`echo $COORDY | tr -d 'n'`
        (( POINT-- ))
	COORDY=${POINT}n
        ;;
    *s) POINT=`echo $COORDY | tr -d 's'`
        (( POINT++ ))
	COORDY=${POINT}s
        ;;
  esac
  echo $COORDY$COORDX
}

function findneighbors() {
  LOCATION=$1
  echo -n "$LOCATION "
  tiles[$LOCATION]=1
  download $LOCATION.png
  if [ -f tiles/$LOCATION.png ]; then
    LEFTOF=`leftof $LOCATION`
    RIGHTOF=`rightof $LOCATION`
    TOPOF=`topof $LOCATION`
    BOTTOMOF=`bottomof $LOCATION`
    for neighbor in $LEFTOF $RIGHTOF $TOPOF $BOTTOMOF; do
      if [ -z ${tiles[$neighbor]} ]; then
        findneighbors $neighbor
      fi
    done
  fi
}

if [ $METHOD = b ]; then
  for i in `seq 1 $NUM`; do
    for north in `seq 1 $NORTH`; do
      for west in `seq 1 $WEST`; do
        download ${north}n${west}w.png
      done
      for east in `seq 1 $EAST`; do
        download ${north}n${east}e.png
      done
    done

    for south in `seq 1 $SOUTH`; do
      for west in `seq 1 $WEST`; do
        download ${south}s${west}w.png
      done
      for east in `seq 1 $EAST`; do
        download ${south}s${east}e.png
      done
    done
  done
else
  findneighbors 1n1w
  echo
fi

wait

