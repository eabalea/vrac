#! /bin/bash

FACTOR=4
PARALLEL=1
ADDMONTAGEARGS=""

TEMP=`getopt -o f:o:p:a:h --long factor:,output:,parallel:,args:,help -n '$0 recompose.sh' -- "$@"`
eval set -- "$TEMP"
while true; do
  case "$1" in
    -f|--factor) FACTOR="$2"; shift 2;;
    -o|--output) OUTPUTFILE="$2"; shift 2;;
    -p|--parallel) PARALLEL="$2"; shift 2;;
    -a|--args) ADDMONTAGEARGS="$2"; shift 2;;
    -h|--help) echo "Options:"
	       echo " -f|--factor   <Reduction factor>"
	       echo " -o|--output   <output file>"
	       echo " -p|--parallel <max parallel jobs>"
	       echo " -a|--args     <montage additional arguments>"
	       echo
	       echo "Factor will reduce tiles by 2^factor in each direction."
	       echo "Parallel setting sets a limit to the number of concurrent tiles resizing jobs."
	       echo "Montage additional arguments allow you to modify default limits, or add monitor."
	       echo " example: \"-limit area 60GiB -limit memory 60GiB -limit map 512GiB -monitor\" if you have a LOT of memory."
               shift
               exit 1
               ;;
    --) shift; break;;
    *) echo "internal error"; exit 1;;
  esac
done

if [ -z "$OUTPUTFILE" ]; then
  OUTPUTFILE=full${FACTOR}.png
fi

function parallelconvert() {
  FILE=$1

  convert -geometry ${TILEDIM}x${TILEDIM} tiles/$FILE tmp/$FILE.mpc &
  while (( $(jobs | wc -l) >= $PARALLEL )); do
    sleep 0.1
    jobs > /dev/null
  done
}

cd tiles
MAXNORTH=`ls *[n]*[ew].png | sed 's/^\([0-9]*\)n.*$/\1/' | sort -n | tail -1`
MAXSOUTH=`ls *[s]*[ew].png | sed 's/^\([0-9]*\)s.*$/\1/' | sort -n | tail -1`
MAXWEST=`ls *[ns]*[w].png | sed 's/^[0-9]*[ns]\([0-9]*\)[w]\.png$/\1/' | sort -n | tail -1`
MAXEAST=`ls *[ns]*[e].png | sed 's/^[0-9]*[ns]\([0-9]*\)[e]\.png$/\1/' | sort -n | tail -1`
cd ..

TOTALWIDTH=`expr $MAXEAST + $MAXWEST`
TOTALHEIGHT=`expr $MAXNORTH + $MAXSOUTH`

TILEDIM=2048
(( TILEDIM >>= FACTOR ))

MONTAGEARGS="-tile ${TOTALWIDTH}x${TOTALHEIGHT} -geometry ${TILEDIM}x${TILEDIM}+0+0 -depth 8"

echo "Launching preconversions of tiles."

mkdir tmp

for north in `seq $MAXNORTH -1 1`; do
  for west in `seq $MAXWEST -1 1`; do
    FILE=${north}n${west}w.png
    if [ -f tiles/$FILE ]; then
      parallelconvert $FILE
      MONTAGE="$MONTAGE tmp/$FILE.mpc"
    else
      MONTAGE="$MONTAGE pattern:GRAY100"
    fi
  done
  for east in `seq 1 $MAXEAST`; do
    FILE=${north}n${east}e.png
    if [ -f tiles/$FILE ]; then
      parallelconvert $FILE
      MONTAGE="$MONTAGE tmp/$FILE.mpc"
    else
      MONTAGE="$MONTAGE pattern:GRAY100"
    fi
  done
done

for south in `seq 1 $MAXSOUTH`; do
  for west in `seq $MAXWEST -1 1`; do
    FILE=${south}s${west}w.png
    if [ -f tiles/$FILE ]; then
      parallelconvert $FILE
      MONTAGE="$MONTAGE tmp/$FILE.mpc"
    else
      MONTAGE="$MONTAGE pattern:GRAY0"
    fi
  done
  for east in `seq 1 $MAXEAST`; do
    FILE=${south}s${east}e.png
    if [ -f tiles/$FILE ]; then
      parallelconvert $FILE
      MONTAGE="$MONTAGE tmp/$FILE.mpc"
    else
      MONTAGE="$MONTAGE pattern:GRAY0"
    fi
  done
done

echo "Waiting for preconversions to finish."
wait
echo "Composing image."

montage $MONTAGEARGS $ADDMONTAGEARGS $MONTAGE $OUTPUTFILE
rm -rf tmp
