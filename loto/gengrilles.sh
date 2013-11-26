#! /bin/sh

if [ -z $1 ]; then
  NBGRILLES=10
else
  NBGRILLES=$1
fi

rm grille.*.txt

for i in `seq 1 $NBGRILLES`; do 
  (SEED=$RANDOM; echo "Grille n° $SEED"; ./loto $SEED) > grille.$i.txt
done
