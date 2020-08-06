#!/bin/bash
if [ -z "$BBOUT" ]; then
  echo "You need to specify \$BBOUT"
  exit 1
fi
if [ "$LIBS" = "#" ]; then
  #echo "run_bb.sh : $PIN_ROOT/pin -t ./obj-intel64/bbcounts2.so -o $BBOUT -libc 0 -- $@"
  $PIN_ROOT/pin -t ./obj-intel64/bbcounts2.so -o $BBOUT -libc 0 -- $@
else
  #echo "run_bb.sh : $PIN_ROOT/pin -t ./obj-intel64/bbcounts2.so -l $LIBS -o $BBOUT -libc 0 -- $@"
  $PIN_ROOT/pin -t ./obj-intel64/bbcounts2.so -l $LIBS -o $BBOUT -libc 0 -- $@
fi
#echo "run_bb.sh : done with $?"