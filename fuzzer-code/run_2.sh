#!/bin/sh
echo $1
echo $2 $1
cwd=$PWD
cd ../libdft64/tools
#echo "run_2.sh : starting pin with libdft"
#echo "run_2.sh : $PIN_ROOT/pin -t libdft-dta.so -filename $2 -x $3 -- $1"
$PIN_ROOT/pin -t libdft-dta.so -filename $2 -x $3 -- $1
#echo "run_2.sh : pin stopped with $? exit code"
cd $cwd
cp ../libdft64/tools/cmp.out .
cp ../libdft64/tools/lea.out .

