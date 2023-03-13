#!/bin/sh

filesdir=$1
searchstr=$2

if [ $# -ne 2 ]
then
	echo "INvalid number of arguments. Total number of arguments shoudl be 2"
	exit 1
fi

if [ -d "$filesdir" ]
then 
	echo "success"
	files=` find ${filesdir} -type f | wc -l`
	lines=`grep -r ${searchstr} ${filesdir} | wc -l`
	echo "The number of files are ${files} and the number of matching lines are ${lines}"
	exit 0
else
	echo "error: file directory does not exist"
	exit 1
fi

