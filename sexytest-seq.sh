#!/bin/bash
#
# sexytest-seq.sh -- sequential read/write test for sexywrap
#
# This program exercises sexywrap by executing sexytest-seq with
# varying I/O size.
#
# Synopsis:
#   sexytest-seq.sh <iscsi-url> <local-file> [-r|-w]
#
# <local-file> should be the path to the disk addressed by <iscsi-url>
# The test may take several minutes to complete.
#
# -r/-w skips the write/read test.  The default is to perform both.
#

url="$1";
disk="$2";
shift 2;

# Verify that sexywrap and sexytest-seq are available.
if [ ! -x ./sexywrap ];
then
	echo "sexywrap is not available" >&2;
	exit 1;
elif [ ! -x ./sexytest-seq ];
then
	echo "sexytest-seq is not available" >&2;
	exit 1;
fi

# Get $blocksize, $optimum and $nblocks.
for str in `./sexywrap -N -s "$url"`;
do
	str="${str%,}";
	case "$str" in
	blocksize=*)
		blocksize=${str#blocksize=};;
	optimum=*)
		optimum=${str#optimum=};;
	nblocks=*)
		nblocks=${str#nblocks=};;
	esac
done

# Construct the test sequence (I/O sizes).
seq="512";
if [ $# -gt 0 -a "x$1" = "x-S" ];
then	# Don't include small buffer sizes which make this test
	# painstakingly slow.
	shift;
else
	seq="$seq 1 2 3 5 12 15 16 17";
fi
seq="$seq 123 511 513 1000 1023 1024 1025 1234";
[ $blocksize -lt 2048 ] \
	|| seq="$seq 2000 2047 2048 2049 2345";
[ $blocksize -lt 4096 ] \
	|| seq="$seq 4000 4095 4096 4097 4567";
[ $blocksize -eq 512 -o $blocksize -eq 2048 -o $blocksize -eq 4096 ] \
	|| seq="$seq $[ blocksize-1 ] $blocksize $[ blocksize+1 ]";
seq="$seq 12345 123456";
if [ $optimum -gt 1 ];
then
	optimum=$[ blocksize * optimum ];
	seq="$seq $[ optimum - blocksize - 1 ]";
	seq="$seq $[ optimum - blocksize ]";
	seq="$seq $[ optimum - 1]";
	seq="$seq $optimum";
	seq="$seq $[ optimum + 1 ]";
	seq="$seq $[ optimum + blocksize ]";
	seq="$seq $[ optimum + blocksize + 1 ]";
fi
seq="$seq $[ blocksize * nblocks ]";
echo "Sequence is $seq" >&2;

# read() the disk $n bytes at a time and verify that what sexytest-seq
# read matches $disk.
if [ $# -eq 0 -o "x$1" = "x-r" ];
then
	output=`mktemp sexytest-read-XXXXXX`;
	trap "rm $output; exit 1" INT;
	for n in $seq;
	do
		echo sexytest-seq -r $n "$url" '>' "$output" >&2;
		./sexywrap -x ./sexytest-seq -r $n "$url" > "$output" \
			|| exit 1;
		echo cmp "$disk" "$output" >&2;
		cmp "$disk" "$output" \
			|| exit 1;
	done
	rm "$output";
fi

# Create two random files and alternating them every cycle have them written
# to $url by sexytest-seq in $n-byte buffers.  When finished, compare $disk
# with the current $input.
if [ $# -eq 0 -o "x$1" = "x-w" ];
then
	size=`stat --printf '%s' "$disk"`;
	input1=`mktemp sexytest-write-XXXXXX`;
	head -c $size /dev/urandom > "$input1";
	input2=`mktemp sexytest-write-XXXXXX`;
	head -c $size /dev/urandom > "$input2";
	input="$input1";
	trap "rm $input1 $input2; exit 1" INT;
	for n in $seq;
	do
		echo sexytest-seq -w $n "$url" '<' "$input" >&2;
		./sexywrap -x ./sexytest-seq -w $n "$url" < "$input" \
			|| exit 1;
		sleep 3;
		echo cmp "$disk" "$input" >&2;
		cmp "$disk" "$input" \
			|| exit 1;

		if [ "$input" = "$input1" ];
		then
			input="$input2";
		else
			input="$input1";
		fi
	done
	rm "$input1" "$input2";
fi

# Done
echo "All tests completed successfully.";
exit 0;

# End of sexytest-seq.sh
