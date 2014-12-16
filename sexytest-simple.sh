#!/bin/sh
#
# sexytest-simple -- sequential read/write test for sexywrap
#
# This program exercises sexywrap by executing sexytest-simple with varying
# chunk sizes.
#
# Synopsis:
#   sexytest-simple.sh <iscsi-url> <local-file> [-r|-w]
#
# <local-file> should be the path to the disk addressed by <iscsi-url>
# The test may take several minutes to complete.
#
# -r/-w skips the write/read test.  The default is to perform both.
#

url="$1";
disk="$2";
shift 2;

if [ ! -x ./sexywrap ];
then
	echo "sexywrap is not available" >&2;
	exit 1;
elif [ ! -x ./sexytest-simple ];
then
	echo "sexytest-simple is not available" >&2;
	exit 1;
fi

blocksize=`./sexywrap -N -s "$url" \
	| sed -ne 's/source target: nblocks=\([0-9]\+\), blocksize=\([0-9]\+\).*/\2/p'`;
seq="512 1 2 3 5 12 123 511 513 1000 1023 1024 1025 1234";
[ $blocksize -lt 2048 ] \
	|| seq="$seq 2000 2047 2048 2049 2345";
[ $blocksize -lt 4096 ] \
	|| seq="$seq 4000 4095 4096 4097 4567";
seq="$seq 12345 123456";
echo "Sequence is $seq" >&2;

if [ $# -eq 0 -o "x$1" = "x-r" ];
then
	output=`mktemp sexytest-read-XXXXXX`;
	for n in $seq;
	do
		echo sexytest-simple -r $n "$url" '>' "$output" >&2;
		./sexytest-simple -r $n "$url" > "$output" \
			|| exit 1;
		echo cmp "$disk" "$output" >&2;
		cmp "$disk" "$output" \
			|| exit 1;
	done
	rm "$output";
fi

if [ $# -eq 0 -o "x$1" = "x-w" ];
then
	size=`stat --printf '%s' "$disk"`;
	input1=`mktemp sexytest-write-XXXXXX`;
	head -c $size /dev/urandom > "$input1";
	input2=`mktemp sexytest-write-XXXXXX`;
	head -c $size /dev/urandom > "$input2";
	input="$input1";
	for n in $seq;
	do
		echo sexytest-simple -w $n "$url" '<' "$input" >&2;
		./sexytest-simple -w $n "$url" < "$input" \
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

echo "All tests completed successfully.";
exit 0;

# End of sexytest-simple.sh
