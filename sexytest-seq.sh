#!/bin/bash -e
#
# sexytest-seq.sh -- sequential read/write test for sexywrap
#
# This program exercises sexywrap by executing sexytest-seq with
# varying I/O sizes.
#
# Synopsis:
#   sexytest-seq.sh <iscsi-url> {<local-file>|-N} [-S] [-r|-w]
#
# <local-file> should be the path to the disk addressed by <iscsi-url>.
# If -N is specified instead some verification will be skipped.
# 
# The test may take several minutes to complete.  Specify -S to omit
# verify slow test rounds.
#
# -r/-w skips the write/read test.  The default is to perform both.
#

url="$1";
disk="$2";
shift 2;

# Verify that the necessary programs are available.
for prg in sexywrap sexytest-seq;
do
	if [ ! -x "$prg" ];
	then
		echo "$prg is not available" >&2;
		exit 1;
	fi
done

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
then	# Don't include small I/O sizes which make this test
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
echo "Sequence is $seq."

# Do the tests.
[ $# -gt 0 -a "x$1" = "x-w" ] \
	|| ./sexywrap -x ./sexytest-seq -r "$url" "$disk" $seq;
[ $# -gt 0 -a "x$1" = "x-r" ] \
	|| ./sexywrap -x ./sexytest-seq -w "$url" "$disk" $seq;

# Done
echo "All tests completed successfully.";
exit 0;

# End of sexytest-seq.sh
