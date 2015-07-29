#!/bin/sh -e

url="$1";
local1=`mktemp sexycat-test-XXXXXX`;
remote1="$2";
local2=`mktemp sexycat-test-XXXXXX`;
remote2="$3";

size1=`stat --printf '%s' "$remote1"`;
size2=`stat --printf '%s' "$remote2"`;
head -c "$size1" /dev/urandom > "$local1";

. ./sexytest-valgrind.sh;

echo "local -> remote1";
$valgrind ./sexywrap -S "$local1" -d "$url/0";
sleep 1;
cmp "$local1" "$remote1";

echo "remote1 -> remote2";
$valgrind ./sexywrap -s "$url/0" -d "$url/1";
sleep 1;
cmp -n $size2 "$remote1" "$remote2";

echo "remote2 -> local";
$valgrind ./sexywrap -s "$url/1" -F -D "$local2";
sleep 1;
cmp "$local2" "$remote2";

echo "local1 vs. local2";
cmp -n $size2 "$local1" "$local2";
rm "$local1" "$local2";
