# Generic interface to run sexytests with valgrind.
# You can either set $VALGRIND to 1 or specify the flags precisely.

if [ "$VALGRIND" != "" ];
then
	valgrind="valgrind --suppressions=valgrind.supp";
	[ "$VALGRIND" = "1" ] \
		|| valgrind="$valgrind $VALGRIND";
	valgrind="$valgrind --";
else
	valgrind="";
fi

# End of sexytest-valgrind.sh
