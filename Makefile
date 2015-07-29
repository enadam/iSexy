TEST_URL := iscsi://127.0.0.1/iqn.2014-07.net.nsn-net.timmy:try
ISEXY_CFLAGS := -Wall -Wno-unused-function -O2

ifneq ($(wildcard libiscsi),)
LIBISCSI := -Ilibiscsi -Llibiscsi -l:libiscsi.a
else
LIBISCSI := -I/usr/include/iscsi -liscsi
endif

sexycat: sexycat.c
	cc $(ISEXY_CFLAGS) $< $(LIBISCSI) -lrt -o $@;
sexywrap: sexywrap.c sexycat.c
	cc -shared -pie -pthread $(ISEXY_CFLAGS) -fPIE \
		-DSEXYCAT $< $(LIBISCSI) -lrt -ldl -o $@;
libsexywrap.so: sexywrap.c sexycat.c
	cc -shared -pthread $(ISEXY_CFLAGS) -fPIC \
		-DSEXYWRAP $< $(LIBISCSI) -lrt -ldl -o $@;
	chmod -x $@;
sexytest-seq: sexytest-seq.c
	cc $(ISEXY_CFLAGS) $< -o $@;

all: sexycat sexywrap libsexywrap.so
clean:
	rm -f sexycat sexywrap libsexywrap.so sexytest-seq;

seqtest: sexytest-seq.sh sexywrap disks/disk1 sexytest-seq
	./sexytest-seq.sh "$(TEST_URL)/0" disks/disk1;
qseqtest: sexytest-seq.sh sexywrap disks/disk1 sexytest-seq
	./sexytest-seq.sh "$(TEST_URL)/0" disks/disk1 -S;
cmptest: sexytest-cmp.sh sexywrap disks/disk1 disks/disk2
	./sexytest-cmp.sh "$(TEST_URL)" disks/disk1 disks/disk2;

.PHONY: all clean seqtest qseqtest cmptest
