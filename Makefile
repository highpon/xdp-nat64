LLC ?= llc
CLANG ?= clang

KERN_C = xdp_nat64_kern.c
KERN_OBJ = ${KERN_C:.c=.o}

all: llvm-check $(KERN_OBJ)

.PHONY: clean $(CLANG) $(LLC)
clean:
	rm -f $(KERN_OBJ)
	rm -f *.ll

.PHONY: llvm-check $(CLANG) $(LLC)
llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(KERN_OBJ): %.o: %.c Makefile
	$(CLANG) -S \
			-target bpf \
			-Wall \
			-Wno-unused-value -Wno-pointer-sign \
			-Wno-compare-distinct-pointer-types \
			-O2 -emit-llvm -c -g $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
	llvm-strip -g $@
