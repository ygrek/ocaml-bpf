.SUFFIXES:
.PHONY: build

build:
	ocamlbuild -use-ocamlfind -I src eBPF.cma eBPF.cmxa test.byte test.native

clean:
	ocamlbuild -clean

%.bpf: %.o
	objcopy -F elf64-little --dump-section .text=$@ $<

%.o: %.c
	clang -c -O2 -target bpf $< -o $@
