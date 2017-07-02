.SUFFIXES:
.PHONY: build

build:
	cd src; ocamlfind ocamlc -package ppx_deriving.enum EBPF.ml test.ml -o test.byte

%.bpf: %.o
	objcopy -F elf64-little --dump-section .text=$@ $<

%.o: %.c
	clang -c -O2 -target bpf $< -o $@
