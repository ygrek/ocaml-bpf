.SUFFIXES:
.PHONY: build

build:
	cd src; ocamlfind ocamlc -w +a-4-32 -bin-annot -g -package ppx_deriving.enum eBPF.mli eBPF.ml test.ml -o test.byte

%.bpf: %.o
	objcopy -F elf64-little --dump-section .text=$@ $<

%.o: %.c
	clang -c -O2 -target bpf $< -o $@