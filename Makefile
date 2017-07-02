.SUFFIXES:
.PHONY: build doc clean

build:
	ocaml pkg/pkg.ml build

clean:
	ocaml pkg/pkg.ml clean

doc:
	topkg doc

%.bpf: %.o
	objcopy -F elf64-little --dump-section .text=$@ $<

%.o: %.c
	clang -c -O2 -target bpf $< -o $@
