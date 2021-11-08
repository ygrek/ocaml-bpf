build:
	dune build

all: build

default: build

clean:
	dune clean

install: build
	dune install
