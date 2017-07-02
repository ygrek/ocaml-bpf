#!/usr/bin/env ocaml
#use "topfind";;
#require "topkg";;
open Topkg

let () =
  Pkg.describe "bpf" ~licenses:[] begin fun c ->
    Ok [
      Pkg.mllib "src/bpf.mllib";
      Pkg.test "src/test";
    ]
  end
