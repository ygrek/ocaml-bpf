{
open Lexing
open Parser
open Core

exception LexingError

let current_line  = ref 1
let current_fname = ref ""
let line_start    = ref 1

let reset () =
  current_line := 1;
  current_fname := "";
  line_start := 1

let line_number () =
  !current_line
let filename () =
  !current_fname
let start_of_line () =
  !line_start

let set_line n =
  current_line  :=  n

let set_start_of_line c =
  line_start := c

let set_filename s =
  current_fname := s

let newline lexbuf =
  current_line := line_number() + 1 ;
  set_start_of_line (lexeme_end lexbuf)

let dec_of_hexchar c =
  match c with
  | '0' -> 0
  | '1' -> 1
  | '2' -> 2
  | '3' -> 3
  | '4' -> 4
  | '5' -> 5
  | '6' -> 6
  | '7' -> 7
  | '8' -> 8
  | '9' -> 9
  | 'a' -> 10
  | 'b' -> 11
  | 'c' -> 12
  | 'd' -> 13
  | 'e' -> 14
  | 'f' -> 15
  | _ -> raise LexingError

let hex_helper hex : int =
  let rec h acc hex =
    if String.length hex = 0
    then acc
    else
      h
        ((acc lsl 4) + dec_of_hexchar (String.get hex 0))
	(Str.string_after hex 1) in
  h 0
    (Str.string_after hex 2
    |> String.lowercase
    |> String.filter ~f:(fun c -> not (Char.equal '_' c)))
}

let name = '"'['A'-'Z' 'a'-'z' '_'] ['A'-'Z' 'a'-'z' '0'-'9' '_']*'"'
let hex_number = '0' ['x' 'X'] ['0'-'9' 'a'-'f' 'A'-'F' '_']+
let int = ['0'-'9'] ['0'-'9' '_']*

let whitespace = [' ' '\t' '\012' '\r']

rule tokenize = parse
  | "//"        { comment lexbuf }
  | whitespace  { tokenize lexbuf }
  | '\n'        { newline lexbuf; tokenize lexbuf }
  | eof         { EOF }
  
  | "add"       { ADD }
  | "sub"       { SUB }
  | "mul"       { MUL }
  | "div"       { DIV }
  | "or"        { OR }
  | "and"       { AND }
  | "lsh"       { LSH }
  | "rsh"       { RSH }
  | "neg"       { NEG }
  | "mod"       { MOD }
  | "xor"       { XOR }
  | "mov"       { MOV }
  | "arsh"      { ARSH }
  
  | "add32"     { ADD32 }
  | "sub32"     { SUB32 }
  | "mul32"     { MUL32 }
  | "div32"     { DIV32 }
  | "or32"      { OR32 }
  | "and32"     { AND32 }
  | "lsh32"     { LSH32 }
  | "rsh32"     { RSH32 }
  | "neg32"     { NEG32 }
  | "mod32"     { MOD32 }
  | "xor32"     { XOR32 }
  | "mov32"     { MOV32 }
  | "arsh32"    { ARSH32 }

  | "le16"      { LE16 }
  | "be16"      { BE16 }
  | "le32"      { LE32 }
  | "be32"      { BE32 }
  | "le64"      { LE64 }
  | "be64"      { BE64 }

  | "lddw"      { LDDW }
  | "ldxw"      { LDXW }
  | "ldxh"      { LDXH }
  | "ldxb"      { LDXB }
  | "ldxdw"     { LDXDW }
  | "stw"       { STW }
  | "sth"       { STH }
  | "stb"       { STB }
  | "stdw"      { STDW }
  | "stxw"      { STXW }
  | "stxh"      { STXH }
  | "stxb"      { STXB }
  | "stxdw"     { STXDW }

  | "ja"        { JA }
  | "jeq"       { JEQ }
  | "jgt"       { JGT }
  | "jge"       { JGE }
  | "jlt"       { JLT }
  | "jle"       { JLE }
  | "jset"      { JSET }
  | "jne"       { JNE }
  | "jsgt"      { JSGT }
  | "jsge"      { JSGE }
  | "jslt"      { JSLT }
  | "jsle"      { JSLE }
  | "call"      { CALL }
  | "exit"      { EX }
  | "label"     { LABEL }
  
  | "$r0"       { R0 }
  | "$r1"       { R1 }
  | "$r2"       { R2 }
  | "$r3"       { R3 }
  | "$r4"       { R4 }
  | "$r5"       { R5 }
  | "$r6"       { R6 }
  | "$r7"       { R7 }
  | "$r8"       { R8 }
  | "$r9"       { R9 }
  | "$r10"      { R10 }

  | "["         { LBRACK }
  | "]"         { RBRACK }
  | "+"         { PLUS }
  | int         { IMM (Lexing.lexeme lexbuf |> Int.of_string) }
  | hex_number  { IMM (Lexing.lexeme lexbuf |> hex_helper) }
  | name        { NAME (Lexing.lexeme lexbuf |> String.filter ~f:(fun c -> not (Char.equal '"' c))) }
  | _           { raise LexingError }

and comment = parse
  | '\n'   { newline lexbuf; tokenize lexbuf }
  | eof    { EOF }
  | _      { comment lexbuf }