{
open Lexing
open Parser

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
}

let name = ['A'-'Z' 'a'-'z' '_'] ['A'-'Z' 'a'-'z' '0'-'9' '_']*
let hex_number = '0' ['x' 'X'] ['0'-'9' 'a'-'f' 'A'-'F' '_']+
let int = ['0'-'9'] ['0'-'9' '_']*

let whitespace = [' ' '\t' '\012' '\r']

rule tokenize = parse
  | "//"        { comment lexbuf }
  | whitespace  { tokenize lexbuf }
  | '\n'        { newline lexbuf; tokenize lexbuf }
  | eof         { EOF }
  | _           { raise LexingError }

and comment = parse
  | '\n'   { newline lexbuf; tokenize lexbuf }
  | eof    { EOF }
  | _      { comment lexbuf }