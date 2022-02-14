open EBPF

let parse fn : string insn list =
  let ic = Stdio.In_channel.create fn in
  let lexbuf = Lexing.from_channel ~with_positions:true ic in
  Parser.program Lexer.tokenize lexbuf
