%start<string EBPF.insn list> program
%token EOF

%%

program:
  | EOF { [] }
