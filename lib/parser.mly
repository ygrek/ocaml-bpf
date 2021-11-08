%{
open EBPF_types
%}

%start<string EBPF_types.insn list> program
%token EOF LBRACK RBRACK PLUS MOVI LDXW JEQ RET LABEL
%token R0 R1 R2
%token<int> IMM
%token<string> NAME

%%

program:
  | is=instr+ EOF { is }

instr:
  | LDXW r1=reg LBRACK r2=reg PLUS off=IMM RBRACK
    { ldx W r1 (r2, off) }
  | MOVI r1=reg imm=IMM
    { movi r1 imm }
  | JEQ r1=reg r2=reg l=NAME
    { jmp l r1 `EQ r2 }
  | LABEL l=NAME
    { label l }
  | RET
    { ret }

reg:
  | R0 { R0 }
  | R1 { R1 }
  | R2 { R2 }
