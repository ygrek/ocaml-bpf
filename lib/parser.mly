%{
    open EBPF_types
%}

%start<string EBPF_types.insn list> program
%token ADD SUB MUL DIV OR AND LSH RSH NEG MOD XOR MOV ARSH
%token ADD32 SUB32 MUL32 DIV32 OR32 AND32 LSH32 RSH32 NEG32 MOD32 XOR32 MOV32 ARSH32
%token LDDW LDXW LDXH LDXB LDXDW STW STH STB STDW STXW STXH STXB STXDW
%token JA JEQ JGT JGE JLT JLE JSET JNE JSGT JSGE JSLT JSLE CALL EX LABEL
%token LE16 BE16 LE32 BE32 LE64 BE64
%token EOF LBRACK RBRACK PLUS
%token R0 R1 R2 R3 R4 R5 R6 R7 R8 R9 R10
%token<int> IMM
%token<string> NAME

%%

program:
  | is=instr+ EOF { is }

instr:
  | i=alu_instr      { i }
  | i=bit32_instr    { i }
  | i=byteswap_instr { i }
  | i=mem_instr      { i }
  | i=br_instr       { i }

alu_instr:
  | ADD r1=reg imm=IMM
    { addi r1 imm }
  | ADD r1=reg r2=reg
    { add r1 r2 }
  | SUB r1=reg imm=IMM
    { subi r1 imm }
  | SUB r1=reg r2=reg
    { sub r1 r2 }
  | MUL r1=reg imm=IMM
    { muli r1 imm }
  | MUL r1=reg r2=reg
    { mul r1 r2 }
  | DIV r1=reg imm=IMM
    { divi r1 imm }
  | DIV r1=reg r2=reg
    { div r1 r2 }
  | OR r1=reg imm=IMM
    { ori r1 imm }
  | OR r1=reg r2=reg
    { or_ r1 r2 }
  | AND r1=reg imm=IMM
    { andi r1 imm }
  | AND r1=reg r2=reg
    { and_ r1 r2 }
  | LSH r1=reg imm=IMM
    { lshi r1 imm }
  | LSH r1=reg r2=reg
    { lsh r1 r2 }
  | RSH r1=reg imm=IMM
    { rshi r1 imm }
  | RSH r1=reg r2=reg
    { rsh r1 r2 }
  | NEG r1=reg
    { neg r1 r1 }
  | MOD r1=reg imm=IMM
    { modi r1 imm }
  | MOD r1=reg r2=reg
    { mod_ r1 r2 }
  | XOR r1=reg imm=IMM
    { xori r1 imm }
  | XOR r1=reg r2=reg
    { xor r1 r2 }
  | MOV r1=reg imm=IMM
    { movi r1 imm }
  | MOV r1=reg r2=reg
    { mov r1 r2 }
  | ARSH r1=reg imm=IMM
    { arshi r1 imm }
  | ARSH r1=reg r2=reg
    { arsh r1 r2 }

bit32_instr:
  | ADD32 r1=reg imm=IMM
    { I32.addi r1 imm }
  | ADD32 r1=reg r2=reg
    { I32.add r1 r2 }
  | SUB32 r1=reg imm=IMM
    { I32.subi r1 imm }
  | SUB32 r1=reg r2=reg
    { I32.sub r1 r2 }
  | MUL32 r1=reg imm=IMM
    { I32.muli r1 imm }
  | MUL32 r1=reg r2=reg
    { I32.mul r1 r2 }
  | DIV32 r1=reg imm=IMM
    { I32.divi r1 imm }
  | DIV32 r1=reg r2=reg
    { I32.div r1 r2 }
  | OR32 r1=reg imm=IMM
    { I32.ori r1 imm }
  | OR32 r1=reg r2=reg
    { I32.or_ r1 r2 }
  | AND32 r1=reg imm=IMM
    { I32.andi r1 imm }
  | AND32 r1=reg r2=reg
    { I32.and_ r1 r2 }
  | LSH32 r1=reg imm=IMM
    { I32.lshi r1 imm }
  | LSH32 r1=reg r2=reg
    { I32.lsh r1 r2 }
  | RSH32 r1=reg imm=IMM
    { I32.rshi r1 imm }
  | RSH32 r1=reg r2=reg
    { I32.rsh r1 r2 }
  | NEG32 r1=reg
    { I32.neg r1 r1 }
  | MOD32 r1=reg imm=IMM
    { I32.modi r1 imm }
  | MOD32 r1=reg r2=reg
    { I32.mod_ r1 r2 }
  | XOR32 r1=reg imm=IMM
    { I32.xori r1 imm }
  | XOR32 r1=reg r2=reg
    { I32.xor r1 r2 }
  | MOV32 r1=reg imm=IMM
    { I32.movi r1 imm }
  | MOV32 r1=reg r2=reg
    { I32.mov r1 r2 }
  | ARSH32 r1=reg imm=IMM
    { I32.arshi r1 imm }
  | ARSH32 r1=reg r2=reg
    { I32.arsh r1 r2 }

byteswap_instr:
  | LE16 r1=reg { le16 r1 }
  | BE16 r1=reg { be16 r1 }
  | LE32 r1=reg { le32 r1 }
  | BE32 r1=reg { be32 r1 }
  | LE64 r1=reg { le64 r1 }
  | BE64 r1=reg { be64 r1 }

mem_instr:
  | LDDW r1=reg imm=IMM
    { lddw r1 (Int64.of_int imm) }
  | LDXW r1=reg LBRACK r2=reg PLUS off=IMM RBRACK
    { ldx W r1 (r2, off) }
  | LDXH r1=reg LBRACK r2=reg PLUS off=IMM RBRACK
    { ldx H r1 (r2, off) }
  | LDXB r1=reg LBRACK r2=reg PLUS off=IMM RBRACK
    { ldx B r1 (r2, off) }
  | LDXDW r1=reg LBRACK r2=reg PLUS off=IMM RBRACK
    { ldx DW r1 (r2, off) }
  | STW LBRACK r1=reg PLUS off=IMM RBRACK imm=IMM
    { st W (r1, off) imm }
  | STH LBRACK r1=reg PLUS off=IMM RBRACK imm=IMM
    { st H (r1, off) imm }
  | STB LBRACK r1=reg PLUS off=IMM RBRACK imm=IMM
    { st B (r1, off) imm }
  | STDW LBRACK r1=reg PLUS off=IMM RBRACK imm=IMM
    { st DW (r1, off) imm }
  | STXW LBRACK r1=reg PLUS off=IMM RBRACK r2=reg
    { stx W (r1, off) r2 }
  | STXH LBRACK r1=reg PLUS off=IMM RBRACK r2=reg
    { stx H (r1, off) r2 }
  | STXB LBRACK r1=reg PLUS off=IMM RBRACK r2=reg
    { stx B (r1, off) r2 }
  | STXDW LBRACK r1=reg PLUS off=IMM RBRACK r2=reg
    { stx DW (r1, off) r2 }

br_instr:
  | JA PLUS off=IMM
    { jump_ off }
  | JA l=NAME
    { jump l }
  | JEQ r1=reg r2=reg PLUS off=IMM
    { jmp_ off r1 `EQ r2 }
  | JEQ r1=reg imm=IMM PLUS off=IMM
    { jmpi_ off r1 `EQ imm }
  | JEQ r1=reg r2=reg l=NAME
    { jmp l r1 `EQ r2 }
  | JEQ r1=reg imm=IMM l=NAME
    { jmpi l r1 `EQ imm }
  | JGT r1=reg r2=reg PLUS off=IMM
    { jmp_ off r1 `GT r2 }
  | JGT r1=reg imm=IMM PLUS off=IMM
    { jmpi_ off r1 `GT imm }
  | JGT r1=reg r2=reg l=NAME
    { jmp l r1 `GT r2 }
  | JGT r1=reg imm=IMM l=NAME
    { jmpi l r1 `GT imm }
  | JGE r1=reg r2=reg PLUS off=IMM
    { jmp_ off r1 `GE r2 }
  | JGE r1=reg imm=IMM PLUS off=IMM
    { jmpi_ off r1 `GE imm }
  | JGE r1=reg r2=reg l=NAME
    { jmp l r1 `GE r2 }
  | JGE r1=reg imm=IMM l=NAME
    { jmpi l r1 `GE imm }
  | JLT r1=reg r2=reg PLUS off=IMM
    { jmp_ off r1 `LT r2 }
  | JLT r1=reg imm=IMM PLUS off=IMM
    { jmpi_ off r1 `LT imm }
  | JLT r1=reg r2=reg l=NAME
    { jmp l r1 `LT r2 }
  | JLT r1=reg imm=IMM l=NAME
    { jmpi l r1 `LT imm }
  | JLE r1=reg r2=reg PLUS off=IMM
    { jmp_ off r1 `LE r2 }
  | JLE r1=reg imm=IMM PLUS off=IMM
    { jmpi_ off r1 `LE imm }
  | JLE r1=reg r2=reg l=NAME
    { jmp l r1 `LE r2 }
  | JLE r1=reg imm=IMM l=NAME
    { jmpi l r1 `LE imm }
  | JSET r1=reg r2=reg PLUS off=IMM
    { jmp_ off r1 `SET r2 }
  | JSET r1=reg imm=IMM PLUS off=IMM
    { jmpi_ off r1 `SET imm }
  | JSET r1=reg r2=reg l=NAME
    { jmp l r1 `SET r2 }
  | JSET r1=reg imm=IMM l=NAME
    { jmpi l r1 `SET imm }
  | JNE r1=reg r2=reg PLUS off=IMM
    { jmp_ off r1 `NE r2 }
  | JNE r1=reg imm=IMM PLUS off=IMM
    { jmpi_ off r1 `NE imm }
  | JNE r1=reg r2=reg l=NAME
    { jmp l r1 `NE r2 }
  | JNE r1=reg imm=IMM l=NAME
    { jmpi l r1 `NE imm }
  | JSGT r1=reg r2=reg PLUS off=IMM
    { jmp_ off r1 `SGT r2 }
  | JSGT r1=reg imm=IMM PLUS off=IMM
    { jmpi_ off r1 `SGT imm }
  | JSGT r1=reg r2=reg l=NAME
    { jmp l r1 `SGT r2 }
  | JSGT r1=reg imm=IMM l=NAME
    { jmpi l r1 `SGT imm }
  | JSGE r1=reg r2=reg PLUS off=IMM
    { jmp_ off r1 `SGE r2 }
  | JSGE r1=reg imm=IMM PLUS off=IMM
    { jmpi_ off r1 `SGE imm }
  | JSGE r1=reg r2=reg l=NAME
    { jmp l r1 `SGE r2 }
  | JSGE r1=reg imm=IMM l=NAME
    { jmpi l r1 `SGE imm }
  | JSLT r1=reg r2=reg PLUS off=IMM
    { jmp_ off r1 `SLT r2 }
  | JSLT r1=reg imm=IMM PLUS off=IMM
    { jmpi_ off r1 `SLT imm }
  | JSLT r1=reg r2=reg l=NAME
    { jmp l r1 `SLT r2 }
  | JSLT r1=reg imm=IMM l=NAME
    { jmpi l r1 `SLT imm }
  | JSLE r1=reg r2=reg PLUS off=IMM
    { jmp_ off r1 `SLE r2 }
  | JSLE r1=reg imm=IMM PLUS off=IMM
    { jmpi_ off r1 `SLE imm }
  | JSLE r1=reg r2=reg l=NAME
    { jmp l r1 `SLE r2 }
  | JSLE r1=reg imm=IMM l=NAME
    { jmpi l r1 `SLE imm }
  | EX
    { ret }
  | CALL imm=IMM
    { call imm }
  | LABEL l=NAME
    { label l }

reg:
  | R0  { R0 }
  | R1  { R1 }
  | R2  { R2 }
  | R3  { R3 }
  | R4  { R4 }
  | R5  { R5 }
  | R6  { R6 }
  | R7  { R7 }
  | R8  { R8 }
  | R9  { R9 }
  | R10 { R10 }
