(**
  Embedded {{:https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf/}eBPF} assembler
*)

(** {2 Types} *)

type size =
| W (** word = 32 bit *)
| H (** half-word = 16 bit *)
| B (** byte *)
| DW (** double word = 64 bit *)
[@@deriving enum]

type reg =
  | R0
  | R1
  | R2
  | R3
  | R4
  | R5
  | R6
  | R7
  | R8
  | R9
  | R10
[@@deriving enum]

type op_alu =
  | ADD
  | SUB
  | MUL
  | DIV
  | OR
  | AND
  | LSH
  | RSH
  | NEG
  | MOD
  | XOR
  | MOV
  | ARSH
  | END
[@@deriving enum]

type op_jmp =
  | JA
  | JEQ
  | JGT
  | JGE
  | JSET
  | JNE
  | JSGT
  | JSGE
  | CALL
  | EXIT
  | JLT
  | JLE
  | JSLT
  | JSLE
[@@deriving enum]

type source = SRC_IMM | SRC_REG [@@deriving enum]

type mode =
  | IMM
  | ABS_todo
  | IND_todo
  | MEM
  | LEN_reserved
  | MSH_reserved
  | XADD_todo
[@@deriving enum]
  
type op =
  | LD of size * mode | LDX of size * mode | ST of size * mode | STX of size * mode
  | ALU of source * op_alu
  | ALU64 of source * op_alu
  | JMP of source * op_jmp
  | JMP32 of source * op_jmp
type int16 = int
type ('op, 'reg) insn_t = {
    op : 'op;
    dst : 'reg;
    src : 'reg;
    off : int16;
    imm : int32;
  }
type prim = (op, reg) insn_t
type cond = [
  | `EQ (** equal *)
  | `GE (** greater or equal *)
  | `GT (** greater than *)
  | `NE (** not equal *)
  | `SET (** bitwise AND *)
  | `SGE (** signed greater or equal *)
  | `SGT (** signed greater than *)
  | `LE (** less or equal *)
  | `LT (** less than *)
  | `SLE (** signed less or equal *)
  | `SLT (** signed less than *)
  ]

(** Single eBPF instruction. ['label] is type of labels, can be any hashable type, e.g. [string], [int], open variant, etc *)
type 'label insn =
  | Prim of prim
  | Label of 'label
  | Jump of 'label * prim
  | Double of prim * prim

(** {2 Memory instructions} *)

val ldx : size -> reg -> reg * int16 -> 'a insn
val lddw : reg -> int64 -> 'a insn
val stx : size -> reg * int16 -> reg -> 'a insn
val st : size -> reg * int16 -> int -> 'a insn

(** {2 Branch instructions} *)

(** mark label position, each label should be unique *)
val label : 'label -> 'label insn

val ret : 'a insn
val call : int -> 'a insn

val jump : 'label -> 'label insn
val jmpi : 'label -> reg -> cond -> int -> 'label insn
val jmp : 'label -> reg -> cond -> reg -> 'label insn

(** same as [jump] but with 32-bit wide operands *)
val jump32 : 'label -> 'label insn
val jmp32i : 'label -> reg -> cond -> int -> 'label insn
val jmp32 : 'label -> reg -> cond -> reg -> 'label insn

(** {3 raw jump instructions with manually-computed offset}

  you probably want to use functions above which take labels
*)

val jump_ : int16 -> 'a insn
val jmpi_ : int16 -> reg -> cond -> int -> 'a insn
val jmp_ : int16 -> reg -> cond -> reg -> 'a insn

val jump32_ : int16 -> 'a insn
val jmp32i_ : int16 -> reg -> cond -> int -> 'a insn
val jmp32_ : int16 -> reg -> cond -> reg -> 'a insn

(** {2 ALU (arithmetic/logic) instructions} *)

module type ALU =
sig
  val add : reg -> reg -> 'a insn
  val addi : reg -> int -> 'a insn
  val sub : reg -> reg -> 'a insn
  val subi : reg -> int -> 'a insn
  val mul : reg -> reg -> 'a insn
  val muli : reg -> int -> 'a insn
  val div : reg -> reg -> 'a insn
  val divi : reg -> int -> 'a insn
  val or_ : reg -> reg -> 'a insn
  val ori : reg -> int -> 'a insn
  val and_ : reg -> reg -> 'a insn
  val andi : reg -> int -> 'a insn
  val lsh : reg -> reg -> 'a insn
  val lshi : reg -> int -> 'a insn
  val rsh : reg -> reg -> 'a insn
  val rshi : reg -> int -> 'a insn
  val neg : reg -> reg -> 'a insn
  val negi : reg -> int -> 'a insn
  val mod_ : reg -> reg -> 'a insn
  val modi : reg -> int -> 'a insn
  val xor : reg -> reg -> 'a insn
  val xori : reg -> int -> 'a insn
  val mov : reg -> reg -> 'a insn
  val movi : reg -> int -> 'a insn
  val arsh : reg -> reg -> 'a insn
  val arshi : reg -> int -> 'a insn
end

module I32 : ALU

(** 64-bit instructions, for 32-bit instructions use {!I32} *)
include ALU

(** {2 Byteswap instructions} *)

val le16 : reg -> 'a insn
val be16 : reg -> 'a insn
val le32 : reg -> 'a insn
val be32 : reg -> 'a insn
val le64 : reg -> 'a insn
val be64 : reg -> 'a insn

(** {2 Assembler} *)

type options = {
  disable_all_checks : bool; (** disable all checks, may generate invalid code *)
  jump_back : bool; (** allow jump backwards, may result in infinite loop *)
  jump_self : bool; (** allow jump to self, guaranteed infinite loop *)
}

val default : options

val assemble : ?options:options -> 'a insn list -> string
