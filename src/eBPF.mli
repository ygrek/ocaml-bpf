(**
  Embedded eBPF assembler

  https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf/
*)

(** {2 Types} *)

type size = W | H | B | DW
type reg = R0 | R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 | R9 | R10
type int16 = int
type cond = [ `EQ | `GE | `GT | `NE | `SET | `SGE | `SGT ]

(** Single eBPF instruction. ['label] is type of labels, can be any hashable type, e.g. [string], [int], open variant, etc *)
type +'label insn

(** {2 Memory instructions} *)

val ldx : size -> reg -> reg * int16 -> 'a insn
val lddw : reg -> int64 -> 'a insn
val stx : size -> reg * int16 -> reg -> 'a insn
val st : size -> reg * int16 -> int -> 'a insn

(** {2 Branch instructions} *)

(** mark label position, each label should unique *)
val label : 'label -> 'label insn

val ret : 'a insn
val call : int -> 'a insn
val jump : 'label -> 'label insn
val jmpi : 'label -> reg -> cond -> int -> 'label insn
val jmp : 'label -> reg -> cond -> reg -> 'label insn

(** raw jump instructions with manually-computed offset, you probably want to use version with labels *)
val jump_ : int16 -> 'a insn
val jmpi_ : int16 -> reg -> cond -> int -> 'a insn
val jmp_ : int16 -> reg -> cond -> reg -> 'a insn

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

val assemble : 'a insn list -> string
