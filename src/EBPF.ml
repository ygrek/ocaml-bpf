(*
  https://www.kernel.org/doc/Documentation/networking/filter.txt
  https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
*)

type size =
| W (** word = 4B *)
| H (** half word = 2B *)
| B (** byte *)
| DW (* double word = 8B *)
[@@deriving enum]

type reg = R0 | R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 | R9 | R10 [@@deriving enum]

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
| MOV   (* eBPF only: mov reg to reg *)
| ARSH  (* eBPF only: sign extending shift right *)
| END   (* eBPF only: endianness conversion *)
[@@deriving enum]

type op_jmp =
| JA
| JEQ
| JGT
| JGE
| JSET
| JNE
| JSGT  (* eBPF only: signed '>' *)
| JSGE  (* eBPF only: signed '>=' *)
| CALL  (* eBPF only: function call *)
| EXIT  (* eBPF only: function return *)
[@@deriving enum]

type source = SRC_IMM | SRC_REG [@@deriving enum]

type mode =
| IMM (* used for 32-bit mov in classic BPF and 64-bit in eBPF *)
| ABS_todo
| IND_todo
| MEM
| LEN_reserved (* classic BPF only, reserved in eBPF *)
| MSH_reserved (* classic BPF only, reserved in eBPF *)
| XADD_todo (* eBPF only, exclusive add *)
[@@deriving enum]

type op =
| LD of size * mode | LDX of size * mode | ST of size * mode | STX of size * mode
| ALU of source * op_alu
| ALU64 of source * op_alu
| JMP of source * op_jmp

type int16 = int (* FIXME *)

(** represents any 64-bit value, i.e. also invalid instructions *)
type ('op, 'reg) insn = { op : 'op; dst : 'reg; src : 'reg; off : int16; imm : int32; }

let make ?(dst=R0) ?(src=R0) ?(off=0) ?(imm=0) op =
  assert (off >= 0);
  assert (off < 65536);
  { op; dst; src; off; imm = Int32.of_int imm; }

type cond = [ `EQ | `GT | `GE | `SET | `NE | `SGT | `SGE ]
let op_of_cond = function
| `EQ -> JEQ
| `GT -> JGT
| `GE -> JGE
| `SET -> JSET
| `NE -> JNE
| `SGT -> JSGT
| `SGE -> JSGE

let ldx size dst (src,off) = make (LDX (size, MEM)) ~dst ~src ~off
let movi dst imm = make (ALU64 (SRC_IMM, MOV)) ~dst ~imm
let mov ~dst ~src = make (ALU64 (SRC_REG, MOV)) ~dst ~src
let jump off = make (JMP (SRC_IMM, JA)) ~off
let jmpi off reg cond imm = make (JMP (SRC_IMM, op_of_cond cond)) ~dst:reg ~off ~imm
let jmp off a cond b = make (JMP (SRC_REG, op_of_cond cond)) ~dst:a ~src:b ~off
let ret = make (JMP (SRC_IMM, EXIT))
let call imm = make (JMP (SRC_IMM, CALL)) ~imm

module Bits = struct

let bpf_ld    = 0x00
let bpf_ldx   = 0x01
let bpf_st    = 0x02
let bpf_stx   = 0x03
let bpf_alu   = 0x04
let bpf_jmp   = 0x05
let bpf_ret_unused = 0x06 (* unused, for future if needed *)
let bpf_alu64 = 0x07

let mode x = mode_to_enum x lsl 5
let size x = size_to_enum x lsl 3
let op_alu x = op_alu_to_enum x lsl 4
let op_jmp x = op_jmp_to_enum x lsl 4
let source x = source_to_enum x lsl 3
let reg = reg_to_enum

end

let encode { op; dst; src; off; imm } =
  let open Bits in
  let op =
    let stld opc sz md = opc + size sz + mode md in
    match op with
    | LD (sz, md) -> stld bpf_ld sz md
    | LDX (sz, md) -> stld bpf_ldx sz md
    | ST (sz, md) -> stld bpf_st sz md
    | STX (sz, md) -> stld bpf_stx sz md
    | ALU (s, op) -> bpf_alu + op_alu op + source s
    | JMP (s, op) -> bpf_jmp + op_jmp op + source s
    | ALU64 (s, op) -> bpf_alu64 + op_alu op + source s
  in
  { op; dst = reg dst; src = reg src; off; imm }

(* TODO host endian? *)
external set_16 : Bytes.t -> int -> int -> unit = "%caml_string_set16"
external set_32 : Bytes.t -> int -> int32 -> unit = "%caml_string_set32"

let blit buf pos { op; dst; src; off; imm } =
  Bytes.set buf (pos+0) (Char.chr op);
  Bytes.set buf (pos+1) (Char.chr @@ src lsl 4 + dst);
  set_16 buf (pos+2) off;
  set_32 buf (pos+4) imm

let emit insns =
  let b = Bytes.create (8 * List.length insns) in
  List.iteri (fun i insn -> blit b (8*i) insn) insns;
  Bytes.unsafe_to_string b

let assemble l = emit @@ List.map encode l
