(*
  https://www.kernel.org/doc/Documentation/networking/filter.txt
  https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
*)

let fail fmt = Printf.ksprintf failwith fmt

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
type ('op, 'reg) insn_t = { op : 'op; dst : 'reg; src : 'reg; off : int16; imm : int32; }
type insn = (op, reg) insn_t

let make ?(dst=R0) ?(src=R0) ?(off=0) ?(imm=0) op =
  (* simple sanity checks *)
  assert (off >= 0);
  assert (off < 65_536);
  assert (imm >= 0);
  assert (imm < 4_294_967_296);
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

type 'label cfg =
| Prim of insn (* valid instruction *)
| Label of 'label (* marker, no instruction *)
| Jump of 'label * insn (* to patch offset field *)
| Double of insn * insn (* eBPF has one 16-byte instruction: BPF_LD | BPF_DW | BPF_IMM *)

let label x = Label x
let prim ?dst ?src ?off ?imm op = Prim (make ?dst ?src ?off ?imm op)
let unprim = function Prim x -> x | _ -> assert false

let ldx size dst (src,off) = prim (LDX (size, MEM)) ~dst ~src ~off
let lddw dst imm = Double (
  make (LD (DW, IMM)) ~dst ~imm:(Int64.to_int @@ Int64.logand imm 0xFFFFFFFFL),
  make (LD (W, IMM)) ~imm:(Int64.to_int @@ Int64.shift_right_logical imm 32)) (* pseudo-insn *)
let stx size (dst,off) src = prim (STX (size, MEM)) ~dst ~src ~off
let st size (dst,off) imm = prim (ST (size, IMM)) ~dst ~off ~imm
let jump_ off = prim (JMP (SRC_IMM, JA)) ~off
let jmpi_ off reg cond imm = prim (JMP (SRC_IMM, op_of_cond cond)) ~dst:reg ~off ~imm
let jmp_ off a cond b = prim (JMP (SRC_REG, op_of_cond cond)) ~dst:a ~src:b ~off
let ret = prim (JMP (SRC_IMM, EXIT))
let call imm = prim (JMP (SRC_IMM, CALL)) ~imm

let jump label = Jump (label, unprim @@ jump_ 0)
let jmpi label reg cond imm = Jump (label, unprim @@ jmpi_ 0 reg cond imm)
let jmp label a cond b = Jump (label, unprim @@ jmp_ 0 a cond b)

module ALU(T : sig val alu_op : source -> op_alu -> op end) = struct

let alu_r op dst src = prim (T.alu_op SRC_REG op) ~dst ~src
let alu_i op dst imm = prim (T.alu_op SRC_IMM op) ~dst ~imm
let alu op = (alu_r op, alu_i op)

let add, addi = alu ADD
let sub, subi = alu SUB
let mul, muli = alu MUL
let div, divi = alu DIV
let or_, ori = alu OR
let and_, andi = alu AND
let lsh, lshi = alu LSH
let rsh, rshi = alu RSH
let neg, negi = alu NEG
let mod_, modi = alu MOD
let xor, xori = alu XOR
let mov, movi = alu MOV
let arsh, arshi = alu ARSH

end

module I64 = ALU(struct let alu_op s op = ALU64 (s,op) end)
module I32 = ALU(struct let alu_op s op = ALU (s,op) end)

include I64

let endian_ source imm dst = prim (ALU (source, END)) ~dst ~imm
let endian imm = (endian_ SRC_IMM imm, endian_ SRC_REG imm)

let le16, be16 = endian 16
let le32, be32 = endian 32
let le64, be64 = endian 64

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

let resolve l =
  let labels = Hashtbl.create 7 in
  (* collect *)
  let (_:int) = List.fold_left begin fun pc x ->
    match x with
    | Prim _ | Jump _ -> pc + 1
    | Double _ -> pc + 2
    | Label x ->
      match Hashtbl.find labels x with
      | prev -> fail "Duplicate label at PC %d (previous at %d)" pc prev
      | exception Not_found -> Hashtbl.add labels x pc; pc
  end 0 l
  in
  (* resolve *)
  List.rev @@ snd @@ List.fold_left begin fun (pc,prog) x ->
    match x with
    | Prim insn -> (pc + 1, insn :: prog)
    | Label _ -> (pc,prog)
    | Double (i1, i2) -> (pc + 2, i2 :: i1 :: prog)
    | Jump (label,insn) ->
      match Hashtbl.find labels label with
      | exception Not_found -> fail "Target label at PC %d not found" pc
      | target when target <= pc -> fail "Target label at PC %d points backwards (to PC %d)" pc target
      | target -> (pc + 1, { insn with off = target - (pc + 1) } :: prog)
  end (0,[]) l

let assemble l = emit @@ List.map encode @@ resolve l
