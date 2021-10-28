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
| JLT   (* eBPF only: unsigned '<' *)
| JLE   (* eBPF only: unsigned '<=' *)
| JSLT  (* eBPF only: signed '<' *)
| JSLE  (* eBPF only: signed '<=' *)
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
| JMP32 of source * op_jmp

type int16 = int (* FIXME *)

(** represents any 64-bit value, i.e. also invalid instructions *)
type ('op, 'reg) insn_t = { op : 'op; dst : 'reg; src : 'reg; off : int16; imm : int32; }
type prim = (op, reg) insn_t

let make ?(dst=R0) ?(src=R0) ?(off=0) ?(imm=0) op =
  (* sanity checks *)
  if not (0 <= imm && imm < 4_294_967_296) then fail "Bad immediate : %d" imm;
  { op; dst; src; off; imm = Int32.of_int imm; }

type cond = [ `EQ | `GT | `GE | `SET | `NE | `SGT | `SGE | `LT | `LE | `SLT | `SLE ]
let op_of_cond = function
| `EQ -> JEQ
| `GT -> JGT
| `GE -> JGE
| `SET -> JSET
| `NE -> JNE
| `SGT -> JSGT
| `SGE -> JSGE
| `LT -> JLT
| `LE -> JLE
| `SLT -> JSLT
| `SLE -> JSLE

type 'label insn =
| Prim of prim (* valid instruction *)
| Label of 'label (* marker, no instruction *)
| Jump of 'label * prim (* to patch offset field *)
| Double of prim * prim (* eBPF has one 16-byte instruction: BPF_LD | BPF_DW | BPF_IMM *)

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
let jump32_ off = prim (JMP32 (SRC_IMM, JA)) ~off
let jmp32i_ off reg cond imm = prim (JMP32 (SRC_IMM, op_of_cond cond)) ~dst:reg ~off ~imm
let jmp32_ off a cond b = prim (JMP32 (SRC_REG, op_of_cond cond)) ~dst:a ~src:b ~off
let ret = prim (JMP (SRC_IMM, EXIT))
let call imm = prim (JMP (SRC_IMM, CALL)) ~imm

let jump label = Jump (label, unprim @@ jump_ 0)
let jmpi label reg cond imm = Jump (label, unprim @@ jmpi_ 0 reg cond imm)
let jmp label a cond b = Jump (label, unprim @@ jmp_ 0 a cond b)
let jump32 label = Jump (label, unprim @@ jump32_ 0)
let jmp32i label reg cond imm = Jump (label, unprim @@ jmp32i_ 0 reg cond imm)
let jmp32 label a cond b = Jump (label, unprim @@ jmp32_ 0 a cond b)

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

module ALU(T : sig val alu_op : source -> op_alu -> op end) : ALU = struct

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
let bpf_jmp32 = 0x06
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
    | JMP32 (s, op) -> bpf_jmp32 + op_jmp op + source s
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
      | target -> (pc + 1, { insn with off = target - (pc + 1) } :: prog)
  end (0,[]) l

type options = {
  disable_all_checks : bool;
  jump_back : bool;
  jump_self : bool;
}

let default = {
  disable_all_checks = false;
  jump_back = false;
  jump_self = false;
}

let check options l =
  let len = List.length l in
  match options.disable_all_checks with
  | true -> ()
  | false ->
    l |> List.iteri begin fun pc x ->
      try
        if not options.jump_self && x.off = (-1) then fail "jump to self (options.jump_self)";
        if not options.jump_back && x.off < 0 then fail "jump backwards (options.jump_back)";
        if not (x.off + pc + 1 >= 0 || x.off + pc + 1 < len) then fail "jump out of bounds : offset %d length %d" x.off len;
      with
        Failure s -> fail "Error detected at PC %d : %s" pc s
    end

let assemble ?(options=default) l =
  let l = if options.disable_all_checks then l else resolve l in
  check options l;
  emit @@ List.map encode l
