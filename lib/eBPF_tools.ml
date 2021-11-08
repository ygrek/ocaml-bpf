open EBPF_types

let fail fmt = Printf.ksprintf failwith fmt
   
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
let reg = EBPF_types.reg_to_enum

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
  let l = resolve l in
  check options l;
  emit @@ List.map encode l

let parse fn : string insn list =
  let ic = Stdio.In_channel.create fn in
  let lexbuf = Lexing.from_channel ~with_positions:true ic in
  Parser.program Lexer.tokenize lexbuf
