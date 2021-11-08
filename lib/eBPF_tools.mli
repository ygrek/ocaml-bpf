open EBPF_types

(** {2 Assembler} *)

type options = {
  disable_all_checks : bool; (** disable all checks, may generate invalid code *)
  jump_back : bool; (** allow jump backwards, may result in infinite loop *)
  jump_self : bool; (** allow jump to self, guaranteed infinite loop *)
}

val default : options

val assemble : ?options:options -> 'a insn list -> string

val parse : string -> string insn list
