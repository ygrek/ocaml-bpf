open EBPF_types
open EBPF_tools

(* check if data starts with the (4-byte) answer to life and everything *)
let life =
[
  ldx W R1 (R1,0);
  movi R0 1;
  movi R2 42;
  jmp `Exit R1 `EQ R2;
  movi R0 0;
label `Exit;
  ret
]

(* check if R1 points to an ARP packet *)
let arp =
[
  ldx H R2 (R1,12);
  movi R0 1;
  jmpi_ 1 R2 `EQ 0x806; (* laborious way to say jmpi `Exit *)
  movi R0 0;
label `Exit;
  ret
]

(* check for IPv4 TCP packet *)
let tcp_ipv4 =
[
  movi R0 0;
  ldx H R2 (R1,12);
  jmpi `Drop R2 `NE 0x800;
  ldx B R2 (R1,23);
  jmpi `Drop R2 `NE 6;
  movi R0 1;
label `Drop;
  ret;
]

let test_lddw =
[
  ldx DW R2 (R1,0);
  lddw R3 0xDEADBEEF01020304L;
  xor R2 R3;
  ldx DW R1 (R1,8);
  movi R0 1;
  jmp `Exit R2 `EQ R1;
  movi R0 0;
label `Exit;
  ret
]

(** check that i-th element of the array is not equal to [value] *)
let not_array i value =
[
  ldx DW R2 (R1,i*8);
  movi R0 0;
  jmpi `Exit R2 `EQ value;
  movi R0 1;
label `Exit;
  ret
]

let () = not_array 2 0 |> assemble |> print_string
