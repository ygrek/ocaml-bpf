open EBPF

let life =
[
  ldx W R1 (R1,0);
  movi R0 1;
  movi R2 42;
  jmp_ 1 R1 `EQ R2;
  movi R0 0;
  ret
]

let arp =
[
  ldx H R2 (R1,12);
  movi R0 1;
  jmpi_ 1 R2 `EQ 0x806;
  movi R0 0;
  ret
]

(* IPv4 TCP packets *)

let tcp_ipv4_ =
[
  movi R0 0;
  ldx H R2 (R1,12);
  jmpi_ 3 R2 `NE 0x800;
  ldx B R2 (R1,23);
  jmpi_ 1 R2 `NE 6;
  movi R0 1;
  ret
]

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

let () = test_lddw |> assemble |> print_string
