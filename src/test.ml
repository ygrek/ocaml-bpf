open EBPF

let life =
[
  ldx W R1 (R1,0);
  movi R0 1;
  movi R2 42;
  jmp 1 R1 `EQ R2;
  movi R0 0;
  ret
]

let arp =
[
  ldx H R2 (R1,12);
  movi R0 1;
  jmpi 1 R2 `EQ 0x806;
  movi R0 0;
  ret
]

(* IPv4 TCP packets *)

let tcp_ipv4 =
[
  movi R0 0;
  ldx H R2 (R1,12);
  jmpi 3 R2 `NE 0x800;
  ldx B R2 (R1,23);
  jmpi 1 R2 `NE 6;
  movi R0 1;
  ret
]

let () = tcp_ipv4 |> assemble |> print_string
