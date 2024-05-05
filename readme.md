# gopper

```
Usage: gopper [OPTIONS] --file <FILE>

Options:
  -f, --file <FILE>      ELF to read gadgets from
  -o, --output <OUTPUT>  Output file for discovered gadgets
      --no-color         Do not show colors even if supported by output [env: NO_COLOR=]
      --force-color      Show colors even if not supported by output [env: FORCE_COLOR=]
  -h, --help             Print help
```

it's fast af

```
❯ hyperfine --warmup 5 "target/release/gopper -f ./tests/bins/libc6_2.35-0ubuntu3.1_amd64.so -o /dev/null"
Benchmark 1: target/release/gopper -f ./tests/bins/libc6_2.35-0ubuntu3.1_amd64.so -o /dev/null
  Time (mean ± σ):     130.9 ms ±   5.7 ms    [User: 131.4 ms, System: 5.3 ms]
  Range (min … max):   123.9 ms … 146.7 ms    22 runs
```

## example

```
❯ ./target/release/gopper --force-color -f tests/bins/libc6_2.35-0ubuntu3.1_amd64.so | head -30
29E24: mov edi,[rdi]; call 00000000000286D0h;
29E23: mov rdi,[r15]; call 00000000000286D0h;
29E1E: cmp eax,1EF17Dh; mov rdi,[r15]; call 00000000000286D0h;
29E1D: mov edi,[218FA0h]; mov rdi,[r15]; call 00000000000286D0h;
29E1C: mov r15,[218FA0h]; mov rdi,[r15]; call 00000000000286D0h;
29E1B: xlat [rbx]; mov r15,[218FA0h]; mov rdi,[r15]; call 00000000000286D0h;
2A5C8: mov [rbp-58h],esi; call strlen (28490);
2A5C7: mov [rbp-58h],rsi; call strlen (28490);
2A5C5: mov edi,esi; mov [rbp-58h],rsi; call strlen (28490);
2A5C4: mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5C2: add [rax],al; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5C0: mov al,0; add [rax],al; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5BE: mov esi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5BD: mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5BB: mov eax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5BA: mov rax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5B8: mov eax,[rax]; mov rax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5B7: mov rax,[rax]; mov rax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5B6: mov rax,fs:[rax]; mov rax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5B2: mov edx,64001EE9h; mov rax,[rax]; mov rax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5B1: add eax,1EE9BAh; mov rax,fs:[rax]; mov rax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5B0: mov eax,[218F70h]; mov rax,fs:[rax]; mov rax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5AF: mov rax,[218F70h]; mov rax,fs:[rax]; mov rax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5AE: add [rax-75h],cl; add eax,1EE9BAh; mov rax,fs:[rax]; mov rax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5AD: add [rax],al; mov rax,[218F70h]; mov rax,fs:[rax]; mov rax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5AC: add [rax],al; add [rax-75h],cl; add eax,1EE9BAh; mov rax,fs:[rax]; mov rax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5AB: xchg ecx,eax; add [rax],al; add [rax-75h],cl; add eax,1EE9BAh; mov rax,fs:[rax]; mov rax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5AA: test [rcx+48000000h],edx; mov eax,[218F70h]; mov rax,fs:[rax]; mov rax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A5A8: add [rdi],cl; test [rcx+48000000h],edx; mov eax,[218F70h]; mov rax,fs:[rax]; mov rax,[rax]; mov rsi,[rax+0B0h]; mov rdi,rsi; mov [rbp-58h],rsi; call strlen (28490);
2A625: out dx,eax; call mempcpy (283E0);
...
1780B9: adc [rcx+rcx*4-0Ah],cl; call __stpncpy (285B0);
1780B8: and al,10h; mov rsi,r14; call __stpncpy (285B0);
1780B6: mov edi,[rsp+10h]; mov rsi,r14; call __stpncpy (285B0);
1780B5: mov rdi,[rsp+10h]; mov rsi,r14; call __stpncpy (285B0);
1780B3: add [rax],al; mov rdi,[rsp+10h]; mov rsi,r14; call __stpncpy (285B0);
1780B1: in al,0; add [rax],al; mov rdi,[rsp+10h]; mov rsi,r14; call __stpncpy (285B0);
19883E: add [rax],al; jmp strlen (28490);
19883C: add [rax],al; add [rax],al; jmp strlen (28490);
19883B: add byte ptr [rax],0; add [rax],al; jmp strlen (28490);
198839: nop [rax]; jmp strlen (28490);
```