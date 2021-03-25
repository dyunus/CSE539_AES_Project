.section .rodata
jmp_table:
.quad x0
.quad x1
.quad x2
.quad x3
.quad x4
.quad x5
.quad x6
.quad x7
.quad x8
.quad x9
.quad x10
.quad x11
.quad x12
.quad x13
.quad x14
.quad x15

.section .text
.global no_cache_lookup

no_cache_lookup:
.intel_syntax noprefix    
    # Load entire lookup table into CPU
    movaps xmm0, [rsi]
    movaps xmm1, [rsi + 0x10]    
    movaps xmm2, [rsi + 0x20]
    movaps xmm3, [rsi + 0x30]
    movaps xmm4, [rsi + 0x40]
    movaps xmm5, [rsi + 0x50]
    movaps xmm6, [rsi + 0x60]
    movaps xmm7, [rsi + 0x70]
    movaps xmm8, [rsi + 0x80]
    movaps xmm9, [rsi + 0x90]
    movaps xmm10, [rsi + 0xa0]
    movaps xmm11, [rsi + 0xb0]
    movaps xmm12, [rsi + 0xc0]
    movaps xmm13, [rsi + 0xd0]
    movaps xmm14, [rsi + 0xe0]
    movaps xmm15, [rsi + 0xf0]

    # Calculate xmm register and offset into register where byte is stored
    xor edx, edx
    mov rax, rdi    
    mov rbx, 16    
    div rbx # quotient stored in rax, remainder in rdx
    mov r9, rdx
    mov rbx, 8
    mul rbx
    mov rdx, r9
    lea r9, [rip + jmp_table]    
    add r9, rax    
    jmp [r9]

join:
    # If offset is greater than 8, its in r8 else r9
    xor eax, eax
    mov r14, rdx
    cmp rdx, 8
    jl less_eight
    sub rdx, 8
less_eight:
    mov rax, rdx
    mov rbx, 8    
    mul rbx
    mov ecx, eax
    cmp r14, 8
    jge in_r9
    shr r8, cl
    and r8, 0xFF
    mov rax, r8
    jmp zeroize
 in_r9:
    shr r9, cl
    and r9, 0xFF
    mov rax, r9 
zeroize:
    vpxor xmm0, xmm0, xmm0
    vpxor xmm1, xmm1, xmm1
    vpxor xmm2, xmm2, xmm2
    vpxor xmm4, xmm4, xmm4
    vpxor xmm5, xmm5, xmm5
    vpxor xmm6, xmm6, xmm6
    vpxor xmm7, xmm7, xmm7
    vpxor xmm8, xmm8, xmm8
    vpxor xmm9, xmm9, xmm9
    vpxor xmm10, xmm10, xmm10
    vpxor xmm11, xmm11, xmm11
    vpxor xmm12, xmm12, xmm12
    vpxor xmm13, xmm13, xmm13
    vpxor xmm14, xmm14, xmm14
    vpxor xmm15, xmm15, xmm15
    ret
x0:
    pextrq r8, xmm0, 0
    pextrq r9, xmm0, 1
    jmp join
x1:
    pextrq r8, xmm1, 0
    pextrq r9, xmm1, 1
    jmp join
x2:
    pextrq r8, xmm2, 0
    pextrq r9, xmm2, 1
    jmp join
x3:
    pextrq r8, xmm3, 0
    pextrq r9, xmm3, 1
    jmp join
x4:
    pextrq r8, xmm4, 0
    pextrq r9, xmm4, 1
    jmp join
x5:
    pextrq r8, xmm5, 0
    pextrq r9, xmm5, 1
    jmp join
x6:
    pextrq r8, xmm6, 0
    pextrq r9, xmm6, 1
    jmp join
x7:
    pextrq r8, xmm7, 0
    pextrq r9, xmm7, 1
    jmp join
x8:
    pextrq r8, xmm8, 0
    pextrq r9, xmm8, 1
    jmp join
x9:
    pextrq r8, xmm9, 0
    pextrq r9, xmm9, 1
    jmp join
x10:
    pextrq r8, xmm10, 0
    pextrq r9, xmm10, 1
    jmp join
x11:
    pextrq r8, xmm11, 0
    pextrq r9, xmm11, 1
    jmp join
x12:
    pextrq r8, xmm12, 0
    pextrq r9, xmm12, 1
    jmp join
x13:
    pextrq r8, xmm13, 0
    pextrq r9, xmm13, 1
    jmp join
x14:
    pextrq r8, xmm14, 0
    pextrq r9, xmm14, 1
    jmp join
x15:
    pextrq r8, xmm15, 0
    pextrq r9, xmm15, 1
    jmp join