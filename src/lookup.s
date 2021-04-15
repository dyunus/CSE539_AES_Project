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
    push rbp
    mov rbp, rsp
    push rbx
    push r9
    push r14
    push r8

    # Load entire lookup table into CPU
    movaps xmm0, [rdx]
    movaps xmm1, [rdx + 0x10]
    movaps xmm2, [rdx + 0x20]
    movaps xmm3, [rdx + 0x30]
    movaps xmm4, [rdx + 0x40]
    movaps xmm5, [rdx + 0x50]
    movaps xmm6, [rdx + 0x60]
    movaps xmm7, [rdx + 0x70]
    movaps xmm8, [rdx + 0x80]
    movaps xmm9, [rdx + 0x90]
    movaps xmm10, [rdx + 0xa0]
    movaps xmm11, [rdx + 0xb0]
    movaps xmm12, [rdx + 0xc0]
    movaps xmm13, [rdx + 0xd0]
    movaps xmm14, [rdx + 0xe0]
    movaps xmm15, [rdx + 0xf0]

    # Calculate which xmm register stores the data using the row provided
    lea r9, [rip + jmp_table]
    mov rcx, 1   # We shift right four to get index and then left 3 to multiply by 8 for quadword offset, 4-3=1
    shr rdi, cl  # The high four-bits hold the register number
    add r9, rdi
    jmp prep_shuf
launch_pad:
    jmp [r9]

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
    pop r8
    pop r14
    pop r9
    pop rbx
    leave
    ret

prep_shuf:
    cmp rdi, 0x78  # 0x78 is 0xf0 shifted right by one bit
    jl use_xmm_15
    jmp use_xmm_0

use_xmm_15:
    vpxor xmm15, xmm15, xmm15
    movq   xmm15, rsi
    jmp launch_pad

use_xmm_0:
    vpxor xmm0, xmm0, xmm0
    movq   xmm0, rsi
    jmp launch_pad

x0:
    pshufb xmm0, xmm15
    pextrb eax, xmm0, 0
    jmp zeroize
x1:
    pshufb xmm1, xmm15
    pextrb eax, xmm1, 0
    jmp zeroize
x2:
    pshufb xmm2, xmm15
    pextrb eax, xmm2, 0
    jmp zeroize
x3:
    pshufb xmm3, xmm15
    pextrb eax, xmm3, 0
    jmp zeroize
x4:
    pshufb xmm4, xmm15
    pextrb eax, xmm4, 0
    jmp zeroize
x5:
    pshufb xmm5, xmm15
    pextrb eax, xmm5, 0
    jmp zeroize
x6:
    pshufb xmm6, xmm15
    pextrb eax, xmm6, 0
    jmp zeroize
x7:
    pshufb xmm7, xmm15
    pextrb eax, xmm7, 0
    jmp zeroize
x8:
    pshufb xmm8, xmm15
    pextrb eax, xmm8, 0
    jmp zeroize
x9:
    pshufb xmm9, xmm15
    pextrb eax, xmm9, 0
    jmp zeroize
x10:
    pshufb xmm10, xmm15
    pextrb eax, xmm10, 0
    jmp zeroize
x11:
    pshufb xmm11, xmm15
    pextrb eax, xmm11, 0
    jmp zeroize
x12:
    pshufb xmm12, xmm15
    pextrb eax, xmm12, 0
    jmp zeroize
x13:
    pshufb xmm13, xmm15
    pextrb eax, xmm13, 0
    jmp zeroize
x14:
    pshufb xmm14, xmm15
    pextrb eax, xmm14, 0
    jmp zeroize
x15:
    pshufb xmm15, xmm0
    pextrb eax, xmm15, 0
    jmp zeroize
