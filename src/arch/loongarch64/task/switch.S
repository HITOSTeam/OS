.section .text
.globl switch
.equ CSR_PGDL, 0x19
.equ CSR_PGDH, 0x1a
switch:
    # a0: current_task_cx_ptr, a1: next_task_cx_ptr
    # Save the coroutine state Rust expects to survive across a context switch:
    # ra, sp, tp, fp, and s0..s8. The remaining slot in `s[12]` is unused.
    st.d $ra, $a0, 0
    st.d $sp, $a0, 8
    # 保存tp(r2)
    st.d $r2, $a0, 16
    # 保存11个 callee-saved 寄存器
    st.d $r22, $a0, 24
    st.d $r23, $a0, 32
    st.d $r24, $a0, 40
    st.d $r25, $a0, 48
    st.d $r26, $a0, 56
    st.d $r27, $a0, 64
    st.d $r28, $a0, 72
    st.d $r29, $a0, 80
    st.d $r30, $a0, 88
    st.d $r31, $a0, 96
    # 保留,因为代码里面要保存12个,所以第12个先填充0
    st.d $zero, $a0, 104

    # 新增的保存CSR_PGDL 以及CSR_PGDH 否则任务切换之后页表还是使用老的页表
    # 使用temp寄存器进行切换
    csrrd $t0, CSR_PGDL
    st.d $t0, $a0, 112
    csrrd $t0, CSR_PGDH
    st.d $t0, $a0, 120

    # Restore the next task's saved coroutine state.
    ld.d $ra, $a1, 0
    ld.d $sp, $a1, 8
    ld.d $r2, $a1, 16
    ld.d $r22, $a1, 24
    ld.d $r23, $a1, 32
    ld.d $r24, $a1, 40
    ld.d $r25, $a1, 48
    ld.d $r26, $a1, 56
    ld.d $r27, $a1, 64
    ld.d $r28, $a1, 72
    ld.d $r29, $a1, 80
    ld.d $r30, $a1, 88
    ld.d $r31, $a1, 96
    ld.d $t0, $a1, 112
    csrwr $t0, CSR_PGDL
    ld.d $t0, $a1, 120
    csrwr $t0, CSR_PGDH
    # Do not flush here: user translations are tagged by ASID on trap return.
    # Flushing on every context switch destroys the cyclictest/hackbench fast path.

    # 跳转到ra执行,也就是a1的最开始位置
    jirl $zero, $ra, 0
