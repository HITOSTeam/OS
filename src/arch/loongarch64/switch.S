.section .text
.globl switch
switch:
    # a0: current_task_cx_ptr, a1: next_task_cx_ptr
    st.d $ra, $a0, 0
    st.d $sp, $a0, 8
    st.d $r21, $a0, 16
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
    st.d $r20, $a0, 104

    ld.d $ra, $a1, 0
    ld.d $sp, $a1, 8
    ld.d $r21, $a1, 16
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
    ld.d $r20, $a1, 104

    jirl $zero, $ra, 0
