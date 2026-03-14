.section .rodata
.align 3
app_0_name:
    .asciz "00shell"
.section .rodata
.align 3
app_1_name:
    .asciz "02helloqiukaiyu"
.section .rodata
.align 3
app_2_name:
    .asciz "03syscall_test"
.section .rodata
.align 3
app_3_name:
    .asciz "04test"
.section .rodata
.align 3
app_4_name:
    .asciz "05"
.section .rodata
.align 3
app_5_name:
    .asciz "06"
.section .rodata
.align 3
app_6_name:
    .asciz "07"
.section .rodata
.align 3
app_7_name:
    .asciz "123"
.section .rodata
.align 3
app_8_name:
    .asciz "all_tests"
.section .rodata
.align 3
app_9_name:
    .asciz "cat"
.section .rodata
.align 3
app_10_name:
    .asciz "condvar_basic"
.section .rodata
.align 3
app_11_name:
    .asciz "fork_no_wait"
.section .rodata
.align 3
app_12_name:
    .asciz "hart_id"
.section .rodata
.align 3
app_13_name:
    .asciz "init_proc"
.section .rodata
.align 3
app_14_name:
    .asciz "multicore_test"
.section .rodata
.align 3
app_15_name:
    .asciz "mutex_block"
.section .rodata
.align 3
app_16_name:
    .asciz "mutex_spin"
.section .rodata
.align 3
app_17_name:
    .asciz "pipe_test"
.section .rodata
.align 3
app_18_name:
    .asciz "producer"
.section .rodata
.align 3
app_19_name:
    .asciz "semaphore_basic"
.section .rodata
.align 3
app_20_name:
    .asciz "semaphore_cond"
.section .rodata
.align 3
app_21_name:
    .asciz "sleep_debug"
.section .rodata
.align 3
app_22_name:
    .asciz "sleep_simple"
.section .rodata
.align 3
app_23_name:
    .asciz "sleep_stress"
.section .rodata
.align 3
app_24_name:
    .asciz "sleep_test"
.section .rodata
.align 3
app_25_name:
    .asciz "sync_abc_mutex"
.section .rodata
.align 3
app_26_name:
    .asciz "thread"
.section .rodata
.align 3
app_27_name:
    .asciz "thread_arg"
.section .rodata
.align 3
app_28_name:
    .asciz "thread_counter"
.section .rodata
.align 3
app_29_name:
    .asciz "thread_lock"
.section .rodata
.align 3
app_30_name:
    .asciz "ls"
.section .rodata
.align 3
app_31_name:
    .asciz "testcode_runner"
.section .rodata
.align 3
app_32_name:
    .asciz "basename"
.section .rodata
.align 3
app_33_name:
    .asciz "submit_script"
.section .rodata
.align 3
app_34_name:
    .asciz "poweroff"
.section .rodata
.align 3
app_35_name:
    .asciz "ifconfig"
.section .rodata
.align 3
app_36_name:
    .asciz "ps"
.section .rodata
.align 3
app_37_name:
    .asciz "nested_epoll_smoke"
.section .rodata
.align 3
app_38_name:
    .asciz "epoll_ctl_wakeup_smoke"
.section .rodata
.align 3
app_39_name:
    .asciz "eventfd_epoll_smoke"
.section .rodata
.align 3
app_40_name:
    .asciz "timerfd_epoll_smoke"
.section .rodata
.align 3
app_41_name:
    .asciz "mq_epoll_smoke"
.section .rodata
.align 3
app_42_name:
    .asciz "mq_unlink_epoll_smoke"
.section .rodata
.align 3
app_43_name:
    .asciz "mq_notify_signal_smoke"
.section .rodata
.align 3
app_44_name:
    .asciz "nested_epoll_ctl_wakeup_smoke"
.section .rodata
.align 3
app_45_name:
    .asciz "nested_epoll_oneshot_smoke"
.section .rodata
.align 3
app_46_name:
    .asciz "nested_epoll_ctl_del_smoke"
.section .rodata
.align 3
app_47_name:
    .asciz "nested_epoll_et_smoke"
.section .rodata
.align 3
app_48_name:
    .asciz "nested_epoll_et_maxevents_smoke"
.section .rodata
.align 3
    .global num_user_apps
num_user_apps:
    .quad 49
    .quad app_0_name
    .quad app_1_name
    .quad app_2_name
    .quad app_3_name
    .quad app_4_name
    .quad app_5_name
    .quad app_6_name
    .quad app_7_name
    .quad app_8_name
    .quad app_9_name
    .quad app_10_name
    .quad app_11_name
    .quad app_12_name
    .quad app_13_name
    .quad app_14_name
    .quad app_15_name
    .quad app_16_name
    .quad app_17_name
    .quad app_18_name
    .quad app_19_name
    .quad app_20_name
    .quad app_21_name
    .quad app_22_name
    .quad app_23_name
    .quad app_24_name
    .quad app_25_name
    .quad app_26_name
    .quad app_27_name
    .quad app_28_name
    .quad app_29_name
    .quad app_30_name
    .quad app_31_name
    .quad app_32_name
    .quad app_33_name
    .quad app_34_name
    .quad app_35_name
    .quad app_36_name
    .quad app_37_name
    .quad app_38_name
    .quad app_39_name
    .quad app_40_name
    .quad app_41_name
    .quad app_42_name
    .quad app_43_name
    .quad app_44_name
    .quad app_45_name
    .quad app_46_name
    .quad app_47_name
    .quad app_48_name
