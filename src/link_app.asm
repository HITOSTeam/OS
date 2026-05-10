.section .rodata
.align 3
app_0_name:
    .asciz "00shell"
.section .rodata
.align 3
app_1_name:
    .asciz "cat"
.section .rodata
.align 3
app_2_name:
    .asciz "init_proc"
.section .rodata
.align 3
app_3_name:
    .asciz "ls"
.section .rodata
.align 3
app_4_name:
    .asciz "testcode_runner"
.section .rodata
.align 3
app_5_name:
    .asciz "basename"
.section .rodata
.align 3
app_6_name:
    .asciz "submit_script"
.section .rodata
.align 3
app_7_name:
    .asciz "poweroff"
.section .rodata
.align 3
app_8_name:
    .asciz "ifconfig"
.section .rodata
.align 3
app_9_name:
    .asciz "ps"
.section .rodata
.align 3
app_10_name:
    .asciz "nested_epoll_smoke"
.section .rodata
.align 3
app_11_name:
    .asciz "epoll_ctl_wakeup_smoke"
.section .rodata
.align 3
app_12_name:
    .asciz "eventfd_epoll_smoke"
.section .rodata
.align 3
app_13_name:
    .asciz "timerfd_epoll_smoke"
.section .rodata
.align 3
app_14_name:
    .asciz "mq_epoll_smoke"
.section .rodata
.align 3
app_15_name:
    .asciz "mq_unlink_epoll_smoke"
.section .rodata
.align 3
app_16_name:
    .asciz "mq_notify_signal_smoke"
.section .rodata
.align 3
app_17_name:
    .asciz "nested_epoll_ctl_wakeup_smoke"
.section .rodata
.align 3
app_18_name:
    .asciz "nested_epoll_oneshot_smoke"
.section .rodata
.align 3
app_19_name:
    .asciz "nested_epoll_ctl_del_smoke"
.section .rodata
.align 3
app_20_name:
    .asciz "nested_epoll_et_smoke"
.section .rodata
.align 3
app_21_name:
    .asciz "nested_epoll_et_maxevents_smoke"
.section .rodata
.align 3
app_22_name:
    .asciz "nested_epoll_parent_oneshot_smoke"
.section .rodata
.align 3
app_23_name:
    .asciz "proc_magic_links_smoke"
.section .rodata
.align 3
app_24_name:
    .asciz "mount_namespace_smoke"
.section .rodata
.align 3
app_25_name:
    .asciz "umount_once"
.section .rodata
.align 3
app_26_name:
    .asciz "dup3_lock_cleanup_smoke"
.section .rodata
.align 3
    .global num_user_apps
num_user_apps:
    .quad 27
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
