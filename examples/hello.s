.data
    hello:
        .asciz      "Hello, world!\n"
    length:
        .word       . - hello

.global main

.text
    main:
        move    $4, $0          # load stdout fd
        la      $5, hello       # load string address
        lw      $6, length      # load string length
        li      $2, 4004        # specify system write service
        syscall                 # call the kernel (write string)
        li      $2, 0           # load return code
        j       $31             # return to caller
