.data
.global __start

.text
    __start:
        li      $4, 97          # Load 97
        li      $2, 4001        # specify program exit
        syscall                 # syscall!
