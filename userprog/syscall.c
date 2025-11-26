#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame*);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

// %MSR은 syscall 관련 레지스터인데, 역할별로 여러개가 있다.
//  이 함수에서는 3개의 %MSR을 세팅해준다.
void syscall_init(void) {
    // syscall, sysret instructions을 각각 호출할 때
    // %cs, %ss의 CPL(Current Privilege Level)을 어떻게 설정할지 설정
    write_msr(MSR_STAR,
              ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);

    // syscall instruction 호출 진입점 설정
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    // syscall instruction 호출 시 마스킹할 요소들
    //  e.g Hardware Interrupts
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

static bool is_valid_address(void* addr) {
    if (addr == NULL) return false;
    if (addr >= (void*)USER_STACK) return false;
    if (pml4_get_page(thread_current()->pml4, addr) == NULL) return false;

    return true;
}

/* The main system call interface */
void syscall_handler(struct intr_frame* f UNUSED) {
    struct thread* curr = thread_current();

    switch (f->R.rax)
    {
        case SYS_HALT: {
            power_off();
        }

        case SYS_EXIT: {
            // TODO:: 자원회수 해야함
            // - 각종 대기열에서 제거
            // - 세마포어
            // - (페이지 테이블의 맵핑된 영역 및 페이지 디렉토리 자체는 이미
            // 구현됨)

            curr->exitStatus = f->R.rdi;

            // WARN::
            // 현재는 thread_exit하면 바로 TCB까지 회수된다.
            // 일단 좀비 상태로 기다려야하고, 부모가 wait를 호출해서
            // exitStatus를 받아줄 때까지 대기한다.
            // - 세마포어 등 활용 필요
            thread_exit();
        }

        case SYS_CREATE: {
            char* fileName = (char*)f->R.rdi;
            unsigned initialSize = f->R.rsi;

            if (!is_valid_address(fileName))
            {
                f->R.rax = false;
                break;
            }

            f->R.rax = filesys_create(fileName, initialSize);
            break;
        }

        default: thread_exit();
    }
    // SYS_FORK,     /* Clone current process. */
    // SYS_EXEC,     /* Switch current process. */
    // SYS_WAIT,     /* Wait for a child process to die. */
    // SYS_REMOVE,   /* Delete a file. */
    // SYS_OPEN,     /* Open a file. */
    // SYS_FILESIZE, /* Obtain a file's size. */
    // SYS_READ,     /* Read from a file. */
    // SYS_WRITE,    /* Write to a file. */
    // SYS_SEEK,     /* Change position in a file. */
    // SYS_TELL,     /* Report current position in a file. */
    // SYS_CLOSE,    /* Close a file. */
}
