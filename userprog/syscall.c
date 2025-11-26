#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "filesys/file.h"
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

static bool is_valid_address_buffer(void* buffer, unsigned size) {
    for (void* checking = buffer; checking < buffer + size; checking++)
        if (!is_valid_address(checking)) return false;

    return true;
}

// @return index of fdTable or -1 if failed
static int findFD(struct file** fdTable) {
    // 0, 1은 STDIN, STDOUT
    for (int idx = 2; idx <= FD_TABLE_LENGTH; idx++)
        if (fdTable[idx] == NULL) return idx;

    return -1;
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

        case SYS_REMOVE: {
            char* fileName = (char*)f->R.rdi;

            if (!is_valid_address(fileName))
            {
                f->R.rax = false;
                break;
            }

            f->R.rax = filesys_remove(fileName);
            break;
        }

        case SYS_WRITE: {
            int fd = (int)f->R.rdi;
            void* buffer = (void*)f->R.rsi;
            unsigned size = (unsigned)f->R.rdx;

            if (!is_valid_address_buffer(buffer, size))
            {
                f->R.rax = -1;  // gitbook에 자료가 없다. 표준을 따른다.
                break;
            }

            switch (fd)
            {
                // 표준 입력(키보드)에 쓰기 할 수는 없다.
                case 0: {
                    f->R.rax = -1;
                    break;
                }

                // 터미널에 한글자씩 출력
                case 1: {
                    putbuf(buffer, size);
                    f->R.rax = size;
                    break;
                }

                default:
                    f->R.rax =
                        (unsigned)file_write(curr->fdTable[fd], buffer, size);
            }

            break;
        }

        case SYS_OPEN: {
            int fd = findFD(curr->fdTable);

            f->R.rax = fd;

            if (fd == -1) break;

            char* fileName = (char*)f->R.rdi;
            struct file* opened = filesys_open(fileName);

            if (opened)
                curr->fdTable[fd] = opened;
            else
                f->R.rax = -1;  // fail

            break;
        }

        case SYS_READ: {
            int fd = (int)f->R.rdi;
            char* buffer = (char*)f->R.rsi;
            unsigned size = (unsigned)f->R.rdx;
            unsigned read;  // 실제로 읽은 길이

            if (!is_valid_address_buffer(buffer, size))
            {
                f->R.rax = -1;  // gitbook에 자료가 없다. 표준을 따른다.
                break;
            }

            switch (fd)
            {
                // 표준 입력(키보드 읽기)
                case 0: {
                    for (read = 0; read < size; read++)
                    {
                        buffer[read] = (char)input_getc();

                        // 개행문자를 만나면 탈출
                        if (buffer[read] == '\n')
                        {
                            f->R.rax = read + 1;
                            break;  // for 반복만 빠져나간다.
                        }
                    }

                    // 끝까지 읽은 경우인지 아닌지 확인 필요
                    if (size == read) f->R.rax = size;
                    break;
                }

                // 표준 출력(터미널)을 읽을수는 없다.
                case 1: {
                    f->R.rax = -1;
                    break;
                }

                // 일반적인 파일 읽기
                default:
                    f->R.rax =
                        (unsigned)file_read(curr->fdTable[fd], buffer, size);
            }

            break;
        }

        default: thread_exit();
    }
    // SYS_FORK,     /* Clone current process. */
    // SYS_EXEC,     /* Switch current process. */
    // SYS_WAIT,     /* Wait for a child process to die. */
    // SYS_FILESIZE, /* Obtain a file's size. */
    // SYS_SEEK,     /* Change position in a file. */
    // SYS_TELL,     /* Report current position in a file. */
    // SYS_CLOSE,    /* Close a file. */
}
