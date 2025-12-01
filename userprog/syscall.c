#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "threads/init.h"
#include "../include/lib/user/syscall.h"
#include "../include/filesys/filesys.h"
#include "../filesys/file.h"
#include "../filesys/inode.h"
// #include "lib/user/syscall.h"

#define MAX_STACK_BUFFER 512

extern struct lock filesys_lock;  /* 전역 파일 시스템 락 */

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* argument validation function */
void check_user_vaddr(void *ptr);
void check_user_buffer(const void *buffer, unsigned size);
void check_user_string(const char *str);

/* syscall list */
void halt(void);
void exit(int status);
int exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. 
 
 * 이전에는 시스템 콜 서비스가 인터럽트 핸들러(예: 리눅스의 int 0x80)를 통해 처리되었다.
하지만 x86-64에서는 시스템 콜을 요청하기 위한 더 효율적인 경로가 제공되며, 바로 syscall 명령어이다.
syscall 명령어는 Model Specific Register(MSR)에 저장된 값을 읽어 동작한다.
 * 
 * */
// CPU가 어떤 권한 레벨의 어떤 세그먼트로 전환할지
#define MSR_STAR 0xc0000081         /* Segment selector msr */
// 시스템 콜이 발생했을 때 실행될 커널 진입 함수의 주소
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
// syscall 진입 시 자동으로 클리어할 RFLAGS 비트 마스크
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

// 완료 함수
void check_user_vaddr(void *ptr) {
	if (ptr == NULL)
		exit(-1);
		

	if (!is_user_vaddr(ptr))
		exit(-1);

	// mapping 된 페이지 인지 
	if (pml4_get_page(thread_current()->pml4, ptr) == NULL)
		exit(-1);
}

void check_user_buffer(const void *buffer, unsigned size) {
	
	if (size == 0)
		return;

	const char *start = buffer;
	const char *end = start + size - 1;

	if (!is_user_vaddr(start) || !is_user_vaddr(end)){
		exit(-1); 
	}
		
	// for (const char *addr = start; addr <= end; addr += PGSIZE) {
	// 	if (pml4_get_page(thread_current()->pml4, addr) == NULL)
	// 		exit(-1);
	// }
	const char *first_page_addr = pg_round_down(start);
	const char *last_page_addr = pg_round_down(end);

	for (const char *addr = first_page_addr; addr <= last_page_addr; addr += PGSIZE) {
		if (pml4_get_page(thread_current()->pml4, addr) == NULL)
			exit(-1);
	}
}

void check_user_string(const char *str) {
	check_user_vaddr(str);

	char *ptr = (char *) str;

	while (true) {
		check_user_vaddr(ptr);

		if (*ptr == '\0')
			break;
		
		ptr++;
	}
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf("\n=== System Call Handler Debug ===\n");
    // printf("Syscall Num (rax): %lld\n", f->R.rax); // 시스템 콜 번호
    // printf("Arg1 (rdi): %lld\n", f->R.rdi);        // 1번째 인자
    // printf("Arg2 (rsi): %lld\n", f->R.rsi);        // 2번째 인자
    // printf("Arg3 (rdx): %lld\n", f->R.rdx);        // 3번째 인자
    // printf("Arg4 (r10): %lld\n", f->R.r10);        // 4번째 인자
    // printf("Arg5 (r8) : %lld\n", f->R.r8);         // 5번째 인자
    // printf("Arg6 (r9) : %lld\n", f->R.r9);         // 6번째 인자
    // printf("Stack Pointer (rsp): %p\n", f->rsp);   // 유저 스택 포인터
    // printf("=================================\n");
	
	int syscall_number = f->R.rax;

	switch (syscall_number) {
		case SYS_HALT: // 운영체제를 종료. QEMU에서 실행 중인 Pintos를 종료
			halt();
			break;
		case SYS_EXIT: // 현재 프로세스를 종료하며, 종료 상태를 부모에게 전달.
			exit(f->R.rdi);
			break;
		case SYS_FORK: // 
			break;
		case SYS_EXEC: // 새로운 사용자 프로그램을 실행. 성공하면 반환하지 않고, 실패시 exit(-1)
			f->R.rax = exec(f->R.rdi);
			break;
		case SYS_WAIT: // 자식 프로세스가 종료될 때까지 기다리고, exit_status를 반환
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE: // 새로운 파일을 생성. 초기 크기 지정 가능. 성공 시 true 반환
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE: // 파일을 삭제. 성공 시 true 반환
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN: // 파일을 열고, fd 테이블에 추가. fd반환 실패 시 -1
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE: // 열린 파일의 크기를 반환 -> 테스트 존재하지 않음
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ: // fd에 해당하는 파일이나 콘솔에서 size 바이트 읽음. 읽은 바이트 수 반환
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE: // fd에 해당하는 파일이나 콘솔에 size 바이트 씀. 쓴 바이트 수 반환
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK: // 열린 파일의 현재 읽기/쓰기 위치를 지정된 위치로 이동.
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL: // 열린 파일의 현재 위치를 반환
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE: // 열린 파일을 닫고, fd테이블에서 제거
			close(f->R.rdi);
			break;
		default:
			// kill_process();
			exit(-1);
	}
}

void halt(void)
{
	power_off();
}

void exit(int status) 
{
	struct thread *t = thread_current();
	t->exit_status = status;
	thread_exit();
	NOT_REACHED();
}

int exec(const char *cmd_line)
{
/**
주어진 cmd_line의 실행 파일로 현재 프로세스를 변경하고, 전달된 인자가 있다면 함께 전달합니다.
실행에 성공하면 이 함수는 절대로 반환하지 않습니다.
만약 프로그램을 로드하거나 실행할 수 없는 이유가 있으면, 프로세스는 exit 상태 -1로 종료됩니다.

이 함수는 exec를 호출한 스레드의 이름을 변경하지 않습니다.
또한, 파일 디스크립터는 exec 호출 이후에도 열린 상태로 유지됩니다.
*/
	check_user_vaddr(cmd_line);
	
	/**
	 * process.c 의 process_create_initd 함수와 유사 -> 단, 스레드를 새로 생성하는 건 form에서 수행하므로
	 * -> 스레드 생성 X , process_exec 호출 
	*/
	char *cmd_line_copy;
	cmd_line_copy = palloc_get_page(0);
	if (cmd_line_copy == NULL)
		exit(-1);
	strlcpy(cmd_line_copy, cmd_line, PGSIZE);

	if (process_exec(cmd_line_copy) == -1)
		exit(-1);
}

int wait(pid_t pid) // 자식 프로세스가 종료될 때까지 기다리고, exit_status를 반환
{
/**
 * 주어진 pid의 자식 프로세스를 기다리고, 그 자식의 종료 상태(exit status)를 가져옵니다.
- 만약 pid가 아직 실행 중이면, 종료될 때까지 기다립니다.
- 종료 후에는 자식이 exit에 전달한 상태값을 반환합니다.
- 만약 자식이 exit()를 호출하지 않고 커널에 의해 종료되었다면(예: 예외 발생으로 강제 종료), wait(pid)는 -1을 반환해야 합니다.

부모 프로세스가 이미 종료된 자식 프로세스를 기다리는 것도 합법적입니다.
- 이 경우 커널은 부모가 자식의 종료 상태를 정상적으로 가져올 수 있도록 하거나,
- 자식이 커널에 의해 강제 종료된 사실을 알 수 있게 해야 합니다.

wait는 아래 조건 중 하나라도 참이면 즉시 실패하고 -1을 반환해야 합니다.

1. pid가 호출한 프로세스의 직접적인 자식이 아닐 경우
- 어떤 프로세스가 fork를 성공적으로 호출했을 때 반환된 pid만이 “직접 자식(direct child)”입니다.
- 부모는 자식의 자식을 기다릴 수 없습니다.
	예:
	- A → B 생성
	- B → C 생성
		이 경우 A는 C를 기다릴 수 없습니다. B가 이미 죽어 있어도 마찬가지입니다.
		A가 wait(C)를 호출하면 반드시 실패해야 합니다.
	- 또한 부모가 먼저 종료되었을 때 고아 프로세스가 다른 부모에게 재할당되는 일도 없습니다.

2. 해당 pid에 대해 이미 wait을 호출한 경우
- 어떤 자식에 대해 wait은 최대 한 번만 호출할 수 있습니다.
- 동일한 pid에 대해 두 번째 wait(pid)는 실패해야 합니다. 


프로세스는 얼마든지 많은 자식 프로세스를 생성할 수 있으며,
어떤 순서로든 wait을 호출할 수 있고,
심지어 일부 혹은 모든 자식에 대해 wait을 호출하지 않은 채 종료될 수도 있습니다.

따라서 wait이 일어날 수 있는 모든 상황을 고려한 설계를 해야 합니다.

부모가 자식을 기다렸는지 여부와 관계없이,
또 자식이 부모보다 먼저 종료했는지 여부와도 무관하게,
모든 프로세스의 자원(struct thread 포함)은 반드시 해제되어야 합니다.

또한 Pintos는 초기 프로세스(initial process)가 종료되기 전까지는 Pintos 전체가 종료되지 않도록 보장해야 합니다.
기본 Pintos 코드는 이를 위해 threads/init.c의 main()에서
userprog/process.c의 process_wait()을 호출하려고 합니다.

따라서 process_wait()을 함수 상단의 주석 설명에 맞춰 구현하고,
그 다음 wait 시스템 콜을 process_wait()을 기반으로 구현할 것을 권장합니다.

참고로, 이 시스템 콜 구현은 지금까지 구현했던 어느 기능보다도
훨씬 많은 작업이 필요합니다.
*/

}

bool create(const char *file, unsigned initial_size) 
{
/**
주어진 이름의 새로운 파일을 생성하며, 파일의 초기 크기는 initial_size 바이트입니다.
성공하면 true를 반환하고, 실패하면 false를 반환합니다.
파일을 생성하는 것(create)은 파일을 여는(open) 것과는 별개의 동작입니다.
새로 생성된 파일을 사용하려면 이후에 open 시스템 콜을 따로 호출해야 합니다.
*/
	check_user_string(file);
	struct file *create_file = file;
	
	lock_acquire(&filesys_lock);
	bool result = filesys_create (file, initial_size);
	lock_release(&filesys_lock);

	return result;
}

bool remove(const char *file) 
{
/**
지정한 이름의 파일을 삭제한다. 삭제에 성공하면 true, 실패하면 false를 반환한다.
파일은 열려 있든 닫혀 있든 상관없이 제거될 수 있으며, 열려 있는 파일을 삭제해도 그 파일이 자동으로 닫히지는 않는다.
자세한 내용은 FAQ의 Removing an Open File 항목을 참고한다. 
*/
	check_user_string(file);
	struct file *remove_file = file;
	
	lock_acquire(&filesys_lock);
	bool result = filesys_remove(file);
	lock_release(&filesys_lock);
	return result;
}

int open(const char *file)
{
/**
파일 이름 file을 연다.
성공하면 음수가 아닌 정수 형태의 파일 디스크립터(fd) 를 반환하고,
열지 못하면 -1을 반환한다.

파일 디스크립터 0과 1은 콘솔에 예약되어 있다.

- fd 0 (STDIN_FILENO) → 표준 입력
- fd 1 (STDOUT_FILENO) → 표준 출력

open 시스템 콜은 이 두 번호를 반환하지 않는다.
이 번호들은 아래에서 명시된 경우에만 시스템 콜 인자로 사용될 수 있다.

각 프로세스는 독립된 파일 디스크립터 집합을 가진다.
그리고 파일 디스크립터는 자식 프로세스에게 상속된다.

같은 파일을 여러 번 열면(같은 프로세스든, 다른 프로세스든 상관없이) 각각 새로운 파일 디스크립터를 반환한다.
동일한 파일에 대해 여러 디스크립터가 존재하면 각 디스크립터는 서로 독립적으로 close 될 수 있으며, 파일 위치(file position) 도 공유하지 않는다.
추가 요구사항으로는, Linux 방식처럼 0부터 시작하는 정수(파일 디스크립터)를 반환하도록 구현해야 한다.
*/
	check_user_string(file);

	lock_acquire(&filesys_lock);
	struct file *open_file = filesys_open(file);
	lock_release(&filesys_lock);

	if (open_file == NULL)
		return -1;

	int fd = fd_alloc();
	thread_current()->fd_table[fd] = open_file;
	return fd;
}

int filesize(int fd)
{
	if (fd == 0 || fd == 1 || !fd_available(fd))
		return -1;

	struct thread *t = thread_current();
	struct file *selected_file = t->fd_table[fd];
	if (selected_file == NULL)
		return -1;
		 
	lock_acquire(&filesys_lock);
	int result = file_length(selected_file);
	lock_release(&filesys_lock);

	return result;
}

int read(int fd, void *buffer, unsigned size)
{
/**
파일 디스크립터 fd로 열린 파일에서 size 바이트를 읽어 buffer에 저장합니다. 
실제로 읽은 바이트 수를 반환하며, 파일 끝에 도달하면 0을 반환합니다. 
읽을 수 없는 경우(파일 끝이 아닌 다른 이유로)에는 -1을 반환합니다. 
fd 0은 키보드에서 읽으며 input_getc()를 사용합니다.
*/
	check_user_buffer(buffer, size);

	if (fd == 1 || fd < 0 || !fd_available(fd))
		return -1;

	if (fd == 0) {
		size_t input_size = 0;
		char *buf_ptr = buffer;

		while (input_size < size) {
			char c = input_getc();
			*buf_ptr++ = c;
			++input_size;

			if (c == '\n')
				break;
		}

		return input_size;
	}

	struct file *selected_file = thread_current()->fd_table[fd];
	
	if (!selected_file)
		return -1;
	
	lock_acquire(&filesys_lock);
	int result = file_read(selected_file, buffer, size);
	lock_release(&filesys_lock);
	return result;
}

int write(int fd, const void *buffer, unsigned size)
{
/**
size 바이트를 buffer에서 읽어, 파일 디스크립터 fd로 열린 파일에 기록합니다.
반환값은 실제로 기록된 바이트 수이며, 일부 바이트만 기록될 수 있으므로 항상 size와 같지는 않을 수 있습니다.

파일 끝을 넘어 쓰는 동작은 일반적으로 파일을 확장시키지만, Pintos의 기본 파일 시스템에서는 파일 크기 증가가 구현되어 있지 않습니다.
따라서 가능한 범위까지만 기록한 뒤, 기록한 바이트 수를 반환하거나, 한 바이트도 기록하지 못한 경우에는 0을 반환해야 합니다.

fd = 1은 콘솔 출력을 의미합니다.
콘솔에 출력할 때는 여러 번 나누어 출력하면 서로 다른 프로세스의 출력이 섞일 수 있으므로,
버퍼 크기가 몇백 바이트 이하라면 putbuf()를 한 번 호출하여 buffer 전체를 출력하는 것이 권장됩니다.
다만 buffer가 매우 큰 경우라면 여러 번 나누어 출력하는 것도 허용됩니다.

그렇지 않으면, 여러 프로세스가 출력하는 텍스트가 뒤섞여 사람이 읽거나 채점 스크립트가 검사하기 어려워지는 문제가 생길 수 있습니다.
*/
	check_user_buffer(buffer, size);
	
	if (fd == 1) {
		putbuf(buffer, size);
		return size;
	}

	if (!fd_available(fd))
		return -1; 

	struct file *selected_file = thread_current()->fd_table[fd];
	
	if (selected_file == NULL)
		return -1;

	lock_acquire(&filesys_lock);
	off_t result = file_write(selected_file, buffer, size); 
	lock_release(&filesys_lock); 
	return result;
}

void seek(int fd, unsigned position)
{
	if (fd <= 1 || !fd_available(fd) || position < 0) 
		exit(-1);
	
	struct file *selected_file = thread_current()->fd_table[fd];

	if (selected_file == NULL)
		exit(-1);

	lock_acquire(&filesys_lock);
	file_seek(selected_file, position); 
	lock_release(&filesys_lock); 
}

unsigned tell(int fd)
{
	if (!fd_available(fd))
		exit(-1);

	struct file *selected_file = thread_current()->fd_table[fd];
	if (selected_file == NULL)
		exit(-1);

	lock_acquire(&filesys_lock);
	int result = (int) file_tell(selected_file);
	lock_release(&filesys_lock); 
	return result;
}

void close(int fd)
{
	if (fd < 2 || !fd_available(fd))
		exit(-1);

	struct file *selected_file = thread_current()->fd_table[fd];
	if (selected_file == NULL)
		exit(-1);

	lock_acquire(&filesys_lock);
	file_close(selected_file);
	lock_release(&filesys_lock);

	thread_current()->fd_table[fd] = NULL;
} 