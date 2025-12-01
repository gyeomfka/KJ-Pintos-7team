#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* See [8254] for hardware details of the 8254 timer chip. */

/**
이 코드는 8254 프로그램 가능 인터벌 타이머(PIT, Programmable Interval Timer)를 제어합니다.
8254 칩의 하드웨어 세부 정보는 [8254 문서]를 참고하라는 뜻입니다.
*/

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
static int64_t ticks;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */

/**
한 타이머 틱(tick) 동안 수행 가능한 반복(loop) 횟수를 저장하는 변수입니다.
timer_calibrate() 함수에서 실제 CPU 속도에 맞게 보정됩니다.
*/
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops (unsigned loops);
static void busy_wait (int64_t loops);
static void real_time_sleep (int64_t num, int32_t denom);

/* Sets up the 8254 Programmable Interval Timer (PIT) to
   interrupt PIT_FREQ times per second, and registers the
   corresponding interrupt. */
/*
의미:
8254 PIT을 설정하여 1초에 TIMER_FREQ번 인터럽트를 발생시키도록 구성하고,
이 타이머 인터럽트를 커널에 등록합니다.
*/
void
timer_init (void) {
	/* 8254 input frequency divided by TIMER_FREQ, rounded to
	   nearest. */
	uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;

	outb (0x43, 0x34);    /* CW: counter 0, LSB then MSB, mode 2, binary. */
	outb (0x40, count & 0xff);
	outb (0x40, count >> 8);

	intr_register_ext (0x20, timer_interrupt, "8254 Timer");
}

/* Calibrates loops_per_tick, used to implement brief delays. */
/*
loops_per_tick 값을 보정(calibration)합니다.
이는 CPU의 속도에 맞는 정확한 “짧은 시간 지연(delay)”을 구현하는 데 사용됩니다.
*/
void
timer_calibrate (void) {
	unsigned high_bit, test_bit;

	ASSERT (intr_get_level () == INTR_ON);
	printf ("Calibrating timer...  ");

	/* Approximate loops_per_tick as the largest power-of-two
	   still less than one timer tick. */
	loops_per_tick = 1u << 10;
	while (!too_many_loops (loops_per_tick << 1)) {
		loops_per_tick <<= 1;
		ASSERT (loops_per_tick != 0);
	}

	/* Refine the next 8 bits of loops_per_tick. */
	high_bit = loops_per_tick;
	for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
		if (!too_many_loops (high_bit | test_bit))
			loops_per_tick |= test_bit;

	printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
/*
운영체제가 부팅된 이후 지난 타이머 틱의 개수를 반환합니다.
(즉, 부팅 후 경과된 시간의 단위)
*/
int64_t
timer_ticks (void) {
	enum intr_level old_level = intr_disable ();
	int64_t t = ticks;
	intr_set_level (old_level);
	barrier ();
	return t;
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
int64_t
timer_elapsed (int64_t then) {
	return timer_ticks () - then;
}

/* Suspends execution for approximately TICKS timer ticks. */
/*
 * 현재는 busy waiting 방식으로 동작한다
현재 시간 확인 -> 루프를 돌며 -> thread_yield() 호출 -> 충분한 시간이 지날 때까지 대기 
*/
/**
 * 바로 sleep list 로 가기전에 ready list에 존재한다 ?
 * -> running 중인 스레드이므로 ready_list 에는 포함되지 않는다.
*/
void
timer_sleep (int64_t ticks) { //param == 스레드를 잠들게 할 타이머 틱 수 
	/**
	 * 현재 시스템의 타이머 틱 수를 가져와 start에 저장
	 * 잠들기 시작한 시점을 기록하는 부분
	 * timer_ticks() -> 현재까지 지난 틱 수를 반환하는 함수
	*/
	int64_t start = timer_ticks (); 
	/**
	 * 인터럽트가 켜져 있는지 확인하는 검증
		intr_get_level()은 현재 인터럽트 상태를 반환하고, INTR_ON은 켜져 있는 상태를 의미합니다.
	*/
	ASSERT (intr_get_level () == INTR_ON);
	/**
	 * time_elapsed(start) -> start 시점 이후 경과한 틱 수를 반환
	 * 	아직 지정된 tick 만큼 시간이 지나지 않았으면 루프를 계속 돌림
	*/
	/* 
		ASIS:
	*/
	// while (timer_elapsed (start) < ticks)
	// 	thread_yield ();
	/**
	 * TODO: ticks동안 block list 에 해당 thread를 넣어둔다.
	*/
	// thread_block();
	// struct thread *this_t = thread_current ();
	// this_t->wakeup_ticks = start + ticks;
	thread_sleep(start + ticks);
}

/* Suspends execution for approximately MS milliseconds. */
void
timer_msleep (int64_t ms) {
	real_time_sleep (ms, 1000);
}

/* Suspends execution for approximately US microseconds. */
void
timer_usleep (int64_t us) {
	real_time_sleep (us, 1000 * 1000);
}

/* Suspends execution for approximately NS nanoseconds. */
void
timer_nsleep (int64_t ns) {
	real_time_sleep (ns, 1000 * 1000 * 1000);
}

/* Prints timer statistics. */
void
timer_print_stats (void) {
	printf ("Timer: %"PRId64" ticks\n", timer_ticks ());
}

/* Timer interrupt handler. */
/**
 * 매 틱마다 인터럽트를 발생시켜 커널로 제어권을 넘김
 * -> 이 개념을 알아야 "얼마나 기다릴지"를 시간 단위로 측정할 수 있음
*/
static void
timer_interrupt (struct intr_frame *args UNUSED) {
	ticks++;
	thread_tick ();
	// enum intr_level old_level = intr_disable();
	thread_awake(ticks);
	// intr_set_level(old_level);
}

/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
static bool
too_many_loops (unsigned loops) {
	/* Wait for a timer tick. */
	int64_t start = ticks;
	while (ticks == start)
		barrier ();

	/* Run LOOPS loops. */
	start = ticks;
	busy_wait (loops);

	/* If the tick count changed, we iterated too long. */
	barrier ();
	return start != ticks;
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE
busy_wait (int64_t loops) {
	while (loops-- > 0)
		barrier ();
}

/* Sleep for approximately NUM/DENOM seconds. */
static void
real_time_sleep (int64_t num, int32_t denom) {
	/* Convert NUM/DENOM seconds into timer ticks, rounding down.

	   (NUM / DENOM) s
	   ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
	   1 s / TIMER_FREQ ticks
	   */
	int64_t ticks = num * TIMER_FREQ / denom;

	ASSERT (intr_get_level () == INTR_ON);
	if (ticks > 0) {
		/* We're waiting for at least one full timer tick.  Use
		   timer_sleep() because it will yield the CPU to other
		   processes. */
		timer_sleep (ticks);
	} else {
		/* Otherwise, use a busy-wait loop for more accurate
		   sub-tick timing.  We scale the numerator and denominator
		   down by 1000 to avoid the possibility of overflow. */
		ASSERT (denom % 1000 == 0);
		busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
	}
}
