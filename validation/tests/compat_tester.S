/* compat_tester.S — Minimal AArch32 static test binary
 * Exercises compat open/creat/stat/readlink/execve/faccessat syscalls.
 * Usage: compat_tester <path> — runs all tests against <path>.
 * Exit code 0 = all pass, 1 = any fail.
 *
 * Built with: armv7a-linux-androideabi33-clang -static -nostdlib -O2
 */

	.syntax unified
	.arm

	@ syscall numbers (AArch32 EABI)
	.equ SYS_open,		5
	.equ SYS_creat,		8
	.equ SYS_close,		6
	.equ SYS_readlink,	85
	.equ SYS_stat,		106
	.equ SYS_execve,	11
	.equ SYS_faccessat,	334
	.equ SYS_exit,		1
	.equ SYS_write,		4

	@ AT_FDCWD
	.equ AT_FDCWD,		-100

	.text
	.global _start

_start:
	@ r0 = argc, r1 = argv
	ldr	r0, [r1]		@ argc
	ldr	r1, [r1, #4]		@ argv[0] = our path
	cmp	r0, #2
	ldrhs	r4, [r1, #4]		@ r4 = target path (argv[1])
	movlo	r4, r1			@ fallback: use our own path

	mov	r6, #0			@ r6 = failure count

	@ --- Test 1: creat ---
	ldr	r0, =creat_path
	mov	r1, #0x1A4		@ 0644 octal
	mov	r7, #SYS_creat
	svc	#0
	cmp	r0, #0
	bhs	1f
	add	r6, r6, #1
1:
	@ close the fd if creat returned >= 0
	cmp	r0, #0
	movlt	r0, #0
	mov	r7, #SYS_close
	svc	#0

	@ --- Test 2: open (O_RDONLY = 0) ---
	mov	r0, r4
	mov	r1, #0			@ O_RDONLY
	mov	r2, #0			@ mode
	mov	r7, #SYS_open
	svc	#0
	cmp	r0, #0
	bhs	2f
	add	r6, r6, #1
2:
	mov	r7, #SYS_close
	svc	#0

	@ --- Test 3: stat ---
	sub	sp, sp, #128		@ struct stat is ~88 bytes on ARM32
	mov	r0, r4
	mov	r1, sp
	mov	r7, #SYS_stat
	svc	#0
	cmp	r0, #0
	bhs	3f
	add	r6, r6, #1
3:
	add	sp, sp, #128

	@ --- Test 4: readlink (on /proc/self/exe) ---
	sub	sp, sp, #256
	ldr	r0, =proc_exe_path
	mov	r1, sp
	mov	r2, #255
	mov	r7, #SYS_readlink
	svc	#0
	cmp	r0, #0
	bhs	4f
	add	r6, r6, #1
4:
	add	sp, sp, #256

	@ --- Test 5: faccessat (AT_FDCWD, path, R_OK=4, flags=0) ---
	mov	r0, #AT_FDCWD
	mov	r1, r4
	mov	r2, #4			@ R_OK
	mov	r3, #0
	mov	r7, #SYS_faccessat
	svc	#0
	cmp	r0, #0
	bhs	5f
	add	r6, r6, #1
5:

	@ --- Test 6: execve (exec /system/bin/true) ---
	@ This replaces us, so only run if all previous passed
	cmp	r6, #0
	bne	6f
	ldr	r0, =true_path
	ldr	r1, =argv_true
	ldr	r2, =envp_empty
	mov	r7, #SYS_execve
	svc	#0
	@ If execve returns, it failed
	add	r6, r6, #1
6:

	@ Report: write "N\n" where N = number of failures (as ASCII)
	mov	r0, #1			@ stdout
	ldr	r1, =result_buf
	add	r2, r6, #'0'		@ convert to ASCII
	strb	r2, [r1]
	mov	r2, #2			@ length
	mov	r7, #SYS_write
	svc	#0

	mov	r0, r6			@ exit code = failure count
	mov	r7, #SYS_exit
	svc	#0

	.data
creat_path:	.asciz	"/data/local/tmp/bl-test/compat_creat.txt"
proc_exe_path:	.asciz	"/proc/self/exe"
true_path:	.asciz	"/system/bin/true"
argv_true:	.word	true_path
		.word	0
envp_empty:	.word	0
result_buf:	.asciz	"0\n"
