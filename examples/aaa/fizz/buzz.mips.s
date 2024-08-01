main:
	# Locals:
	#	$t0: i
	#	$t1: i % 3
	#	$t2: i % 5

main__loop_i__init:
	li	$t0, 1					# i = 0;

main__loop_i__body:					# while (1) {
	rem	$t1, $t0, 3				#   i % 3
	rem	$t2, $t0, 5				#   i % 5

	bnez	$t1, main__loop_i__not_fizz_buzz	#   if (i % 3 == 0
	bnez	$t2, main__loop_i__not_fizz_buzz	#       && i % 5 == 0) {

	li	$a0, fizz_buzz_str
	li	$v0, 4					#     syscall 4: print_str
	syscall						#     printf("fizz buzz!");
	b	main__loop_i__step			#     continue;

main__loop_i__not_fizz_buzz:				#   }
	beqz	$t1, main__loop_i__fizz			#   if (i % 3 == 0) { ...
	beqz	$t2, main__loop_i__buzz			#   if (i % 5 == 0) { ...

	move	$a0, $t0
	li	$v0, 1					#   syscall 1: print_int
	syscall						#   printf("%d", i);

	li	$a0, '\n'
	li	$v0, 11					#   syscall 11: print_char
	syscall						#   putchar('\n');

	b	main__loop_i__step			#   continue;

main__loop_i__fizz:					#   if (i % 3 == 0) {
	li	$a0, fizz_str
	li	$v0, 4					#     syscall 4: print_str
	syscall						#     printf("fizz...\n");
	b	main__loop_i__step			#     continue;

main__loop_i__buzz:					#   } else if (i % 5 == 0) {
	li	$a0, buzz_str
	li	$v0, 4					#     syscall 4: print_str
	syscall						#     printf("buzz?\n");
	b	main__loop_i__step			#     continue;

main__loop_i__step:					#   }
	addi	$t0, $t0, 1				#   i++;
	b	main__loop_i__body			# }


fizz_buzz_str:
	.asciiz	"fizz buzz!\n"
fizz_str:
	.asciiz "fizz...\n"
buzz_str:
	.asciiz	"buzz?\n"
