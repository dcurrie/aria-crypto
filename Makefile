

test: 
	cc -O2 -Wall -Wextra -Wstrict-overflow -std=c99 -o aria -DARIA_TEST aria.c
	./aria -s
