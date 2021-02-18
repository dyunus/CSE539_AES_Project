EXEC = a.out
CC = g++
CFLAGS = -c -Wall -std=c++11


$(EXEC) : main.o
	$(CC) -o $(EXEC) main.o

main.o : main.cpp main.h
	$(CC) $(CFLAGS) main.cpp

clean :
	rm *.o
