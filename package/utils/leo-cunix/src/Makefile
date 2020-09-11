all: cunix

cunix: cunix.o
	$(CC) $(LDFLAGS) cunix.o -o cunix
cunix.o: cunix.c
	$(CC) $(CFLAGS) -c cunix.c


clean:
	rm *.o cunix

