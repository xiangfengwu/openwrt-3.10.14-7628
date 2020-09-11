all: mylibuci

mylibuci: myconfig.o main.o
	$(CC) $(LDFLAGS) main.o myconfig.o -o mylibuci -luci
myconfig.o: myconfig.c
	$(CC) $(CFLAGS) -c myconfig.c

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

clean:
	rm *.o mylibuci

