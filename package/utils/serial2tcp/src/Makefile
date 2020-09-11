serial2tcp: main.o TCPClient.o SerialPort.o
	gcc main.o TCPClient.o SerialPort.o -o serial2tcp -lpthread

main.o:main.c 
	gcc -c main.c -lpthread
	
SerialPort.o:SerialPort.c
	gcc -c SerialPort.c

TCPClient.o:TCPClient.c
	gcc -c TCPClient.c

clean:
	rm -rf *.o main serial2tcp
