all: fibacap

OBJ=main.o fbc_address.o fbc_packet.o fbc_ether.o fbc_ip.o fbc_arp.o 

fibacap: $(OBJ)
	gcc -Wall -o fibacap $(OBJ)

main.o: main.c fbc_common.h fbc_packet.h
	gcc -Wall -c main.c

fbc_packet.o: fbc_packet.h fbc_packet.c fbc_packet.h
	gcc -Wall -c fbc_packet.c

fbc_address.o: fbc_address.h fbc_address.c fbc_common.h
	gcc -Wall -c fbc_address.c

fbc_ether.o: fbc_ether.c fbc_ether.h fbc_common.h fbc_packet.h fbc_address.h
	gcc -Wall -c fbc_ether.c

fbc_ip.o: fbc_ip.h fbc_ip.c fbc_common.h fbc_packet.h fbc_address.h
	gcc -Wall -c fbc_ip.c

fbc_arp.o: fbc_arp.h fbc_arp.c fbc_common.h fbc_packet.h fbc_address.h
	gcc -Wall -c fbc_arp.c

run: 
	./fibacap

clean:
	rm -f *.o *~

ct:
	rm -f *~
