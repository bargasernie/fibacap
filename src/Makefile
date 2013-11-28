all: fibacap

FILTER_OBJ=fbc_filter_ether.o
OBJ=main.o fbc_address.o fbc_packet.o fbc_ether.o fbc_ip.o fbc_arp.o fbc_tcp.o fbc_udp.o fbc_filter.o fbc_pf.o fbc_lib.o $(FILTER_OBJ)

fibacap: $(OBJ)
	gcc -Wall -o fibacap $(OBJ)

main.o: main.c fbc_common.h fbc_packet.h
	gcc -Wall -c main.c

fbc_packet.o: fbc_packet.h fbc_packet.c fbc_packet.h
	gcc -Wall -c fbc_packet.c

fbc_lib.o: fbc_lib.h fbc_lib.c
	gcc -Wall -c fbc_lib.c

fbc_address.o: fbc_address.h fbc_address.c fbc_common.h
	gcc -Wall -c fbc_address.c

fbc_filter.o: fbc_filter.h fbc_filter.c fbc_packet.h
	gcc -Wall -c fbc_filter.c

fbc_pf.o: fbc_pf.h fbc_pf.c fbc_filter.h 
	gcc -Wall -c fbc_pf.c

fbc_ether.o: fbc_ether.c fbc_ether.h fbc_common.h fbc_packet.h fbc_address.h
	gcc -Wall -c fbc_ether.c

fbc_ip.o: fbc_ip.h fbc_ip.c fbc_common.h fbc_packet.h fbc_address.h
	gcc -Wall -c fbc_ip.c

fbc_arp.o: fbc_arp.h fbc_arp.c fbc_common.h fbc_packet.h fbc_address.h
	gcc -Wall -c fbc_arp.c

fbc_tcp.o: fbc_tcp.h fbc_tcp.c fbc_common.h fbc_packet.h fbc_address.h
	gcc -Wall -c fbc_tcp.c

fbc_udp.o: fbc_udp.h fbc_tcp.c fbc_common.h fbc_packet.h fbc_address.h
	gcc -Wall -c fbc_udp.c

fbc_filter_ether.o: fbc_filter_ether.h fbc_filter_ether.c fbc_packet.h fbc_lib.h
	gcc -Wall -c fbc_filter_ether.c

run: 
	./fibacap

clean:
	rm -f *.o *~

ct:
	rm -f *~
