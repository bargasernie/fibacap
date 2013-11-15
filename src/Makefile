all: fibacap

OBJ=main.o analysis.o ether_analysis.o 

fibacap: $(OBJ)
	gcc -Wall -o fibacap $(OBJ)

main.o: main.c
	gcc -Wall -c main.c

analysis.o: analysis.c analysis.h
	gcc -Wall -c analysis.c

ether_analysis.o: ether_analysis.c ether_analysis.h
	gcc -Wall -c ether_analysis.c

run: 
	./fibacap

clean:
	rm -f *.o *~
