LDLIBS += -lpcap

all: deauth_attack

deauth_attack: deauth_attack.o

deauth_attack.o: deauth_attack.c

clean:
	rm -f deauth_attack.o deauth_attack