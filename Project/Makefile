CC = gcc
CFLAGS = -Wall
LIBS = -lpcap

FIREWALL = firewall
SENDER = sender

all: $(FIREWALL) $(SENDER)

$(FIREWALL): firewall.c
	$(CC) $(CFLAGS) -o $(FIREWALL) firewall.c $(LIBS)

$(SENDER): sender.c
	$(CC) $(CFLAGS) -o $(SENDER) sender.c $(LIBS)

clean:
	rm -f $(FIREWALL) $(SENDER)
