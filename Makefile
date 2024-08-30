CC ?= cc
PAM_CFLAGS = $(shell pkg-config --cflags pam)
PAM_LIBS = $(shell pkg-config --libs pam)
PAM_LIBDIR = $(shell pkg-config --variable=libdir pam)
SECURITY_DIR = $(PAM_LIBDIR)/security
INSTALL = install
RM = rm

.PHONY: all clean
default: all

clean:
	rm -f pam_dsba.o pam_dsba.so

pam_dsba.o: pam_dsba.c
	$(CC) -Wall -Wextra $(PAM_CFLAGS) -fPIC $(CFLAGS) -c pam_dsba.c

pam_dsba.so: pam_dsba.o
	$(CC) -shared $(PAM_LIBS) $(LDLIBS) $(LDFLAGS) -o pam_dsba.so pam_dsba.o

all: pam_dsba.so

install: pam_dsba.so
	install -o 0 -g 0 -m 755 -t $(SECURITY_DIR) pam_dsba.so

uninstall:
	rm -f $(SECURITY_DIR)/pam_dsba.so
