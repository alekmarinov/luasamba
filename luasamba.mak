# modules/c/io/net/luasamba/luasamba.mak

TARGET=luasamba
VERSION=1.0
OBJS=luasamba.o

SAMBA_DIR=/usr
SAMBA_DIR_INC=$(SAMBA_DIR)/include
SAMBA_DIR_LIB=$(SAMBA_DIR)/lib

EXTRA_INCS=-I$(SAMBA_DIR_INC)
EXTRA_LIBS=-I$(SAMBA_DIR_LIB) -lsmbclient
