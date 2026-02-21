# LSA Whisperer BOF - Makefile
# Cross-compile from Linux using MinGW
#
# Prerequisites:
#   apt install mingw-w64
#
# Usage:
#   make all      - Build all BOF modules
#   make msv1_0   - Build MSV1_0 module only
#   make kerberos - Build Kerberos module only
#   make cloudap  - Build CloudAP module only
#   make clean    - Remove build artifacts

CC_x64 = x86_64-w64-mingw32-gcc
CC_x86 = i686-w64-mingw32-gcc

# BOF compilation flags:
#   -c          Compile only (no linking - BOFs are object files)
#   -Os         Optimize for size (smaller BOF = faster transfer)
#   -DBOF       Define BOF macro for conditional compilation
#   -Wall       Enable all warnings
#   -Wno-unused But suppress unused variable warnings (common in BOFs)
CFLAGS = -c -Os -DBOF -Wall -Wno-unused-variable -Wno-unused-function
INCLUDES = -Iinclude -Isrc/common

OUTDIR = build

.PHONY: all msv1_0 kerberos cloudap clean

all: msv1_0 kerberos cloudap

# MSV1_0 Module (DPAPI cred key, NTLMv1 generation)
msv1_0: $(OUTDIR)/msv1_0_bof.x64.o $(OUTDIR)/msv1_0_bof.x86.o

$(OUTDIR)/msv1_0_bof.x64.o: src/msv1_0/msv1_0_bof.c src/common/lsa_common.c include/*.h
	@mkdir -p $(OUTDIR)
	$(CC_x64) $(CFLAGS) $(INCLUDES) -o $@ src/msv1_0/msv1_0_bof.c

$(OUTDIR)/msv1_0_bof.x86.o: src/msv1_0/msv1_0_bof.c src/common/lsa_common.c include/*.h
	@mkdir -p $(OUTDIR)
	$(CC_x86) $(CFLAGS) $(INCLUDES) -o $@ src/msv1_0/msv1_0_bof.c

# Kerberos Module (klist, dump, PTT, purge, policies)
kerberos: $(OUTDIR)/kerberos_bof.x64.o $(OUTDIR)/kerberos_bof.x86.o

$(OUTDIR)/kerberos_bof.x64.o: src/kerberos/kerberos_bof.c src/common/lsa_common.c include/*.h
	@mkdir -p $(OUTDIR)
	$(CC_x64) $(CFLAGS) $(INCLUDES) -o $@ src/kerberos/kerberos_bof.c

$(OUTDIR)/kerberos_bof.x86.o: src/kerberos/kerberos_bof.c src/common/lsa_common.c include/*.h
	@mkdir -p $(OUTDIR)
	$(CC_x86) $(CFLAGS) $(INCLUDES) -o $@ src/kerberos/kerberos_bof.c

# CloudAP Module (SSO cookies, cloud info)
cloudap: $(OUTDIR)/cloudap_bof.x64.o $(OUTDIR)/cloudap_bof.x86.o

$(OUTDIR)/cloudap_bof.x64.o: src/cloudap/cloudap_bof.c src/common/lsa_common.c include/*.h
	@mkdir -p $(OUTDIR)
	$(CC_x64) $(CFLAGS) $(INCLUDES) -o $@ src/cloudap/cloudap_bof.c

$(OUTDIR)/cloudap_bof.x86.o: src/cloudap/cloudap_bof.c src/common/lsa_common.c include/*.h
	@mkdir -p $(OUTDIR)
	$(CC_x86) $(CFLAGS) $(INCLUDES) -o $@ src/cloudap/cloudap_bof.c

clean:
	rm -rf $(OUTDIR)

# Quick test: verify compilation succeeds
test: all
	@echo "=== Build Summary ==="
	@ls -la $(OUTDIR)/*.o 2>/dev/null || echo "No output files"
	@echo "=== Object file sizes ==="
	@for f in $(OUTDIR)/*.o; do printf "  %-35s %s bytes\n" "$$f" "$$(wc -c < $$f)"; done
