# ebpf/Makefile
# Build target for CO-RE (optional, not used in BCC mode)
# BCC compiles the C source at runtime from Python.
# This Makefile is provided for static analysis / future CO-RE migration.

CLANG ?= clang
BPFTOOL ?= bpftool

.PHONY: all check verify clean

all: check

check:
	@echo "Verifying BPF LSM hooks exist on running kernel..."
	@echo ""
	@echo "=== /sys/kernel/security/lsm ==="
	@cat /sys/kernel/security/lsm 2>/dev/null || echo "FILE NOT FOUND"
	@echo ""
	@echo "=== BTF hook verification ==="
	@for hook in bpf_lsm_file_open bpf_lsm_inode_create bpf_lsm_bprm_check_security bpf_lsm_socket_connect; do \
	  if $(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep -q "$$hook"; then \
	    echo "  ✓ BTF: $$hook"; \
	  elif grep -q "$$hook" /proc/kallsyms 2>/dev/null; then \
	    echo "  ✓ kallsyms: $$hook"; \
	  else \
	    echo "  ✗ NOT FOUND: $$hook"; \
	  fi; \
	done
	@echo ""
	@echo "=== BPF feature probe (LSM) ==="
	@$(BPFTOOL) feature probe 2>/dev/null | grep -i lsm || echo "(bpftool feature probe unavailable)"

verify: check

# Lint-check the BPF C source with clang (no full compile needed for BCC mode)
lint:
	@echo "Checking BPF C syntax..."
	$(CLANG) -fsyntax-only \
	  -target bpf \
	  -D__KERNEL__ \
	  -D__BPF_TRACING__ \
	  -I/usr/include \
	  lsm_policy.c 2>&1 || echo "(syntax check done – some errors expected without full kernel headers)"

clean:
	rm -f *.o *.ll
