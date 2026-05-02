# Builds the elfloader samples and runs them. Loader TUs are compiled with
# -nostdinc++ to enforce the no-STL invariant at build time.

ROOT      := $(abspath ../..)
ELFLOADER := $(ROOT)/elfloader
BUILD     := $(ROOT)/build/elf

CXX      := g++
CC       := gcc

LOADER_CXXFLAGS := -std=c++20 -O2 -Wall -Wextra -fno-rtti -fno-exceptions -nostdinc++ -I$(ROOT)
SAMPLE_CXXFLAGS := -std=c++20 -O2 -Wall -Wextra -I$(ROOT)
SAMPLE_CFLAGS   := -O2 -Wall -fPIC

LOADER_OBJS := $(BUILD)/loader.o $(BUILD)/file_loader.o $(BUILD)/module_list.o

SAMPLE_SO    := $(BUILD)/sample.so
LOAD_SO_EXE  := $(BUILD)/load_so
SAMPLE_EXE   := $(BUILD)/sample_exe
LOAD_EXE_EXE := $(BUILD)/load_exe

.PHONY: all run run_so run_exe clean

all: $(SAMPLE_SO) $(LOAD_SO_EXE) $(SAMPLE_EXE) $(LOAD_EXE_EXE)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/loader.o: $(ELFLOADER)/loader.cc $(ELFLOADER)/loader.h | $(BUILD)
	$(CXX) $(LOADER_CXXFLAGS) -c $< -o $@

$(BUILD)/file_loader.o: $(ELFLOADER)/file_loader.cc $(ELFLOADER)/file_loader.h | $(BUILD)
	$(CXX) $(LOADER_CXXFLAGS) -c $< -o $@

$(BUILD)/module_list.o: $(ELFLOADER)/module_list.cc $(ELFLOADER)/module_list.h $(ELFLOADER)/loader.h | $(BUILD)
	$(CXX) $(LOADER_CXXFLAGS) -c $< -o $@

$(SAMPLE_SO): sample_so/sample.c | $(BUILD)
	$(CC) $(SAMPLE_CFLAGS) -shared -nostdlib -fvisibility=hidden $< -o $@

$(LOAD_SO_EXE): load_so/main.cc $(LOADER_OBJS) | $(BUILD)
	$(CXX) $(SAMPLE_CXXFLAGS) $< $(LOADER_OBJS) -ldl -o $@

$(SAMPLE_EXE): sample_exe/sample.c | $(BUILD)
	$(CC) -O2 -Wall -fPIC -nostdlib -fno-stack-protector -static-pie $< -o $@

$(LOAD_EXE_EXE): load_exe/main.cc $(LOADER_OBJS) | $(BUILD)
	$(CXX) $(SAMPLE_CXXFLAGS) $< $(LOADER_OBJS) -o $@

run: run_so run_exe

run_so: $(LOAD_SO_EXE) $(SAMPLE_SO)
	@echo "=== load_so test ==="
	$(LOAD_SO_EXE) $(SAMPLE_SO)

run_exe: $(LOAD_EXE_EXE) $(SAMPLE_EXE)
	@echo "=== load_exe test ==="
	$(LOAD_EXE_EXE) $(SAMPLE_EXE)

clean:
	rm -rf $(BUILD)
