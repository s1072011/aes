PROJDIR := $(CURDIR)
DIST := $(PROJDIR)/dist
GENERATE_DIR := $(PROJDIR)/generate_random_byte_stream
CFLAGS := -Wall -Wextra -Wpedantic -Wformat -Wshadow -Wnull-dereference -Wno-unused-parameter -O3 --std=c++14
SOURCEFILES := aes_strategy.cpp aes_ecb.cpp aes_cbc.cpp aes_cfb.cpp aes_ofb.cpp aes_ctr.cpp aes.cpp test.cpp
OBJFILES := $(patsubst %.cpp,%.o,$(SOURCEFILES))

ifeq ($(OS),Windows_NT)
  RM := del
else
  RM := rm -f
endif

build:
	echo $(DIST)
	g++ -c $(CFLAGS) $(SOURCEFILES)
	g++ -o $(DIST)/aes $(OBJFILES)
build-generate:
	g++ generate.cpp -o $(GENERATE_DIR)/generate
build-debug:
	g++ -g -c $(CFLAGS) $(SOURCEFILES)
	g++ -g -o $(DIST)/aes-debug $(OBJFILES)
clean:
	$(RM) *.o $(DIST)/*.exe $(DIST)/*.a $(DIST)/aes $(DIST)/aes-static $(DIST)/aes-debug $(GENERATE_DIR)/*.exe $(GENERATE_DIR)/generate
