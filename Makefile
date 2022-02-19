SOURCES = $(wildcard *.cpp)
OBJECTS = $(SOURCES:.cpp=.o)
BINS = $(SOURCES:.cpp=)

CXXFLAGS += -std=c++17

.PHONY: all clean

all: $(BINS)

clean:
	$(RM) $(OBJECTS) $(BINS)
