CXX      = clang++
CXXFLAGS = -O3 -std=c++17 -march=native -Wall

.PHONY: all clean gpu

all: solver

solver: solver.cpp enigma.h
	$(CXX) $(CXXFLAGS) -o solver solver.cpp

gpu: solver_gpu

solver_gpu: metal_solver.mm enigma.h
	$(CXX) $(CXXFLAGS) -ObjC++ -framework Metal -framework Foundation -o solver_gpu metal_solver.mm

clean:
	rm -f solver solver_gpu
