# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/yancheng/code/ringSNARK

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/yancheng/code/ringSNARK/build

# Include any dependencies generated for this target.
include depends/SEAL-Polytools/CMakeFiles/polytools.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include depends/SEAL-Polytools/CMakeFiles/polytools.dir/compiler_depend.make

# Include the progress variables for this target.
include depends/SEAL-Polytools/CMakeFiles/polytools.dir/progress.make

# Include the compile flags for this target's objects.
include depends/SEAL-Polytools/CMakeFiles/polytools.dir/flags.make

depends/SEAL-Polytools/CMakeFiles/polytools.dir/src/poly_arith.cpp.o: depends/SEAL-Polytools/CMakeFiles/polytools.dir/flags.make
depends/SEAL-Polytools/CMakeFiles/polytools.dir/src/poly_arith.cpp.o: ../depends/SEAL-Polytools/src/poly_arith.cpp
depends/SEAL-Polytools/CMakeFiles/polytools.dir/src/poly_arith.cpp.o: depends/SEAL-Polytools/CMakeFiles/polytools.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yancheng/code/ringSNARK/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/SEAL-Polytools/CMakeFiles/polytools.dir/src/poly_arith.cpp.o"
	cd /home/yancheng/code/ringSNARK/build/depends/SEAL-Polytools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT depends/SEAL-Polytools/CMakeFiles/polytools.dir/src/poly_arith.cpp.o -MF CMakeFiles/polytools.dir/src/poly_arith.cpp.o.d -o CMakeFiles/polytools.dir/src/poly_arith.cpp.o -c /home/yancheng/code/ringSNARK/depends/SEAL-Polytools/src/poly_arith.cpp

depends/SEAL-Polytools/CMakeFiles/polytools.dir/src/poly_arith.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/polytools.dir/src/poly_arith.cpp.i"
	cd /home/yancheng/code/ringSNARK/build/depends/SEAL-Polytools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yancheng/code/ringSNARK/depends/SEAL-Polytools/src/poly_arith.cpp > CMakeFiles/polytools.dir/src/poly_arith.cpp.i

depends/SEAL-Polytools/CMakeFiles/polytools.dir/src/poly_arith.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/polytools.dir/src/poly_arith.cpp.s"
	cd /home/yancheng/code/ringSNARK/build/depends/SEAL-Polytools && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yancheng/code/ringSNARK/depends/SEAL-Polytools/src/poly_arith.cpp -o CMakeFiles/polytools.dir/src/poly_arith.cpp.s

# Object files for target polytools
polytools_OBJECTS = \
"CMakeFiles/polytools.dir/src/poly_arith.cpp.o"

# External object files for target polytools
polytools_EXTERNAL_OBJECTS =

depends/SEAL-Polytools/libpolytools.a: depends/SEAL-Polytools/CMakeFiles/polytools.dir/src/poly_arith.cpp.o
depends/SEAL-Polytools/libpolytools.a: depends/SEAL-Polytools/CMakeFiles/polytools.dir/build.make
depends/SEAL-Polytools/libpolytools.a: depends/SEAL-Polytools/CMakeFiles/polytools.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/yancheng/code/ringSNARK/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libpolytools.a"
	cd /home/yancheng/code/ringSNARK/build/depends/SEAL-Polytools && $(CMAKE_COMMAND) -P CMakeFiles/polytools.dir/cmake_clean_target.cmake
	cd /home/yancheng/code/ringSNARK/build/depends/SEAL-Polytools && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/polytools.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/SEAL-Polytools/CMakeFiles/polytools.dir/build: depends/SEAL-Polytools/libpolytools.a
.PHONY : depends/SEAL-Polytools/CMakeFiles/polytools.dir/build

depends/SEAL-Polytools/CMakeFiles/polytools.dir/clean:
	cd /home/yancheng/code/ringSNARK/build/depends/SEAL-Polytools && $(CMAKE_COMMAND) -P CMakeFiles/polytools.dir/cmake_clean.cmake
.PHONY : depends/SEAL-Polytools/CMakeFiles/polytools.dir/clean

depends/SEAL-Polytools/CMakeFiles/polytools.dir/depend:
	cd /home/yancheng/code/ringSNARK/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yancheng/code/ringSNARK /home/yancheng/code/ringSNARK/depends/SEAL-Polytools /home/yancheng/code/ringSNARK/build /home/yancheng/code/ringSNARK/build/depends/SEAL-Polytools /home/yancheng/code/ringSNARK/build/depends/SEAL-Polytools/CMakeFiles/polytools.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/SEAL-Polytools/CMakeFiles/polytools.dir/depend

