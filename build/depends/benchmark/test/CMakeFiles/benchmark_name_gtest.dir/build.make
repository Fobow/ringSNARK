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
include depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/compiler_depend.make

# Include the progress variables for this target.
include depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/progress.make

# Include the compile flags for this target's objects.
include depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/flags.make

depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.o: depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/flags.make
depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.o: ../depends/benchmark/test/benchmark_name_gtest.cc
depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.o: depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yancheng/code/ringSNARK/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.o"
	cd /home/yancheng/code/ringSNARK/build/depends/benchmark/test && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.o -MF CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.o.d -o CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.o -c /home/yancheng/code/ringSNARK/depends/benchmark/test/benchmark_name_gtest.cc

depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.i"
	cd /home/yancheng/code/ringSNARK/build/depends/benchmark/test && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yancheng/code/ringSNARK/depends/benchmark/test/benchmark_name_gtest.cc > CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.i

depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.s"
	cd /home/yancheng/code/ringSNARK/build/depends/benchmark/test && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yancheng/code/ringSNARK/depends/benchmark/test/benchmark_name_gtest.cc -o CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.s

# Object files for target benchmark_name_gtest
benchmark_name_gtest_OBJECTS = \
"CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.o"

# External object files for target benchmark_name_gtest
benchmark_name_gtest_EXTERNAL_OBJECTS =

bin/benchmark_name_gtest: depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/benchmark_name_gtest.cc.o
bin/benchmark_name_gtest: depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/build.make
bin/benchmark_name_gtest: depends/benchmark/src/libbenchmark.a
bin/benchmark_name_gtest: lib/libgmock_main.a
bin/benchmark_name_gtest: lib/libgmock.a
bin/benchmark_name_gtest: lib/libgtest.a
bin/benchmark_name_gtest: depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/yancheng/code/ringSNARK/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../../../bin/benchmark_name_gtest"
	cd /home/yancheng/code/ringSNARK/build/depends/benchmark/test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/benchmark_name_gtest.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/build: bin/benchmark_name_gtest
.PHONY : depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/build

depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/clean:
	cd /home/yancheng/code/ringSNARK/build/depends/benchmark/test && $(CMAKE_COMMAND) -P CMakeFiles/benchmark_name_gtest.dir/cmake_clean.cmake
.PHONY : depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/clean

depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/depend:
	cd /home/yancheng/code/ringSNARK/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yancheng/code/ringSNARK /home/yancheng/code/ringSNARK/depends/benchmark/test /home/yancheng/code/ringSNARK/build /home/yancheng/code/ringSNARK/build/depends/benchmark/test /home/yancheng/code/ringSNARK/build/depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/benchmark/test/CMakeFiles/benchmark_name_gtest.dir/depend
