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
include depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/compiler_depend.make

# Include the progress variables for this target.
include depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/progress.make

# Include the compile flags for this target's objects.
include depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/flags.make

depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/test/example.o: depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/flags.make
depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/test/example.o: depends/SEAL/thirdparty/zlib-src/test/example.c
depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/test/example.o: depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yancheng/code/ringSNARK/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/test/example.o"
	cd /home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/zlib-build && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/test/example.o -MF CMakeFiles/example64.dir/test/example.o.d -o CMakeFiles/example64.dir/test/example.o -c /home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/zlib-src/test/example.c

depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/test/example.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/example64.dir/test/example.i"
	cd /home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/zlib-build && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/zlib-src/test/example.c > CMakeFiles/example64.dir/test/example.i

depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/test/example.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/example64.dir/test/example.s"
	cd /home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/zlib-build && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/zlib-src/test/example.c -o CMakeFiles/example64.dir/test/example.s

# Object files for target example64
example64_OBJECTS = \
"CMakeFiles/example64.dir/test/example.o"

# External object files for target example64
example64_EXTERNAL_OBJECTS =

depends/SEAL/bin/example64: depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/test/example.o
depends/SEAL/bin/example64: depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/build.make
depends/SEAL/bin/example64: depends/SEAL/lib/libz.so.1.2.13
depends/SEAL/bin/example64: depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/yancheng/code/ringSNARK/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable ../../bin/example64"
	cd /home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/zlib-build && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/example64.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/build: depends/SEAL/bin/example64
.PHONY : depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/build

depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/clean:
	cd /home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/zlib-build && $(CMAKE_COMMAND) -P CMakeFiles/example64.dir/cmake_clean.cmake
.PHONY : depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/clean

depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/depend:
	cd /home/yancheng/code/ringSNARK/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yancheng/code/ringSNARK /home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/zlib-src /home/yancheng/code/ringSNARK/build /home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/zlib-build /home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/SEAL/thirdparty/zlib-build/CMakeFiles/example64.dir/depend

