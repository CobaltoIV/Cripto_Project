# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.19

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
CMAKE_SOURCE_DIR = /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests

# Include any dependencies generated for this target.
include CompFunc/CMakeFiles/CompFunc.dir/depend.make

# Include the progress variables for this target.
include CompFunc/CMakeFiles/CompFunc.dir/progress.make

# Include the compile flags for this target's objects.
include CompFunc/CMakeFiles/CompFunc.dir/flags.make

CompFunc/CMakeFiles/CompFunc.dir/comparator.cpp.o: CompFunc/CMakeFiles/CompFunc.dir/flags.make
CompFunc/CMakeFiles/CompFunc.dir/comparator.cpp.o: CompFunc/comparator.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CompFunc/CMakeFiles/CompFunc.dir/comparator.cpp.o"
	cd /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests/CompFunc && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/CompFunc.dir/comparator.cpp.o -c /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests/CompFunc/comparator.cpp

CompFunc/CMakeFiles/CompFunc.dir/comparator.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/CompFunc.dir/comparator.cpp.i"
	cd /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests/CompFunc && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests/CompFunc/comparator.cpp > CMakeFiles/CompFunc.dir/comparator.cpp.i

CompFunc/CMakeFiles/CompFunc.dir/comparator.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/CompFunc.dir/comparator.cpp.s"
	cd /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests/CompFunc && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests/CompFunc/comparator.cpp -o CMakeFiles/CompFunc.dir/comparator.cpp.s

# Object files for target CompFunc
CompFunc_OBJECTS = \
"CMakeFiles/CompFunc.dir/comparator.cpp.o"

# External object files for target CompFunc
CompFunc_EXTERNAL_OBJECTS =

CompFunc/libCompFunc.a: CompFunc/CMakeFiles/CompFunc.dir/comparator.cpp.o
CompFunc/libCompFunc.a: CompFunc/CMakeFiles/CompFunc.dir/build.make
CompFunc/libCompFunc.a: CompFunc/CMakeFiles/CompFunc.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libCompFunc.a"
	cd /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests/CompFunc && $(CMAKE_COMMAND) -P CMakeFiles/CompFunc.dir/cmake_clean_target.cmake
	cd /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests/CompFunc && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/CompFunc.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CompFunc/CMakeFiles/CompFunc.dir/build: CompFunc/libCompFunc.a

.PHONY : CompFunc/CMakeFiles/CompFunc.dir/build

CompFunc/CMakeFiles/CompFunc.dir/clean:
	cd /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests/CompFunc && $(CMAKE_COMMAND) -P CMakeFiles/CompFunc.dir/cmake_clean.cmake
.PHONY : CompFunc/CMakeFiles/CompFunc.dir/clean

CompFunc/CMakeFiles/CompFunc.dir/depend:
	cd /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests/CompFunc /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests/CompFunc /mnt/c/Users/ricas/Documents/IST/5ºano/1sem/Cripto/Project/Git/Cripto_Project/Tests/CompFunc/CMakeFiles/CompFunc.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CompFunc/CMakeFiles/CompFunc.dir/depend

