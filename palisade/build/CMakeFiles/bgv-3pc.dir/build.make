# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.21

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
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.21.1/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.21.1/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/tanmay.ghai/amppere/palisade

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/tanmay.ghai/amppere/palisade/build

# Include any dependencies generated for this target.
include CMakeFiles/bgv-3pc.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/bgv-3pc.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/bgv-3pc.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/bgv-3pc.dir/flags.make

CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.o: CMakeFiles/bgv-3pc.dir/flags.make
CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.o: ../psi_bgvrns_3pc.cpp
CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.o: CMakeFiles/bgv-3pc.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/tanmay.ghai/amppere/palisade/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.o -MF CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.o.d -o CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.o -c /Users/tanmay.ghai/amppere/palisade/psi_bgvrns_3pc.cpp

CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/tanmay.ghai/amppere/palisade/psi_bgvrns_3pc.cpp > CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.i

CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/tanmay.ghai/amppere/palisade/psi_bgvrns_3pc.cpp -o CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.s

# Object files for target bgv-3pc
bgv__3pc_OBJECTS = \
"CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.o"

# External object files for target bgv-3pc
bgv__3pc_EXTERNAL_OBJECTS =

bgv-3pc: CMakeFiles/bgv-3pc.dir/psi_bgvrns_3pc.cpp.o
bgv-3pc: CMakeFiles/bgv-3pc.dir/build.make
bgv-3pc: /usr/local/lib/libPALISADEpke.1.11.3.dylib
bgv-3pc: /usr/local/lib/libPALISADEbinfhe.1.11.3.dylib
bgv-3pc: /usr/local/lib/libPALISADEcore.1.11.3.dylib
bgv-3pc: CMakeFiles/bgv-3pc.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/tanmay.ghai/amppere/palisade/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable bgv-3pc"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/bgv-3pc.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/bgv-3pc.dir/build: bgv-3pc
.PHONY : CMakeFiles/bgv-3pc.dir/build

CMakeFiles/bgv-3pc.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/bgv-3pc.dir/cmake_clean.cmake
.PHONY : CMakeFiles/bgv-3pc.dir/clean

CMakeFiles/bgv-3pc.dir/depend:
	cd /Users/tanmay.ghai/amppere/palisade/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/tanmay.ghai/amppere/palisade /Users/tanmay.ghai/amppere/palisade /Users/tanmay.ghai/amppere/palisade/build /Users/tanmay.ghai/amppere/palisade/build /Users/tanmay.ghai/amppere/palisade/build/CMakeFiles/bgv-3pc.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/bgv-3pc.dir/depend

