# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.13

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/liuqingxiu/afstream-0.2.0

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/liuqingxiu/afstream-0.2.0/release

# Include any dependencies generated for this target.
include CMakeFiles/zmq_mailbox.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/zmq_mailbox.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/zmq_mailbox.dir/flags.make

CMakeFiles/zmq_mailbox.dir/src/control_channel/ip.cpp.o: CMakeFiles/zmq_mailbox.dir/flags.make
CMakeFiles/zmq_mailbox.dir/src/control_channel/ip.cpp.o: ../src/control_channel/ip.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/zmq_mailbox.dir/src/control_channel/ip.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/zmq_mailbox.dir/src/control_channel/ip.cpp.o -c /home/liuqingxiu/afstream-0.2.0/src/control_channel/ip.cpp

CMakeFiles/zmq_mailbox.dir/src/control_channel/ip.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zmq_mailbox.dir/src/control_channel/ip.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/liuqingxiu/afstream-0.2.0/src/control_channel/ip.cpp > CMakeFiles/zmq_mailbox.dir/src/control_channel/ip.cpp.i

CMakeFiles/zmq_mailbox.dir/src/control_channel/ip.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zmq_mailbox.dir/src/control_channel/ip.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/liuqingxiu/afstream-0.2.0/src/control_channel/ip.cpp -o CMakeFiles/zmq_mailbox.dir/src/control_channel/ip.cpp.s

CMakeFiles/zmq_mailbox.dir/src/control_channel/mailbox.cpp.o: CMakeFiles/zmq_mailbox.dir/flags.make
CMakeFiles/zmq_mailbox.dir/src/control_channel/mailbox.cpp.o: ../src/control_channel/mailbox.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/zmq_mailbox.dir/src/control_channel/mailbox.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/zmq_mailbox.dir/src/control_channel/mailbox.cpp.o -c /home/liuqingxiu/afstream-0.2.0/src/control_channel/mailbox.cpp

CMakeFiles/zmq_mailbox.dir/src/control_channel/mailbox.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zmq_mailbox.dir/src/control_channel/mailbox.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/liuqingxiu/afstream-0.2.0/src/control_channel/mailbox.cpp > CMakeFiles/zmq_mailbox.dir/src/control_channel/mailbox.cpp.i

CMakeFiles/zmq_mailbox.dir/src/control_channel/mailbox.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zmq_mailbox.dir/src/control_channel/mailbox.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/liuqingxiu/afstream-0.2.0/src/control_channel/mailbox.cpp -o CMakeFiles/zmq_mailbox.dir/src/control_channel/mailbox.cpp.s

CMakeFiles/zmq_mailbox.dir/src/control_channel/signaler.cpp.o: CMakeFiles/zmq_mailbox.dir/flags.make
CMakeFiles/zmq_mailbox.dir/src/control_channel/signaler.cpp.o: ../src/control_channel/signaler.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/zmq_mailbox.dir/src/control_channel/signaler.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/zmq_mailbox.dir/src/control_channel/signaler.cpp.o -c /home/liuqingxiu/afstream-0.2.0/src/control_channel/signaler.cpp

CMakeFiles/zmq_mailbox.dir/src/control_channel/signaler.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zmq_mailbox.dir/src/control_channel/signaler.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/liuqingxiu/afstream-0.2.0/src/control_channel/signaler.cpp > CMakeFiles/zmq_mailbox.dir/src/control_channel/signaler.cpp.i

CMakeFiles/zmq_mailbox.dir/src/control_channel/signaler.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zmq_mailbox.dir/src/control_channel/signaler.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/liuqingxiu/afstream-0.2.0/src/control_channel/signaler.cpp -o CMakeFiles/zmq_mailbox.dir/src/control_channel/signaler.cpp.s

CMakeFiles/zmq_mailbox.dir/src/control_channel/zmq_err.cpp.o: CMakeFiles/zmq_mailbox.dir/flags.make
CMakeFiles/zmq_mailbox.dir/src/control_channel/zmq_err.cpp.o: ../src/control_channel/zmq_err.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/zmq_mailbox.dir/src/control_channel/zmq_err.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/zmq_mailbox.dir/src/control_channel/zmq_err.cpp.o -c /home/liuqingxiu/afstream-0.2.0/src/control_channel/zmq_err.cpp

CMakeFiles/zmq_mailbox.dir/src/control_channel/zmq_err.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zmq_mailbox.dir/src/control_channel/zmq_err.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/liuqingxiu/afstream-0.2.0/src/control_channel/zmq_err.cpp > CMakeFiles/zmq_mailbox.dir/src/control_channel/zmq_err.cpp.i

CMakeFiles/zmq_mailbox.dir/src/control_channel/zmq_err.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zmq_mailbox.dir/src/control_channel/zmq_err.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/liuqingxiu/afstream-0.2.0/src/control_channel/zmq_err.cpp -o CMakeFiles/zmq_mailbox.dir/src/control_channel/zmq_err.cpp.s

zmq_mailbox: CMakeFiles/zmq_mailbox.dir/src/control_channel/ip.cpp.o
zmq_mailbox: CMakeFiles/zmq_mailbox.dir/src/control_channel/mailbox.cpp.o
zmq_mailbox: CMakeFiles/zmq_mailbox.dir/src/control_channel/signaler.cpp.o
zmq_mailbox: CMakeFiles/zmq_mailbox.dir/src/control_channel/zmq_err.cpp.o
zmq_mailbox: CMakeFiles/zmq_mailbox.dir/build.make

.PHONY : zmq_mailbox

# Rule to build all files generated by this target.
CMakeFiles/zmq_mailbox.dir/build: zmq_mailbox

.PHONY : CMakeFiles/zmq_mailbox.dir/build

CMakeFiles/zmq_mailbox.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/zmq_mailbox.dir/cmake_clean.cmake
.PHONY : CMakeFiles/zmq_mailbox.dir/clean

CMakeFiles/zmq_mailbox.dir/depend:
	cd /home/liuqingxiu/afstream-0.2.0/release && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/liuqingxiu/afstream-0.2.0 /home/liuqingxiu/afstream-0.2.0 /home/liuqingxiu/afstream-0.2.0/release /home/liuqingxiu/afstream-0.2.0/release /home/liuqingxiu/afstream-0.2.0/release/CMakeFiles/zmq_mailbox.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/zmq_mailbox.dir/depend
