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
include CMakeFiles/controller.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/controller.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/controller.dir/flags.make

CMakeFiles/controller.dir/src/controller/ZkUtil.cpp.o: CMakeFiles/controller.dir/flags.make
CMakeFiles/controller.dir/src/controller/ZkUtil.cpp.o: ../src/controller/ZkUtil.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/controller.dir/src/controller/ZkUtil.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/controller.dir/src/controller/ZkUtil.cpp.o -c /home/liuqingxiu/afstream-0.2.0/src/controller/ZkUtil.cpp

CMakeFiles/controller.dir/src/controller/ZkUtil.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/controller.dir/src/controller/ZkUtil.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/liuqingxiu/afstream-0.2.0/src/controller/ZkUtil.cpp > CMakeFiles/controller.dir/src/controller/ZkUtil.cpp.i

CMakeFiles/controller.dir/src/controller/ZkUtil.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/controller.dir/src/controller/ZkUtil.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/liuqingxiu/afstream-0.2.0/src/controller/ZkUtil.cpp -o CMakeFiles/controller.dir/src/controller/ZkUtil.cpp.s

CMakeFiles/controller.dir/src/controller/main.cpp.o: CMakeFiles/controller.dir/flags.make
CMakeFiles/controller.dir/src/controller/main.cpp.o: ../src/controller/main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/controller.dir/src/controller/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/controller.dir/src/controller/main.cpp.o -c /home/liuqingxiu/afstream-0.2.0/src/controller/main.cpp

CMakeFiles/controller.dir/src/controller/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/controller.dir/src/controller/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/liuqingxiu/afstream-0.2.0/src/controller/main.cpp > CMakeFiles/controller.dir/src/controller/main.cpp.i

CMakeFiles/controller.dir/src/controller/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/controller.dir/src/controller/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/liuqingxiu/afstream-0.2.0/src/controller/main.cpp -o CMakeFiles/controller.dir/src/controller/main.cpp.s

# Object files for target controller
controller_OBJECTS = \
"CMakeFiles/controller.dir/src/controller/ZkUtil.cpp.o" \
"CMakeFiles/controller.dir/src/controller/main.cpp.o"

# External object files for target controller
controller_EXTERNAL_OBJECTS = \
"/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/generated/zookeeper.jute.c.o" \
"/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/src/hashtable/hashtable.c.o" \
"/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/src/hashtable/hashtable_itr.c.o" \
"/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/src/mt_adaptor.c.o" \
"/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/src/recordio.c.o" \
"/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/src/zk_hashtable.c.o" \
"/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/src/zk_log.c.o" \
"/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/src/zookeeper.c.o"

controller: CMakeFiles/controller.dir/src/controller/ZkUtil.cpp.o
controller: CMakeFiles/controller.dir/src/controller/main.cpp.o
controller: CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/generated/zookeeper.jute.c.o
controller: CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/src/hashtable/hashtable.c.o
controller: CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/src/hashtable/hashtable_itr.c.o
controller: CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/src/mt_adaptor.c.o
controller: CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/src/recordio.c.o
controller: CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/src/zk_hashtable.c.o
controller: CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/src/zk_log.c.o
controller: CMakeFiles/zkmt.dir/third_party/zookeeper-3.4.7/src/zookeeper.c.o
controller: CMakeFiles/controller.dir/build.make
controller: CMakeFiles/controller.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/liuqingxiu/afstream-0.2.0/release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable controller"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/controller.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/controller.dir/build: controller

.PHONY : CMakeFiles/controller.dir/build

CMakeFiles/controller.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/controller.dir/cmake_clean.cmake
.PHONY : CMakeFiles/controller.dir/clean

CMakeFiles/controller.dir/depend:
	cd /home/liuqingxiu/afstream-0.2.0/release && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/liuqingxiu/afstream-0.2.0 /home/liuqingxiu/afstream-0.2.0 /home/liuqingxiu/afstream-0.2.0/release /home/liuqingxiu/afstream-0.2.0/release /home/liuqingxiu/afstream-0.2.0/release/CMakeFiles/controller.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/controller.dir/depend

