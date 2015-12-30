# -*- Mode: Python -*-

env = Environment(CXX = "clang++")

env.Append(CPPFLAGS  = "-D_GNU_SOURCE",
           CCFLAGS   = "-Os",
           CXXFLAGS  = "-std=c++14",
           LINKFLAGS = "-Wl,--gc-sections",
           LIBS      = "owfat")

env.Program('seccomp', ['main.cpp'])

# EOF
