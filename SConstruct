# -*- Mode: Python -*-

env = Environment()

env.Program('seccomp', ['main.cpp'],
            CPPFLAGS  = "-D_GNU_SOURCE",
            CCFLAGS   = "-O2 -g",
            CXXFLAGS  = "-std=c++14",
            LINKFLAGS = "-Wl,--gc-sections",
            LIBS = ["owfat"])

# EOF
