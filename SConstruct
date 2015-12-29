# -*- Mode: Python -*-

env = Environment()

env.ParseConfig('pkg-config --cflags --libs capstone')
env.Append( CPPFLAGS  = "-D_GNU_SOURCE",
            CCFLAGS   = "-O2 -g",
            CXXFLAGS  = "-std=c++14",
            LINKFLAGS = "-Wl,--gc-sections",
            LIBS      = "owfat")

env.Program('seccomp', ['main.cpp'])

# EOF
