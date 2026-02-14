add_library(libbb STATIC
        mylib.cpp
)

target_include_directories(libbb PUBLIC
        include
)
