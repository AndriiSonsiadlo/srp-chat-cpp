find_package(Threads REQUIRED)
#find_package(OpenSSL)
#find_package(Qt6 COMPONENTS
#        Core
#        Widgets
#        Network
#        REQUIRED
#)
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

add_executable(myapp
        main.cpp
        app.cpp
)
target_include_directories(myapp PRIVATE include)
target_link_libraries(myapp PRIVATE libbb Threads::Threads)
