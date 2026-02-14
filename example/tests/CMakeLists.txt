add_executable(test_suite test_mylib.cpp)
target_link_libraries(test_suite PRIVATE mylib)
add_test(NAME MyLibTests COMMAND test_suite)
