#include "include/mylib.h"

std::string MyLib::greet(const std::string& name) {
    return "Hello, " + name + "!";
}

int MyLib::add(const int a, const int b) {
    return a + b;
}
