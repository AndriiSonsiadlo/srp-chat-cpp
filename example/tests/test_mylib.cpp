#include "../lib/include/mylib.h"
#include <cassert>
#include <iostream>

int main() {
    // Test add function
    assert(MyLib::add(2, 3) == 5);
    assert(MyLib::add(-1, 1) == 0);

    // Test greet function
    assert(MyLib::greet("Alice") == "Hello, Alice!");

    std::cout << "All tests passed!" << std::endl;
    return 0;
}
