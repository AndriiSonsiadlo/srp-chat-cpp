#include <iostream>
#include "mylib.h"
#include "app.h"

void runAppExample()
{
    std::cout << "Running app example..." << std::endl;
    std::cout << MyLib::greet("C++ Developer") << std::endl;
}
