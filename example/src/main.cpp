#include <iostream>
#include "mylib.h"
#include "app.h"

int main() {
    std::cout << MyLib::greet("World") << std::endl;
    std::cout << "2 + 3 = " << MyLib::add(2, 3) << std::endl;

    runAppExample();
    return 0;
}
