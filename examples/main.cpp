#include <iostream>
#include <isc/isc.h>
#include <unistd.h>

void test(std::stop_token token) {
    char buff[1024];
    isc::read(token, 0, buff, 1024);
    if (!token.stop_requested()) {
        std::cout << buff << std::endl;
    } else {
        /* interrupt handling */
        std::cout << std::system_category().message(errno) << std::endl;
    }
}
int main()
{
    std::jthread t(test);
    sleep(1);
    t.request_stop();
    t.join();
    return 0;
}
