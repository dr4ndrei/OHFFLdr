#include "arguments-packer.hpp"
#include "custom-ohffldr.hpp"

#include <iostream>
#include <format>

int main(const int argc, char** argv)
{
    /* Banner */

    std::cout << "\n * Welcome to OHFFLdr.\n" << std::endl;

    /* Check the number of arguments */

    if (argc < 4)
    {
        std::cout << std::format(" ? Usage: {} <object file> <symbol> <api prefix> <opt:arguments>\n", argv[0]) << std::endl;
        return 1;
    }

    /* Prepare arguments */

    std::cout << " i Processing arguments... " << std::flush;

    if (!arguments_packer::process_arguments(argc, argv, 4))
        return 1;

    auto arg = arguments_packer::get_buffer();

    std::cout << "ok" << std::endl;

    /* Load BOF */

    if (!ohffldr::load(argv[1], argv[2], argv[3], reinterpret_cast<char*>(arg.data()), static_cast<int>(arg.size())))
    {
        std::cerr << std::format("\n ! OHFFLdr failed with errno {}.\n", static_cast<int>(ohffldr::get_last_error())) << std::endl;
        return 1;
    }

    std::cout << " i Exiting.\n" << std::endl;

    return 0;
}