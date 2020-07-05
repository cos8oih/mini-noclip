#include <string>
#include <iomanip>
#include <iostream>

inline void rotl(
    uint32_t& x,
    uint32_t n)
{
    auto constexpr mask = (8 * sizeof(uint32_t) - 1);
    n &= mask;
    x = (x << n) | (x >> ((-n) & mask));
}

uint32_t hashString(std::string const& s)
{
    uint32_t hash = 0;

    for (auto const c : s)
    {
        hash += c;
        rotl(hash, 27);
    }

    return hash;
}

int main(
    int const argc,
    char const* const* argv)
{
    if (argc > 1)
        std::cout
            << "0x"
            << std::hex
            << std::uppercase
            << hashString(argv[1])
            << std::endl;

    return 0;
}