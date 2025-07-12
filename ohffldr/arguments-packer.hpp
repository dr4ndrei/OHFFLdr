#ifndef ARGUMENTS_PACKER_HPP
#define ARGUMENTS_PACKER_HPP

#include <string>
#include <iostream>
#include <format>
#include <cstdint>
#include <vector>

class arguments_packer
{
public:

    /**
     * Processes the command-line arguments starting from a specified index.
     * The arguments must be in the format 'type=value', where 'type' defines
     * the data type (e.g., short, int, string, wstring) and 'value' is the associated value.
     *
     * @param argc The total number of command-line arguments.
     * @param argv The array of null-terminated strings representing arguments.
     * @param index The starting index from which arguments should be processed.
     *
     * @return True if all arguments are successfully processed, false otherwise.
     */
    static bool process_arguments(const int argc, char** argv, const int index)
    {
        for (int i = index; i < argc; ++i)
        {
            /* Find `=` */

            std::string arg = argv[i];
            const std::size_t equal_pos = arg.find('=');

            if (equal_pos == std::string::npos)
            {
                std::cerr << std::format(R"( ! Invalid argument syntax for "{}")", arg) << std::endl;
                return false;
            }

            /* Extract type and value */

            std::string type = arg.substr(0, equal_pos);
            std::string value = arg.substr(equal_pos + 1);

            /* Remove double quotes if any */

            if (type == "string" || type == "wstring")
                if (!value.empty() && value.front() == '"' && value.back() == '"')
                    value = value.substr(1, value.size() - 2);

            /* Check type */

            try
            {
                if (type == "short")
                {
                    const auto short_value = static_cast<int16_t>(std::stoi(value));
                    add_short(short_value);
                }
                else if (type == "int")
                {
                    const auto int_value = std::stoi(value);
                    add_int(int_value);
                }
                else if (type == "string")
                {
                    add_string(value);
                }
                else if (type == "wstring")
                {
                    std::wstring wvalue(value.begin(), value.end());
                    add_wstring(wvalue);
                }
                else
                {
                    std::cerr << std::format(R"( ! Unknown type "{}" for "{}")", type, arg) << std::endl;
                    return false;
                }
            }
            catch (const std::exception& e)
            {
                std::cerr << std::format(R"( ! Unable to parse "{}" due to: {})", arg, e.what()) << std::endl;
                return false;
            }
        }

        return true;
    }

    /**
     * Retrieves the contents of the static buffer.
     *
     * @return A vector containing the buffer size, followed by the buffer's data.
     */
    static std::vector<uint8_t> get_buffer()
    {
        /* Add the buffer size to the buffer itself (4 bytes) */

        std::vector<uint8_t> output;

        const uint32_t size = buffer.size();
        output.push_back(size & 0xFF);
        output.push_back((size >> 8) & 0xFF);
        output.push_back((size >> 16) & 0xFF);
        output.push_back((size >> 24) & 0xFF);

        /* Append the actual buffer */

        output.insert(output.end(), buffer.begin(), buffer.end());
        return output;
    }

    static void reset()
    {
        buffer.clear();
    }

private:

    static std::vector<uint8_t> buffer;

    /**
     * Adds a 16-bit integer to the buffer.
     *
     * @param value The 16-bit integer value to add to the buffer.
     */
    static void add_short(const int16_t value)
    {
        buffer.push_back(value & 0xFF);
        buffer.push_back((value >> 8) & 0xFF);
    }

    /**
     * Adds a 32-bit integer to the buffer.
     *
     * @param value The 32-bit integer value to add to the buffer.
     */
    static void add_int(const int32_t value)
    {
        buffer.push_back(value & 0xFF);
        buffer.push_back((value >> 8) & 0xFF);
        buffer.push_back((value >> 16) & 0xFF);
        buffer.push_back((value >> 24) & 0xFF);
    }

    /**
     * Adds a UTF-8 string to the buffer, prefixed with its size.
     *
     * @param str The UTF-8 string to add to the buffer.
     */
    static void add_string(const std::string& str)
    {
        /* Include null terminator */

        const uint32_t str_length = str.size() + 1;

        /* Add the string length as a 4-byte integer */

        buffer.push_back(str_length & 0xFF);
        buffer.push_back((str_length >> 8) & 0xFF);
        buffer.push_back((str_length >> 16) & 0xFF);
        buffer.push_back((str_length >> 24) & 0xFF);

        /* Add the string bytes */

        buffer.insert(buffer.end(), str.begin(), str.end());

        /* Null-terminate the string */

        buffer.push_back(0);
    }

    /**
     * Adds a wide string (UTF-16) to the buffer.
     *
     * @param wstr The wide string to add to the buffer.
     */
    static void add_wstring(const std::wstring& wstr)
    {
        /* Convert from a wide string (UTF-16) to a byte array */

        std::vector<uint8_t> utf16_bytes;

        for (const wchar_t wc : wstr)
        {
            utf16_bytes.push_back(wc & 0xFF);
            utf16_bytes.push_back((wc >> 8) & 0xFF);
        }

        /* Append the null-terminators for UTF-16 */

        utf16_bytes.push_back(0);
        utf16_bytes.push_back(0);

        /* Add the size of the wide string as a 4-byte integer */

        const uint32_t byte_count = utf16_bytes.size();

        buffer.push_back(byte_count & 0xFF);
        buffer.push_back((byte_count >> 8) & 0xFF);
        buffer.push_back((byte_count >> 16) & 0xFF);
        buffer.push_back((byte_count >> 24) & 0xFF);

        /* Append the UTF-16 bytes to the buffer */

        buffer.insert(buffer.end(), utf16_bytes.begin(), utf16_bytes.end());
    }
};

inline std::vector<uint8_t> arguments_packer::buffer{};

#endif //ARGUMENTS_PACKER_HPP
