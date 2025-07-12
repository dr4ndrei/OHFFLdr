#ifndef OHFFLDR_HPP
#define OHFFLDR_HPP

#include <filesystem>
#include <iostream>
#include <fstream>
#include <optional>
#include <windows.h>
#include <cstdint>
#include <unordered_map>
#include <vector>

#define SIZE_OF_PAGE 0x1000

/**
 * This macro rounds up the given address to the very next page (SIZE_OF_PAGE multiple).
 *
 * The following example shows how this macro works:
 * @code
 * ULONG_PTR address = 0x1234;
 * ULONG_PTR aligned_address = PAGE_ALIGN(address); // 0x2000
 * @endcode
 *
 * @param x Address to align
 *
 * @return Aligned page address
 */
#define PAGE_ALIGN(x) ((((ULONG_PTR)(x) + SIZE_OF_PAGE - 1) / SIZE_OF_PAGE) * SIZE_OF_PAGE)

class ohffldr
{
public:

    enum error_code
    {
        ok,

        /* Memory API fails */

        malloc_fail,
        virtualalloc_fail,
        virtualprotect_fail,

        /* Stream fails */

        file_stream_fail,
        read_stream_fail,

        /* Integrity fails */

        invalid_path,
        unsupported_bof_arch,
        invalid_symbol,

        /* Resolving fails */

        unresolved_module,
        unresolved_symbol
    };

    /**
     * Loads and executes a BOF into memory.
     *
     * @param path The file system path of the BOF to be loaded.
     * @param symbol The symbol name to execute within the loaded BOF.
     * @param api_prefix The API prefix used to resolve external symbols.
     * @param arg The arguments passed to the BOF symbol execution.
     * @param arg_size The number of arguments.
     *
     * @return True if the BOF was successfully loaded and executed, false otherwise.
     */
    static bool load(const std::filesystem::path &path, const std::string &symbol, const std::string &api_prefix, char* arg, const int arg_size)
    {
        /* Load BOF */

        const auto bof = ohffldr::read_bof(path);

        if (!bof.has_value())
            return false;

        /* Parsing */

        const auto parse_result = ohffldr::parse(bof.value());

        if (parse_result == nullptr)
            return false;

        /* Calculate aligned size to store BOF */

        const auto aligned_memory_size = ohffldr::compute_aligned_memory(parse_result);

        /* Load */

        void* bof_base_address = VirtualAlloc(nullptr, aligned_memory_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        if (bof_base_address == nullptr)
        {
            last_error = virtualalloc_fail;
            return false;
        }

        /* Allocate section map entries on the heap */

        parse_result->sections_map = ohffldr::raii_heap_ptr_type(std::malloc(parse_result->n_sections * sizeof(ohffldr::parse_result_type::section_map_type)), &std::free);

        if (parse_result->sections_map == nullptr)
        {
            last_error = malloc_fail;

            VirtualFree(bof_base_address, 0, MEM_RELEASE);
            return false;
        }

        memset(parse_result->sections_map.get(), 0, parse_result->n_sections * sizeof(ohffldr::parse_result_type::section_map_type));

        /* Load section map entries */

        auto section_base = bof_base_address;
        ULONG section_size = 0;

        for (auto i = 0; i < parse_result->n_sections; ++i)
        {
            /* Store section size and base address */

            static_cast<ohffldr::parse_result_type::section_map_type*>(parse_result->sections_map.get())[i].size = section_size = parse_result->sections[i].size;
            static_cast<ohffldr::parse_result_type::section_map_type*>(parse_result->sections_map.get())[i].va = section_base;

            /* Copy section into allocated memory */

            memcpy(section_base, parse_result->sections[i].va, section_size);

            /* Calculate next address for next section */

            section_base = reinterpret_cast<void*>(PAGE_ALIGN(reinterpret_cast<ULONG_PTR>(section_base) + section_size));
        }

        parse_result->symbols_map = static_cast<void**>(section_base);

        /* Process sections */

        if (!ohffldr::process_sections(parse_result, api_prefix))
        {
            VirtualFree(bof_base_address, 0, MEM_RELEASE);
            return false;
        }

        /* Execute function */

        if (!ohffldr::execute(parse_result, symbol, arg, arg_size))
        {
            VirtualFree(bof_base_address, 0, MEM_RELEASE);
            return false;
        }

        VirtualFree(bof_base_address, 0, MEM_RELEASE);
        return true;
    }

    /**
     * Retrieves the last error code.
     *
     * @return The last error code of type ohffldr::error_code.
     */
    static error_code get_last_error()
    {
        return last_error;
    }

private:

    /* Objects */

    static error_code last_error;

    using raii_heap_ptr_type = std::unique_ptr<void, decltype(&std::free)>;

    struct parse_result_type
    {
        PIMAGE_FILE_HEADER image_file_header{};
        PIMAGE_SYMBOL image_symbol{};

        uint16_t n_sections{};
        uint16_t n_symbols{};

        PIMAGE_SECTION_HEADER image_section_header{};

        struct section_type
        {
            std::string name;
            void* va;
            uint64_t size;

            struct relocation_type
            {
                mutable PIMAGE_RELOCATION relocation_ptr;
                uint64_t n_relocations;
            };

            relocation_type relocations;
        };

        std::vector<section_type> sections;

        struct section_map_type
        {
            void* va;
            ULONG size;
        };

        mutable raii_heap_ptr_type sections_map{nullptr, &std::free};
        mutable void** symbols_map{};
    };

    /* Procedures */

    /**
     * Reads a BOF from the specified file path into memory.
     *
     * @param path The file system path of the BOF to be read.
     *
     * @return An optional containing a heap-allocated pointer to the BOF content if the process is successful;
     *         otherwise, returns std::nullopt to indicate failure.
     */
    static std::optional<raii_heap_ptr_type> read_bof(const std::filesystem::path &path)
    {
        /* Integrity checks */

        if (!std::filesystem::exists(path) || !std::filesystem::is_regular_file(path))
        {
            last_error = invalid_path;
            return std::nullopt;
        }

        /* Get file size */

        const auto file_size = std::filesystem::file_size(path);

        /* Allocate heap */

        raii_heap_ptr_type heap_ptr(std::malloc(file_size), &std::free);

        if (heap_ptr.get() == nullptr)
        {
            last_error = malloc_fail;
            return std::nullopt;
        }

        /* Open the file stream */

        std::ifstream file_stream(path, std::ios::binary);

        if (!file_stream)
        {
            last_error = file_stream_fail;
            return std::nullopt;
        }

        /* Read the file */

        file_stream.read(static_cast<char*>(heap_ptr.get()), static_cast<std::streamsize>(file_size));

        if (!file_stream)
        {
            last_error = read_stream_fail;
            return std::nullopt;
        }

        return heap_ptr;
    }

    /**
     * Parses the memory containing a BOF and extracts its components.
     *
     * @param heap_ptr A unique pointer to the memory region containing the BOF data.
     *                 The memory region must have been preloaded into heap memory.
     *
     * @return A unique pointer to a parse_result_type structure containing the
     *         parsed content of the BOF on successful parsing, or nullptr if
     *         parsing fails due to unsupported architecture or other issues.
     */
    static std::unique_ptr<parse_result_type> parse(const raii_heap_ptr_type &heap_ptr)
    {
        /* Extract essential headers */

        auto parse_result = std::make_unique<parse_result_type>();

        parse_result->image_file_header = static_cast<PIMAGE_FILE_HEADER>(heap_ptr.get());

        if (parse_result->image_file_header->Machine != IMAGE_FILE_MACHINE_AMD64)
        {
            last_error = unsupported_bof_arch;
            return nullptr;
        }

        parse_result->image_symbol = reinterpret_cast<PIMAGE_SYMBOL>(static_cast<char*>(heap_ptr.get()) + static_cast<ULONG_PTR>(parse_result->image_file_header->PointerToSymbolTable));

        /* Get the number of sections and symbols */

        parse_result->n_sections = parse_result->image_file_header->NumberOfSections;
        parse_result->n_symbols = parse_result->image_file_header->NumberOfSymbols;

        /* Parse sections */

        parse_result->image_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(static_cast<char*>(heap_ptr.get()) + sizeof(IMAGE_FILE_HEADER));

        for (auto i = 0; i < parse_result->n_sections; ++i)
            parse_result->sections.push_back({
                reinterpret_cast<PSTR>(parse_result->image_section_header[i].Name),
                static_cast<char*>(heap_ptr.get()) + parse_result->image_section_header[i].PointerToRawData,
                parse_result->image_section_header[i].SizeOfRawData,
                {
                    reinterpret_cast<PIMAGE_RELOCATION>(static_cast<char*>(heap_ptr.get()) + parse_result->image_section_header[i].PointerToRelocations),
                    parse_result->image_section_header[i].NumberOfRelocations
                }
            });

        return parse_result;
    }

    /**
     * Computes the total aligned memory required for the given sections and their relocations.
     *
     * @param parse_result A unique pointer to the parse results that contain information
     *                     about the sections, relocations, and symbols of the data being processed.
     *
     * @return The total aligned memory size required, including alignment for sections and imported symbols.
     */
    static uint64_t compute_aligned_memory(const std::unique_ptr<parse_result_type> &parse_result)
    {
        /* Calculate sections and their relocations */

        uint64_t total_aligned_memory = 0;

        for (const auto &section : parse_result->sections)
        {
            /* Align sections */

            total_aligned_memory += PAGE_ALIGN(section.size);

            /* Align imported symbols */

            const auto old_relocation_ptr = section.relocations.relocation_ptr;

            for (auto i = 0; i < section.relocations.n_relocations; ++i)
            {
                /* Short name check */

                const auto current_section_image_symbol = &parse_result->image_symbol[section.relocations.relocation_ptr->SymbolTableIndex];

                const auto symbol = current_section_image_symbol->N.Name.Short ?
                    reinterpret_cast<PSTR>(current_section_image_symbol->N.ShortName) :
                        reinterpret_cast<PSTR>(reinterpret_cast<ULONG_PTR>(parse_result->image_symbol + parse_result->n_symbols) +
                                static_cast<ULONG_PTR>(current_section_image_symbol->N.Name.Long));

                /* Check if imported symbol */

                if (strncmp("__imp_", symbol, 6) == 0)
                    total_aligned_memory += sizeof(void*);

                /* Skip to the next relocation */

                section.relocations.relocation_ptr = reinterpret_cast<PIMAGE_RELOCATION>(reinterpret_cast<ULONG_PTR>(section.relocations.relocation_ptr) + sizeof(IMAGE_RELOCATION));
            }

            section.relocations.relocation_ptr = old_relocation_ptr;
        }

        return PAGE_ALIGN(total_aligned_memory);
    }

    /**
     * Processes the sections and performs necessary relocations based on the parsed results.
     *
     * @param parse_result A unique pointer to the parse result object containing section definitions,
     *                     symbols, and associated mappings.
     * @param api_prefix The API prefix used for resolving external symbols during relocation.
     *
     * @return True if all section relocations were successfully processed, false otherwise.
     */
    static bool process_sections(const std::unique_ptr<parse_result_type> &parse_result, const std::string &api_prefix)
    {
        auto sections_counter = 0, function_index = 0;

        for (const auto &section : parse_result->sections)
        {
            const auto old_relocation_ptr = section.relocations.relocation_ptr;

            for (auto i = 0; i < section.relocations.n_relocations; ++i)
            {
                /* Short name check */

                const auto current_section_image_symbol = &parse_result->image_symbol[section.relocations.relocation_ptr->SymbolTableIndex];

                const auto symbol = current_section_image_symbol->N.Name.Short ?
                    reinterpret_cast<PSTR>(current_section_image_symbol->N.ShortName) :
                        reinterpret_cast<PSTR>(reinterpret_cast<ULONG_PTR>(parse_result->image_symbol + parse_result->n_symbols) +
                                static_cast<ULONG_PTR>(current_section_image_symbol->N.Name.Long));

                /* Calculate relocation address */

                auto relocation_address = reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(
                    static_cast<parse_result_type::section_map_type*>(parse_result->sections_map.get())[sections_counter].va) + section.relocations.relocation_ptr->VirtualAddress);

                /* Check if imported symbol */

                void* resolved = nullptr;

                if (strncmp("__imp_", symbol, 6) == 0)
                    if ((resolved = resolve_symbol(symbol, api_prefix)) == nullptr)
                        return false;

                /* Perform relocation */

                if (section.relocations.relocation_ptr->Type == IMAGE_REL_AMD64_REL32 && resolved != nullptr)
                {
                    parse_result->symbols_map[function_index] = resolved;

                    *static_cast<PUINT32>(relocation_address) = static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(parse_result->symbols_map) +
                        function_index * sizeof(void*) - reinterpret_cast<ULONG_PTR>(relocation_address) - sizeof(UINT32));

                    function_index++;
                }
                else
                    relocate_generic(section.relocations.relocation_ptr->Type, relocation_address,
                        static_cast<parse_result_type::section_map_type*>(parse_result->sections_map.get())[current_section_image_symbol->SectionNumber - 1].va);

                /* Skip to the next relocation */

                section.relocations.relocation_ptr = reinterpret_cast<PIMAGE_RELOCATION>(reinterpret_cast<ULONG_PTR>(section.relocations.relocation_ptr) + sizeof(IMAGE_RELOCATION));
            }

            section.relocations.relocation_ptr = old_relocation_ptr;
            sections_counter++;
        }

        return true;
    }

    /**
     * Executes a specified function symbol from the BOF.
     *
     * @param parse_result A unique pointer containing the parsed result.
     * @param symbol The name of the function symbol to execute.
     * @param arg The arguments passed to the function execution.
     * @param arg_size The number of arguments.
     *
     * @return True if the symbol was successfully located, executed, and memory protection was restored; false otherwise.
     */
    static bool execute(const std::unique_ptr<parse_result_type> &parse_result, const std::string &symbol, char* arg, const int arg_size)
    {
        for (auto i = 0; i < parse_result->n_symbols; ++i)
        {
            /* Short name check */

            const auto current_section_image_symbol = &parse_result->image_symbol[i];

            const auto current_symbol = current_section_image_symbol->N.Name.Short ?
                reinterpret_cast<PSTR>(current_section_image_symbol->N.ShortName) :
                    reinterpret_cast<PSTR>(reinterpret_cast<ULONG_PTR>(parse_result->image_symbol + parse_result->n_symbols) +
                            static_cast<ULONG_PTR>(current_section_image_symbol->N.Name.Long));

            /* Check if the symbol is by object */

            if (ISFCN(current_section_image_symbol->Type) && strcmp(current_symbol, symbol.c_str()) == 0)
            {
                /* Extract section */

                const auto section_base_address =
                    static_cast<parse_result_type::section_map_type*>(parse_result->sections_map.get())[current_section_image_symbol->SectionNumber - 1].va;
                const auto section_size =
                    static_cast<parse_result_type::section_map_type*>(parse_result->sections_map.get())[current_section_image_symbol->SectionNumber - 1].size;

                /* Make the section executable */

                DWORD old_protection = 0;

                if (!VirtualProtect(section_base_address, section_size, PAGE_EXECUTE_READ, &old_protection))
                {
                    last_error = virtualprotect_fail;
                    return false;
                }

                /* Execute function */

                const auto executable_function = reinterpret_cast<void(*)(char*, int)>(reinterpret_cast<ULONG_PTR>(section_base_address) + current_section_image_symbol->Value);

                executable_function(arg, arg_size);

                /* Restore protection */

                if (!VirtualProtect(section_base_address, section_size, old_protection, &old_protection))
                {
                    last_error = virtualprotect_fail;
                    return false;
                }
            }
        }

        return true;
    }

    /* Helpers */

    /**
     * Resolves a symbol to its corresponding memory address.
     *
     * @param symbol The name of the symbol to resolve.
     * @param api_prefix The prefix that identifies Beacon-specific API symbols.
     *
     * @return A pointer to the resolved memory address if successful, or nullptr if the symbol cannot be resolved.
     */
    static void* resolve_symbol(std::string symbol, const std::string &api_prefix)
    {
        /* Remove prefix */

        if (const std::string prefix = "__imp_"; symbol.rfind(prefix, 0) == 0)
            symbol = symbol.substr(prefix.size());

        /* Check if the symbol is Beacon API related */

        if (symbol.compare(0, api_prefix.size(), api_prefix) == 0)
        {
            static const std::unordered_map<std::string, void*> symbols
            {
                {},
            };

            if (const auto it = symbols.find(symbol); it != symbols.end())
                return it->second;
        }
        else
        {
            /* Extract module name and symbol */

            const auto position = symbol.find('$');
            if (position == std::string::npos)
            {
                last_error = invalid_symbol;
                return nullptr;
            }

            const std::string module = symbol.substr(0, position);
            const std::string function = symbol.substr(position + 1);

            /* Retrieve module's handle */

            auto module_ptr = GetModuleHandleA(module.c_str());
            if (module_ptr == nullptr)
            {
                /* Load module if isn't found in the current process */

                module_ptr = LoadLibraryA(module.c_str());
                if (module_ptr == nullptr)
                {
                    last_error = unresolved_module;
                    return nullptr;
                }
            }

            /* Retrieve function's address */

            const auto function_ptr = reinterpret_cast<void*>(GetProcAddress(module_ptr, function.c_str()));
            if (function_ptr == nullptr)
            {
                last_error = unresolved_symbol;
                return nullptr;
            }

            return function_ptr;
        }

        last_error = unresolved_symbol;
        return nullptr;
    }

    /**
     * Performs relocation of a given type on a specified address within a section.
     *
     * @param type The relocation type identifier.
     * @param relocation_address The memory address where the relocation is to be applied.
     * @param section_base_address The base address of the section containing the relocation.
     *
     * @return True if the relocation was successfully processed, false for unsupported relocation types.
     */
    static bool relocate_generic(const WORD type, void* relocation_address, void* section_base_address)
    {
        switch (type)
        {
            case IMAGE_REL_AMD64_REL32:
                *static_cast<PUINT32>(relocation_address) = *static_cast<PUINT32>(relocation_address) + static_cast<ULONG>(
                    reinterpret_cast<ULONG_PTR>(section_base_address) - reinterpret_cast<ULONG_PTR>(relocation_address) - sizeof(UINT32));
                break;

            case IMAGE_REL_AMD64_REL32_1:
                *static_cast<PUINT32>(relocation_address) = *static_cast<PUINT32>(relocation_address) + static_cast<ULONG>(
                    reinterpret_cast<ULONG_PTR>(section_base_address) - reinterpret_cast<ULONG_PTR>(relocation_address) - sizeof(UINT32) - 1);
                break;

            case IMAGE_REL_AMD64_REL32_2:
                *static_cast<PUINT32>(relocation_address) = *static_cast<PUINT32>(relocation_address) + static_cast<ULONG>(
                    reinterpret_cast<ULONG_PTR>(section_base_address) - reinterpret_cast<ULONG_PTR>(relocation_address) - sizeof(UINT32) - 2);
                break;

            case IMAGE_REL_AMD64_REL32_3:
                *static_cast<PUINT32>(relocation_address) = *static_cast<PUINT32>(relocation_address) + static_cast<ULONG>(
                    reinterpret_cast<ULONG_PTR>(section_base_address) - reinterpret_cast<ULONG_PTR>(relocation_address) - sizeof(UINT32) - 3);
                break;

            case IMAGE_REL_AMD64_REL32_4:
                *static_cast<PUINT32>(relocation_address) = *static_cast<PUINT32>(relocation_address) + static_cast<ULONG>(
                    reinterpret_cast<ULONG_PTR>(section_base_address) - reinterpret_cast<ULONG_PTR>(relocation_address) - sizeof(UINT32) - 4);
                break;

            case IMAGE_REL_AMD64_REL32_5:
                *static_cast<PUINT32>(relocation_address) = *static_cast<PUINT32>(relocation_address) + static_cast<ULONG>(
                    reinterpret_cast<ULONG_PTR>(section_base_address) - reinterpret_cast<ULONG_PTR>(relocation_address) - sizeof(UINT32) - 5);
                break;

            case IMAGE_REL_AMD64_ADDR64:
                *static_cast<PUINT64>(relocation_address) = *static_cast<PUINT64>(relocation_address) + reinterpret_cast<ULONG64>(section_base_address);
                break;

            default:
                return false;
        }

        return true;
    }
};

inline ohffldr::error_code ohffldr::last_error = ohffldr::error_code::ok;

#endif //OHFFLDR_HPP
