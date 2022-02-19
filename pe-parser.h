#pragma once

constexpr char const* const SPACE = "    ";

using offset_t = int32_t;

constexpr size_t const SECTION_ENTRY_SIZE = 40;
constexpr size_t const IMPORT_ENTRY_SIZE = 20;

constexpr offset_t const PE_POINTER = 0x3C;
constexpr char const SIGNATURE[] = {'P', 'E', '\0', '\0'};
constexpr char const ZEROS[IMPORT_ENTRY_SIZE] = {0};

// relative to PE_start
constexpr offset_t const NUM_OF_SECTIONS = 0x6;
constexpr offset_t const DATA_DIRECTORIES = 0x88;
constexpr offset_t const SECTION_TABLE = 0xB8;

// relative to DATA_DIRECTORIES
constexpr offset_t const EXPORT_TABLE = 0;
constexpr offset_t const IMPORT_TABLE = 0x8;

// relative to section table entry start
constexpr offset_t const SECTION_VS = 0x8;
constexpr offset_t const SECTION_RVA = 0xC;
constexpr offset_t const SECTION_RAW = 0x14;

// relative to import table entry start
constexpr offset_t const NAME_RVA = 0xC;

// relative to name table start
constexpr offset_t const NAME = 0x2;

// relative to export table start
constexpr offset_t const NUM_OF_NAMES = 0x18;
constexpr offset_t const NAMES_RVA = 0x20;
