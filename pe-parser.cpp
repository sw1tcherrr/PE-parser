#include <iostream>
#include <fstream>
#include <cstring>
#include <memory>
#include <vector>

#include "pe-parser.h"

struct dll {
	dll() = delete;
	explicit dll(std::string&& name) : name(name) {}

	void add_func(std::string&& f) {
		functions.emplace_back(std::move(f));
	}

	friend std::ostream& operator<<(std::ostream& s, dll const& d);

private:
	std::string name;
	std::vector<std::string> functions;
};

std::ostream& operator<<(std::ostream& s, dll const& d) {
	s << d.name << "\n";
	for (auto const& f : d.functions) {
		s << SPACE << f << "\n";
	}
	return s;
}

struct PE_parser {
	PE_parser() = delete;
	explicit PE_parser(std::ifstream&& f) : f(std::move(f)) {
		offset_read(PE_POINTER, PE_start);
		offset_read(PE_start + NUM_OF_SECTIONS, sections_cnt);
	}

	bool is_pe() {
		char sig[sizeof(SIGNATURE)];

		offset_read(PE_start, sig);

		return memcmp(sig, SIGNATURE, sizeof(SIGNATURE)) == 0;
	}

	std::vector<dll> import_functions() {
		if (!is_pe()) {
			throw std::invalid_argument("File is not in PE format");
		}
		std::vector<dll> res;

		offset_t import_table_rva;
		offset_read(PE_start + DATA_DIRECTORIES + IMPORT_TABLE, import_table_rva);

		offset_t import_table_raw = get_raw(import_table_rva);

		import_table_entry entry{};
		offset_read(import_table_raw, entry);
		for (int32_t k = 0;
			memcmp(&entry, ZEROS, IMPORT_ENTRY_SIZE) != 0;
			++k, offset_read(import_table_raw + IMPORT_ENTRY_SIZE * k, entry))
		{
			offset_t name_raw = get_raw(entry.name_rva);
			std::string name;

			offset_read_str(name_raw, name);

			res.emplace_back(std::move(name));

			offset_t lookup_raw = get_raw(entry.lookup_rva);
			int64_t lookup_entry;
			offset_read(lookup_raw, lookup_entry);

			for (int32_t j = 0;
				lookup_entry != 0;
				++j, offset_read(lookup_raw + j * sizeof(lookup_entry), lookup_entry))
			{
				if (!(lookup_entry & (1ll << 63))) {
					std::string func_name;
					offset_t name_table_rva = lookup_entry & ((1ll << 31) - 1);
					offset_t name_table_raw = get_raw(name_table_rva);

					offset_read_str(name_table_raw + NAME, func_name);

					res.back().add_func(std::move(func_name));
				}
			}
		}

		return res;
	}

	std::vector<std::string> export_functions() {
		if (!is_pe()) {
			throw std::invalid_argument("File is not in PE format");
		}
		std::vector<std::string> res;

		offset_t export_table_rva;
		offset_read(PE_start + DATA_DIRECTORIES + EXPORT_TABLE, export_table_rva);

		if (export_table_rva == 0) {
			return res;
		}

		offset_t export_table_raw = get_raw(export_table_rva);
		int32_t name_cnt;
		offset_t name_rva_table_rva;

		offset_read(export_table_raw + NUM_OF_NAMES, name_cnt);
		offset_read(export_table_raw + NAMES_RVA, name_rva_table_rva);
		offset_t name_rva_table_raw = get_raw(name_rva_table_rva);

		for (int32_t k = 0; k < name_cnt; ++k) {
			std::string name;
			offset_t name_rva;

			offset_read(name_rva_table_raw + k * sizeof(offset_t), name_rva);
			offset_t name_raw = get_raw(name_rva);

			offset_read_str(name_raw, name);
			res.emplace_back(std::move(name));
		}

		return res;
	}

private:
	std::ifstream f;
	offset_t PE_start{};
	int16_t sections_cnt{};

	int32_t get_raw(int32_t rva) {
		int32_t raw;
		bool found = false;
		for (auto k = 0; k < sections_cnt; ++k) {
			offset_t cur_entry = PE_start + SECTION_TABLE + k * SECTION_ENTRY_SIZE;
			int32_t section_virtual_size;
			offset_t section_rva;
			offset_t section_raw;

			offset_read(cur_entry + SECTION_VS, section_virtual_size);
			offset_read(cur_entry + SECTION_RVA, section_rva);
			offset_read(cur_entry + SECTION_RAW, section_raw);

			if (!section_rva || !section_raw || !section_virtual_size) {
				continue;
			}

			if (section_rva <= rva && rva <= section_rva + section_virtual_size) {
				raw = section_raw + rva - section_rva;
				found = true;
				break;
			}
		}

		if (!found) {
			throw std::invalid_argument("Invalid PE");
		}

		return raw;
	}

	template <typename T>
	void offset_read(offset_t offset, T& dst) {
		f.seekg(offset, std::ios::beg);
		f.read((char*)&dst, sizeof(T));
	}

	void offset_read_str(offset_t offset, std::string& s) {
		f.seekg(offset, std::ios::beg);
		std::getline(f, s, '\0');
	}

	struct import_table_entry {
		int32_t lookup_rva;
		int32_t unused1;
		int32_t unused2;
		int32_t name_rva;
		int32_t unused3;
	};
};

void usage() {
	std::cout << "usage: pe-parser [is-pe, import-functions, export-functions] <file_name>" << std::endl;
}

int main(int argc, char** argv) {
	if (argc != 3) {
		usage();
		return -1;
	}

	std::ifstream f(argv[2], std::ios_base::binary);
	if (!f.is_open()) {
		std::cerr << "Can't open file" << std::endl;
		return -1;
	}

	PE_parser parser(std::move(f));

	if (std::strcmp(argv[1], "is-pe") == 0) {
		if (parser.is_pe()) {
			std::cout << "PE" << std::endl;
			return 0;
		} else {
			std::cout << "Not PE" << std::endl;
			return 1;
		}
	} else if (std::strcmp(argv[1], "import-functions") == 0) {
		auto res = parser.import_functions();
		for (auto const& e : res) {
			std::cout << e;
		}
	} else if (std::strcmp(argv[1], "export-functions") == 0) {
		auto res = parser.export_functions();
		for (auto const& e : res) {
			std::cout << e << "\n";
		}
	} else {
		usage();
		return -1;
	}
}
