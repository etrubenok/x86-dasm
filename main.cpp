#include <iostream>
#include <utility>
#include <vector>
#include <fstream>
#include <iomanip>
#include <map>

std::string byte_to_hex(const uint8_t number) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(2) << std::setfill('0') << (static_cast<uint8_t>(number) & 0xFF);
    return oss.str();
}

std::string word_to_hex(const uint16_t number) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << (static_cast<uint16_t>(number) & 0xFFFF);
    return oss.str();
}

std::string disp_addr8_to_hex(const uint8_t addr8) {
    auto addr = static_cast<int8_t>(addr8); // Convert to signed 8-bit integer
    std::string sign = addr < 0 ? "-" : "+";

    std::ostringstream oss;
    oss << sign << "0x" << std::hex << std::setw(2) << std::setfill('0') << std::abs(addr);
    return oss.str();
}

std::string disp_addr16_to_hex(const uint16_t addr16) {
    auto addr = static_cast<int16_t>(addr16); // Convert to signed 16-bit integer
    std::string sign = addr < 0 ? "-" : "+";

    std::ostringstream oss;
    oss << sign << "0x" << std::hex << std::setw(4) << std::setfill('0') << std::abs(addr);
    return oss.str();
}

namespace ModNamespace {
    enum class Mod {
      MemoryMode,
      MemoryMode8,
      MemoryMode16,
      RegisterMode,
    };


    std::ostream& operator<<(std::ostream &os, const Mod &mod) {
            switch (mod) {
            case Mod::MemoryMode:
                os << "MemoryMode";
                break;
            case Mod::MemoryMode8:
                os << "MemoryMode8";
                break;
            case Mod::MemoryMode16:
                os << "MemoryMode16";
                break;
            case Mod::RegisterMode:
                os << "RegisterMode";
                break;
            default:
                os << "Unknown";
                break;
            }
            return os;
    }
}

namespace OperationTypeNamespace {
    enum class OperationType {
      UNKNOWN,
      MOV_REG_MEMORY_TO_FROM_REG,
      MOV_IMMEDIATE_TO_REG_MEMORY,
      MOV_IMMEDIATE_TO_REG,
      MOV_IMMEDIATE_TO_MEMORY,
      MOV_MEMORY_TO_ACC,
      MOV_ACC_TO_MEMORY,
      MOV_REG_MEMORY_TO_SEGREG,
      MOV_SEGREG_TO_REG_MEMORY,
    };

    std::ostream& operator<<(std::ostream &os, const OperationType &op_type)
    {
        switch (op_type) {
        case OperationType::UNKNOWN:os << "UNKNOWN";
            break;
        case OperationType::MOV_REG_MEMORY_TO_FROM_REG:
        case OperationType::MOV_IMMEDIATE_TO_REG_MEMORY:
        case OperationType::MOV_IMMEDIATE_TO_REG:
        case OperationType::MOV_IMMEDIATE_TO_MEMORY:
        case OperationType::MOV_MEMORY_TO_ACC:
        case OperationType::MOV_ACC_TO_MEMORY:
        case OperationType::MOV_REG_MEMORY_TO_SEGREG:
        case OperationType::MOV_SEGREG_TO_REG_MEMORY:os << "MOV";
            break;
        default:
            break;
        }
        return os;
    }
}

class Operation {
public:
    Operation(std::string name, const OperationTypeNamespace::OperationType op_type):name{std::move(name)}, op_type{op_type} {
    }

    [[nodiscard]]
    auto get_name() const {
        return name;
    }

    [[nodiscard]]
    auto get_op_type() const {
        return op_type;
    }
private:
    std::string name;
    OperationTypeNamespace::OperationType op_type;
};

using namespace ModNamespace;
using namespace OperationTypeNamespace;

std::map<uint8_t, Operation> opcodes = {
        {0x88, Operation{"MOV REG8/MEM8, REG8", OperationType::MOV_REG_MEMORY_TO_FROM_REG}},
        {0x89, Operation{"MOV REG16/MEM16, REG16", OperationType::MOV_REG_MEMORY_TO_FROM_REG}},
        {0x8A, Operation{"MOV REG8, REG8/MEM8", OperationType::MOV_REG_MEMORY_TO_FROM_REG}},
        {0x8B, Operation{"MOV REG16, REG16/MEM16", OperationType::MOV_REG_MEMORY_TO_FROM_REG}},
        {0x8C, Operation{"MOV REG16/MEM16, SEGREG", OperationType::MOV_SEGREG_TO_REG_MEMORY}},
        // {0x8D, Operation{"LEA REG16, MEM", "lea"}},
        {0x8E, Operation{"MOV SEGREG, REG16/MEM16", OperationType::MOV_REG_MEMORY_TO_SEGREG}},

        {0xA0, Operation{"MOV AL, MEM8", OperationType::MOV_MEMORY_TO_ACC}},
        {0xA1, Operation{"MOV AX, MEM16", OperationType::MOV_MEMORY_TO_ACC}},
        {0xA2, Operation{"MOV MEM8, AL", OperationType::MOV_ACC_TO_MEMORY}},
        {0xA3, Operation{"MOV MEM16, AX", OperationType::MOV_ACC_TO_MEMORY}},

        {0xB0, Operation{"MOV REG8, IMM8", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xB1, Operation{"MOV REG8, IMM8", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xB2, Operation{"MOV REG8, IMM8", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xB3, Operation{"MOV REG8, IMM8", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xB4, Operation{"MOV REG8, IMM8", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xB5, Operation{"MOV REG8, IMM8", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xB6, Operation{"MOV REG8, IMM8", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xB7, Operation{"MOV REG8, IMM8", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xB8, Operation{"MOV REG16, IMM16", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xB9, Operation{"MOV REG16, IMM16", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xBA, Operation{"MOV REG16, IMM16", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xBB, Operation{"MOV REG16, IMM16", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xBC, Operation{"MOV REG16, IMM16", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xBD, Operation{"MOV REG16, IMM16", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xBE, Operation{"MOV REG16, IMM16", OperationType::MOV_IMMEDIATE_TO_REG}},
        {0xBF, Operation{"MOV REG16, IMM16", OperationType::MOV_IMMEDIATE_TO_REG}},

        {0xC6, Operation{"MOV MEM8, IMM8", OperationType::MOV_IMMEDIATE_TO_MEMORY}},
        {0xC7, Operation{"MOV MEM16, IMM16", OperationType::MOV_IMMEDIATE_TO_MEMORY}},
};

class Register {
public:
    Register(std::string name, uint8_t size): name{std::move(name)}, size{size} {
    }

    [[nodiscard]]
    std::string get_name() const {
        return name;
    }

    [[nodiscard]]
    uint8_t get_size() const{
        return size;
    }
private:
    std::string name;
    uint8_t size;
};


// Index is 0bW_XXX where W is the wide bit and XXX is the register mask
const std::array<Register, 16> REGISTERS = {
        Register{"AL", 8}, // 0b0_000
        Register{"CL", 8}, // 0b0_001
        Register{"DL", 8}, // 0b0_010
        Register{"BL", 8}, // 0b0_011
        Register{"AH", 8}, // 0b0_100
        Register{"CH", 8}, // 0b0_101
        Register{"DH", 8}, // 0b0_110
        Register{"BH", 8}, // 0b0_111
        Register{"AX", 16}, // 0b1_000
        Register{"CX", 16}, // 0b1_001
        Register{"DX", 16}, // 0b1_010
        Register{"BX", 16}, // 0b1_011
        Register{"SP", 16}, // 0b1_100
        Register{"BP", 16}, // 0b1_101
        Register{"SI", 16}, // 0b1_110
        Register{"DI", 16}, // 0b1_111
};

class EffectiveAddress {
public:
    explicit EffectiveAddress(std::string name):name{std::move(name)} {
    }

    [[nodiscard]]
    std::string get_name() const {
        return name;
    }
private:
    std::string name;
};

inline std::string generate_effective_address8_output(const EffectiveAddress& ea, const uint8_t third_byte) {
    return "[" + ea.get_name()  +disp_addr8_to_hex(third_byte) + "]";
}

inline std::string generate_effective_address16_output(const EffectiveAddress& ea, const uint8_t third_byte, const uint8_t forth_byte) {
    return "[" + ea.get_name() +disp_addr16_to_hex((static_cast<uint16_t>(forth_byte) << 8) | third_byte) + "]";
}

const std::array<EffectiveAddress, 8> EFFECTIVE_ADDRESSES = {
        EffectiveAddress{"BX+SI"}, // 0b000
        EffectiveAddress{"BX+DI"}, // 0b001
        EffectiveAddress{"BP+SI"}, // 0b010
        EffectiveAddress{"BP+DI"}, // 0b011
        EffectiveAddress{"SI"}, // 0b100
        EffectiveAddress{"DI"}, // 0b101
        EffectiveAddress{"BP"}, // 0b110
        EffectiveAddress{"BX"}, // 0b111
};

class FileCharStream {
public:
    explicit FileCharStream(const std::string &filename) :file{filename, std::ios::binary} {
        if (!file.is_open()) {
            throw std::runtime_error("Error: could not open file " + filename);
        }
    }

    std::istreambuf_iterator<char> iterator() {
        return std::istreambuf_iterator<char>{file};
    }
private:
    std::ifstream file;
};


Operation decode_operation(const uint8_t op_byte) {
    const auto operation = opcodes.find(op_byte);
    if (operation == opcodes.end()) {
        std::cerr << "Error: unknown operation " << byte_to_hex(op_byte) << std::endl;
        return Operation{"", OperationType::UNKNOWN};
    }

    return operation->second;
}

Register decode_register(const uint8_t reg_mask, const bool wide) {
    const auto i = static_cast<uint8_t>(wide) << 3 | reg_mask;
    return REGISTERS[i];
}

std::array<Register, 2> decode_registers_for_register_mode(const uint8_t second_byte, const bool wide, const bool direction) {
    auto reg1 = decode_register((second_byte >> 3) & 0b111, wide);
    auto reg2 = decode_register(second_byte & 0b111, wide);
    if (direction) {
        return {reg1, reg2};
    }
    return {reg2, reg1};
}

EffectiveAddress decode_effective_address(const uint8_t mask) {
    return EFFECTIVE_ADDRESSES[mask];
}

std::string decode_operands_for_mov_memory_mode(const uint8_t second_byte, const bool wide, const bool direction, std::istreambuf_iterator<char> &instructions) {
    auto reg = decode_register((second_byte >> 3) & 0b111, wide);
    auto ea = decode_effective_address(second_byte & 0b111);
    if ((second_byte & 0b111) == 0b110) {
        // Direct address case. Direct address is always a 16-bit address
        uint8_t addr_l = *(++instructions);
        uint8_t addr_h = *(++instructions);
        ea = EffectiveAddress{word_to_hex((static_cast<uint16_t>(addr_h) << 8) | addr_l)};
    }
    std::ostringstream oss;
    if (direction) {
        oss << reg.get_name() << ", [" << ea.get_name() << "]";
    } else {
        oss << "[" << ea.get_name() << "], " << reg.get_name();
    }
    return oss.str();
}

std::string decode_operands_for_mov_memory_mode_immediate8(const uint8_t second_byte, const uint8_t immediate) {
    auto ea = decode_effective_address(second_byte & 0b111);
    std::ostringstream oss;
    oss << "[" << ea.get_name() << "], " << "byte " << byte_to_hex(immediate);
    return oss.str();
}

std::string decode_operands_for_mov_memory_mode_immediate16(const uint8_t second_byte, const uint16_t immediate) {
    auto ea = decode_effective_address(second_byte & 0b111);
    std::ostringstream oss;
    oss << "[" << ea.get_name() << "], " << "word " << byte_to_hex(immediate);
    return oss.str();
}

std::string decode_operands_for_mov_memory_mode8_immediate8(const uint8_t second_byte, const uint8_t third_byte, const uint8_t immediate) {
    auto ea = decode_effective_address(second_byte & 0b111);
    std::ostringstream oss;
    oss << generate_effective_address8_output(ea, third_byte) << ", " << "byte " << byte_to_hex(immediate);
    return oss.str();
}

std::string decode_operands_for_mov_memory_mode8_immediate16(const uint8_t second_byte, const uint8_t third_byte, const uint16_t immediate) {
    auto ea = decode_effective_address(second_byte & 0b111);
    std::ostringstream oss;
    oss << generate_effective_address8_output(ea, third_byte) << ", " << "word " << byte_to_hex(immediate);
    return oss.str();
}

std::string decode_operands_for_mov_memory_mode16_immediate8(const uint8_t second_byte, const uint8_t third_byte, const uint8_t fourth_byte, const uint8_t immediate) {
    auto ea = decode_effective_address(second_byte & 0b111);
    std::ostringstream oss;
    oss << generate_effective_address16_output(ea, third_byte, fourth_byte) << ", " << "byte " << byte_to_hex(immediate);
    return oss.str();
}

std::string decode_operands_for_mov_memory_mode16_immediate16(const uint8_t second_byte, const uint8_t third_byte, const uint8_t fourth_byte, const uint16_t immediate) {
    auto ea = decode_effective_address(second_byte & 0b111);
    std::ostringstream oss;
    oss << generate_effective_address16_output(ea, third_byte, fourth_byte) << ", " << "word " << word_to_hex(immediate);
    return oss.str();
}

std::string decode_operands_for_mov_memory_mode8(const uint8_t second_byte, const bool wide, const bool direction, const uint8_t third_byte) {
    auto reg = decode_register((second_byte >> 3) & 0b111, wide);
    auto ea = decode_effective_address(second_byte & 0b111);
    std::ostringstream oss;
    if (direction) {
        oss << reg.get_name() << ", " << generate_effective_address8_output(ea, third_byte);
    } else {
        oss << generate_effective_address8_output(ea, third_byte) << ", " << reg.get_name();
    }
    return oss.str();
}


std::string decode_operands_for_mov_memory_mode16(const uint8_t second_byte, const bool wide, const bool direction, const uint8_t third_byte, const uint8_t forth_byte) {
    auto reg = decode_register((second_byte >> 3) & 0b111, wide);
    auto ea = decode_effective_address(second_byte & 0b111);
    std::ostringstream oss;
    if (direction) {
        oss << reg.get_name() << ", " << generate_effective_address16_output(ea, third_byte, forth_byte);
    } else {
        oss << generate_effective_address16_output(ea, third_byte, forth_byte) << ", " << reg.get_name();
    }
    return oss.str();
}

ModNamespace::Mod decode_mod(const uint8_t byte) {
    // decode mod
    return static_cast<ModNamespace::Mod>(byte >> 6);
}

std::string decode_operands_for_mov_reg_memory_to_from_reg(uint8_t first_byte, std::istreambuf_iterator<char> &instructions) {
    // Check 0th bit to determine wide or not
    bool wide = first_byte & 0b1;
    // Check 1st bit to determine direction
    bool direction = first_byte & 0b10;

    std::ostringstream oss;

    uint8_t second_byte = *instructions;
    auto mode = decode_mod(second_byte);
    switch (mode) {
        case Mod::MemoryMode: {
            oss << decode_operands_for_mov_memory_mode(second_byte, wide, direction, instructions);
            break;
        }
        case Mod::MemoryMode8: {
            uint8_t third_byte = *(++instructions);
            oss << decode_operands_for_mov_memory_mode8(second_byte, wide, direction, third_byte);
            break;
        }
        case Mod::MemoryMode16: {
            uint8_t third_byte = *(++instructions);
            uint8_t forth_byte = *(++instructions);
            oss << decode_operands_for_mov_memory_mode16(second_byte, wide, direction, third_byte, forth_byte);
            break;
        }
        case Mod::RegisterMode: {
            auto registers = decode_registers_for_register_mode(second_byte, wide, direction);
            oss << registers[0].get_name() << ", " << registers[1].get_name();
            break;
        }
    }
    return oss.str();
}

std::string decode_operands_for_mov_immediate_to_reg(const uint8_t first_byte, std::istreambuf_iterator<char> &instructions) {
    // Check 3d bit to determine wide or not
    bool wide = first_byte & 0b1000;

    // Get the REG
    auto reg = decode_register(first_byte & 0b111, wide);

    std::ostringstream oss;

    uint8_t second_byte = *instructions;
    if (wide) {
        uint8_t third_byte = *(++instructions);
        uint16_t immediate = (static_cast<u_int16_t>(third_byte) << 8) | second_byte;
        oss << reg.get_name() << ", " << word_to_hex(immediate);
    } else {
        uint8_t immediate = second_byte;
        oss << reg.get_name() << ", " << byte_to_hex(immediate);
    }
    return oss.str();
}

std::string decode_operands_for_mov_immediate_to_memory(const uint8_t first_byte, std::istreambuf_iterator<char> &instructions) {
    // Check 0th bit to determine wide or not
    bool wide = first_byte & 0b1;

    std::ostringstream oss;

    const uint8_t second_byte = *instructions;
    // Get MODE
    auto mode = decode_mod(second_byte);
    switch (mode) {
    case Mod::MemoryMode: {
        if (wide) {
            uint8_t third_byte = *(++instructions);
            uint8_t forth_byte = *(++instructions);
            oss << decode_operands_for_mov_memory_mode_immediate16(second_byte, (static_cast<uint16_t>(forth_byte) << 8) | third_byte);
        } else {
            uint8_t third_byte = *(++instructions);
            oss << decode_operands_for_mov_memory_mode_immediate8(second_byte, third_byte);
        }
        break;
    }
    case Mod::MemoryMode8: {
        if (wide) {
            uint8_t third_byte = *(++instructions);
            uint8_t forth_byte = *(++instructions);
            uint8_t fifth_byte = *(++instructions);
            oss << decode_operands_for_mov_memory_mode8_immediate16(second_byte, third_byte, (static_cast<uint16_t>(fifth_byte) << 8) | forth_byte);
        } else {
            uint8_t third_byte = *(++instructions);
            uint8_t forth_byte = *(++instructions);
            oss << decode_operands_for_mov_memory_mode8_immediate8(second_byte, third_byte, forth_byte);
        }
        break;
    }
    case Mod::MemoryMode16: {
        if (wide) {
            uint8_t third_byte = *(++instructions);
            uint8_t forth_byte = *(++instructions);
            uint8_t fifth_byte = *(++instructions);
            uint8_t sixth_byte = *(++instructions);
            oss << decode_operands_for_mov_memory_mode16_immediate16(second_byte, third_byte, forth_byte, (static_cast<uint16_t>(sixth_byte) << 8) | fifth_byte);
        } else {
            uint8_t third_byte = *(++instructions);
            uint8_t forth_byte = *(++instructions);
            uint8_t fifth_byte = *(++instructions);
            oss << decode_operands_for_mov_memory_mode16_immediate8(second_byte, third_byte, forth_byte, fifth_byte);
        }
        break;
    }
    }
    return oss.str();
}

std::string decode_operands_for_mov_acc_memory(const uint8_t first_byte, std::istreambuf_iterator<char> &instructions) {
    // Get direction
    bool direction = first_byte & 0b10;

    // Get wide
    bool wide = first_byte & 0b1;

    std::ostringstream oss;
    uint8_t addr_lo = *(++instructions);
    uint8_t addr_hi = *(++instructions);
    auto acc_name = wide ? "AX" : "AL";
    if (direction) {
        oss << "[" << word_to_hex((static_cast<uint16_t>(addr_hi) << 8) | addr_lo) << "], " << acc_name;
    } else {
        oss << acc_name << ", [" << word_to_hex((static_cast<uint16_t>(addr_hi) << 8) | addr_lo) << "]";
    }
    return oss.str();
}

void disassemble(uint16_t i, std::istreambuf_iterator<char> &instructions) {
    uint8_t first_byte = *instructions;
    auto operation = decode_operation(first_byte);
    switch (operation.get_op_type()) {

    case OperationType::MOV_REG_MEMORY_TO_FROM_REG:
        ++instructions;
        std::cout  << operation.get_op_type() << " " << decode_operands_for_mov_reg_memory_to_from_reg(first_byte, instructions) << std::endl;
        break;

    case OperationType::MOV_IMMEDIATE_TO_REG:
        ++instructions;
        std::cout << operation.get_op_type() << " " << decode_operands_for_mov_immediate_to_reg(first_byte, instructions) << std::endl;
        break;

    case OperationType::MOV_IMMEDIATE_TO_MEMORY:
        ++instructions;
        std::cout << operation.get_op_type() << " " << decode_operands_for_mov_immediate_to_memory(first_byte, instructions) << std::endl;
        break;

    case OperationType::MOV_MEMORY_TO_ACC:
    case OperationType::MOV_ACC_TO_MEMORY:
        std::cout << operation.get_op_type() << " " << decode_operands_for_mov_acc_memory(first_byte, instructions) << std::endl;
        break;

    case OperationType::UNKNOWN:
        std::cerr << "Error: unknown operation type" << std::endl;
        break;
    default:
        // Probably some operations don't have operands
        std::cerr << "Error: operation type " << operation.get_name() << " not implemented" << std::endl;
        break;
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
        return 1;
    }

    const auto filename = argv[1];

    auto stream = FileCharStream{filename};
    auto instructions = stream.iterator();

    std::cout << "bits 16" << std::endl;
    auto i = 0;
    while (instructions != std::istreambuf_iterator<char>{}) {
        disassemble(i, instructions);
        ++instructions;
        ++i;
    }
    return 0;
}
