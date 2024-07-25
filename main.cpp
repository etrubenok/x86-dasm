#include <iostream>
#include <utility>
#include <vector>
#include <fstream>
#include <iomanip>
#include <map>

std::string byte_to_hex(const uint8_t number) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(2) << std::setfill('0') << (static_cast<int>(number) & 0xFF);
    return oss.str();
}

std::string word_to_hex(const uint16_t number) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << (static_cast<int>(number) & 0xFFFF);
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


std::map<uint8_t, Register> slim_registers = {
        {0b000, Register{"AL", 8}},
        {0b001, Register{"CL", 8}},
        {0b010, Register{"DL", 8}},
        {0b011, Register{"BL", 8}},
        {0b100, Register{"AH", 8}},
        {0b101, Register{"CH", 8}},
        {0b110, Register{"DH", 8}},
        {0b111, Register{"BH", 8}},
};

std::map<uint8_t, Register> wide_registers = {
        {0b000, Register{"AX", 16}},
        {0b001, Register{"CX", 16}},
        {0b010, Register{"DX", 16}},
        {0b011, Register{"BX", 16}},
        {0b100, Register{"SP", 16}},
        {0b101, Register{"BP", 16}},
        {0b110, Register{"SI", 16}},
        {0b111, Register{"DI", 16}},
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

std::map<uint8_t, EffectiveAddress> effective_addresses = {
        {0b000, EffectiveAddress{"BX+SI"}},
        {0b001, EffectiveAddress{"BX+DI"}},
        {0b010, EffectiveAddress{"BP+SI"}},
        {0b011, EffectiveAddress{"BP+DI"}},
        {0b100, EffectiveAddress{"SI"}},
        {0b101, EffectiveAddress{"DI"}},
        {0b110, EffectiveAddress{"BP"}},
        {0b111, EffectiveAddress{"BX"}},
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
    if (wide) {
        auto reg = wide_registers.find(reg_mask);
        if (reg == wide_registers.end()) {
            std::cerr << "Error: unknown register " << byte_to_hex(reg_mask) << std::endl;
            return Register{"", 0};
        }
        return reg->second;
    } else {
        auto reg = slim_registers.find(reg_mask);
        if (reg == slim_registers.end()) {
            std::cerr << "Error: unknown register "<< byte_to_hex(reg_mask) << std::endl;
            return Register{"", 0};
        }
        return reg->second;
    }
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
    auto ea = effective_addresses.find(mask);
    if (ea == effective_addresses.end()) {
        std::cerr << "Error: unknown effective address " << byte_to_hex(mask) << std::endl;
        return EffectiveAddress{""};
    }
    return ea->second;
}

std::string decode_operands_for_mov_memory_mode(uint8_t second_byte, const bool wide, const bool direction) {
    auto reg = decode_register((second_byte >> 3) & 0b111, wide);
    auto ea = decode_effective_address(second_byte & 0b111);
    std::ostringstream oss;
    if (direction) {
        oss << reg.get_name() << ", [" << ea.get_name() << "]";
    } else {
        oss << "[" << ea.get_name() << "], " << reg.get_name();
    }
    return oss.str();
}

std::string decode_operands_for_mov_memory_mode8(const uint8_t second_byte, const bool wide, const bool direction, const uint8_t third_byte) {
    auto reg = decode_register((second_byte >> 3) & 0b111, wide);
    auto ea = decode_effective_address(second_byte & 0b111);
    std::ostringstream oss;
    if (direction) {
        oss << reg.get_name() << ", [" << ea.get_name() << "+" << byte_to_hex(third_byte) << "]";
    } else {
        oss << "[" << ea.get_name() << "+" << byte_to_hex(third_byte) << "], " << reg.get_name();
    }
    return oss.str();
}

std::string decode_operands_for_mov_memory_mode16(const uint8_t second_byte, const bool wide, const bool direction, const uint8_t third_byte, const uint8_t forth_byte) {
    auto reg = decode_register((second_byte >> 3) & 0b111, wide);
    auto ea = decode_effective_address(second_byte & 0b111);
    std::ostringstream oss;
    if (direction) {
        oss << reg.get_name() << ", [" << ea.get_name() << "+" << word_to_hex((static_cast<uint16_t>(forth_byte) << 8) | third_byte) << "]";
    } else {
        oss << "[" << ea.get_name() << "+" << word_to_hex((static_cast<uint16_t>(forth_byte) << 8) | third_byte) << "], " << reg.get_name();
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
            oss << decode_operands_for_mov_memory_mode(second_byte, wide, direction);
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

std::string decode_operands_for_mov_immediate_to_reg(uint8_t first_byte, std::istreambuf_iterator<char> &instructions) {
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

void disassemble(std::istreambuf_iterator<char> &instructions) {
    uint8_t first_byte = *instructions;
    auto operation = decode_operation(first_byte);
    switch (operation.get_op_type()) {

    case OperationType::MOV_REG_MEMORY_TO_FROM_REG:
        ++instructions;
        std::cout << operation.get_op_type() << " " << decode_operands_for_mov_reg_memory_to_from_reg(first_byte, instructions) << std::endl;
        break;

    case OperationType::MOV_IMMEDIATE_TO_REG:
        ++instructions;
        std::cout << operation.get_op_type() << " " << decode_operands_for_mov_immediate_to_reg(first_byte, instructions) << std::endl;
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

    std::string filename = argv[1];

    auto stream = FileCharStream{filename};
    auto instructions = stream.iterator();

    std::cout << "bits 16" << std::endl;
    while (instructions != std::istreambuf_iterator<char>{}) {
        disassemble(instructions);
        ++instructions;
    }
    return 0;
}
