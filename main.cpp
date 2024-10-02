#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <capstone/capstone.h>
#include <fstream>
#include <ncurses.h>

class Disassembler {
public:
    Disassembler(cs_arch arch, cs_mode mode) {
        if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
            throw std::runtime_error("Failed to initialize Capstone.");
        }
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    }

    ~Disassembler() {
        cs_close(&handle);
    }

    std::vector<cs_insn> disassemble(const uint8_t* code, size_t size, uint64_t address = 0x1000) {
        cs_insn* insn;
        size_t count = cs_disasm(handle, code, size, address, 0, &insn);
        std::vector<cs_insn> instructions(insn, insn + count);
        cs_free(insn, count);
        return instructions;
    }

private:
    csh handle;
};

class BasicBlock {
public:
    uint64_t start, end;
    std::vector<cs_insn> instructions;

    BasicBlock(uint64_t start) : start(start), end(0) {}

    void addInstruction(const cs_insn& inst) {
        instructions.push_back(inst);
        end = inst.address + inst.size;
    }
};

class ControlFlowGraph {
public:
    std::map<uint64_t, BasicBlock*> blocks;
    std::map<uint64_t, std::set<uint64_t>> edges;

    void addBasicBlock(BasicBlock* block) {
        blocks[block->start] = block;
    }

    void addEdge(uint64_t from, uint64_t to) {
        edges[from].insert(to);
    }

    std::vector<BasicBlock*> getBlocks() {
        std::vector<BasicBlock*> blockList;
        for (const auto& pair : blocks) {
            blockList.push_back(pair.second);
        }
        return blockList;
    }
};

class Decompiler {
public:
    std::vector<std::string> decompile(ControlFlowGraph& cfg) {
        std::vector<std::string> decompiledOutput;
        for (const auto& [start, block] : cfg.blocks) {
            decompiledOutput.push_back(decompileBasicBlock(block));
        }
        return decompiledOutput;
    }

private:
    std::string decompileBasicBlock(BasicBlock* block) {
        std::string blockCode = "Block 0x" + intToHex(block->start) + "-0x" + intToHex(block->end) + ":\n";
        for (const auto& inst : block->instructions) {
            blockCode += "  0x" + intToHex(inst.address) + ": ";
            if (strcmp(inst.mnemonic, "mov") == 0) {
                blockCode += "Assignment: " + std::string(inst.op_str) + "\n";
            } else if (strcmp(inst.mnemonic, "call") == 0) {
                blockCode += "Function Call: " + std::string(inst.op_str) + "\n";
            } else if (strcmp(inst.mnemonic, "jmp") == 0) {
                blockCode += "Unconditional Jump to: " + std::string(inst.op_str) + "\n";
            } else if (strcmp(inst.mnemonic, "ret") == 0) {
                blockCode += "Return statement\n";
            } else {
                blockCode += std::string(inst.mnemonic) + " " + std::string(inst.op_str) + "\n";
            }
        }
        return blockCode;
    }

    std::string intToHex(uint64_t val) {
        std::stringstream ss;
        ss << std::hex << val;
        return ss.str();
    }
};

// === TUI === //
void displayInstructions(WINDOW* win, const std::vector<cs_insn>& instructions, int currentLine) {
    wclear(win);
    box(win, 0, 0);
    mvwprintw(win, 0, 1, "Disassembled Instructions");

    int maxLines = getmaxy(win) - 2;
    for (int i = 0; i < maxLines && currentLine + i < instructions.size(); i++) {
        const auto& inst = instructions[currentLine + i];
        mvwprintw(win, i + 1, 2, "0x%" PRIx64 ": %s %s", inst.address, inst.mnemonic, inst.op_str);
    }

    wrefresh(win);
}

void displayCFG(WINDOW* win, const ControlFlowGraph& cfg, int currentBlock) {
    wclear(win);
    box(win, 0, 0);
    mvwprintw(win, 0, 1, "Control Flow Graph");

    int maxLines = getmaxy(win) - 2;
    auto blocks = cfg.getBlocks();
    for (int i = 0; i < maxLines && currentBlock + i < blocks.size(); i++) {
        const auto& block = blocks[currentBlock + i];
        mvwprintw(win, i + 1, 2, "Block 0x%" PRIx64 "-0x%" PRIx64, block->start, block->end);
    }

    wrefresh(win);
}

void displayDecompiled(WINDOW* win, const std::vector<std::string>& decompiledCode, int currentLine) {
    wclear(win);
    box(win, 0, 0);
    mvwprintw(win, 0, 1, "Decompiled Code");

    int maxLines = getmaxy(win) - 2;
    for (int i = 0; i < maxLines && currentLine + i < decompiledCode.size(); i++) {
        mvwprintw(win, i + 1, 2, decompiledCode[currentLine + i].c_str());
    }

    wrefresh(win);
}
std::vector<uint8_t> readBinary(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), {});
}

ControlFlowGraph buildCFG(const std::vector<cs_insn>& instructions) {
    ControlFlowGraph cfg;
    BasicBlock* currentBlock = nullptr;

    for (const auto& inst : instructions) {
        if (!currentBlock) {
            currentBlock = new BasicBlock(inst.address);
        }

        currentBlock->addInstruction(inst);

        if (strcmp(inst.mnemonic, "jmp") == 0 || strcmp(inst.mnemonic, "je") == 0 || strcmp(inst.mnemonic, "jne") == 0) {
            uint64_t target = inst.detail->x86.operands[0].imm;
            cfg.addEdge(currentBlock->start, target);
            cfg.addBasicBlock(currentBlock);
            currentBlock = nullptr;
        }
    }

    if (currentBlock) {
        cfg.addBasicBlock(currentBlock);
    }

    return cfg;
}
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <binary file>" << std::endl;
        return 1;
    }

    try {
        Disassembler disassembler(CS_ARCH_X86, CS_MODE_64);
        auto binary = readBinary(argv[1]);
        if (binary.empty()) {
            std::cerr << "Failed to load binary file: " << argv[1] << std::endl;
            return 1;
        }
        auto instructions = disassembler.disassemble(binary.data(), binary.size());
        ControlFlowGraph cfg = buildCFG(instructions);
        Decompiler decompiler;
        auto decompiledCode = decompiler.decompile(cfg);
        initscr();
        cbreak();
        noecho();
        curs_set(0);
        WINDOW* instructionWin = newwin(LINES / 3, COLS, 0, 0);
        WINDOW* cfgWin = newwin(LINES / 3, COLS, LINES / 3, 0);
        WINDOW* decompiledWin = newwin(LINES / 3, COLS, 2 * LINES / 3, 0);

        int currentLineInstr = 0;
        int currentLineCFG = 0;
        int currentLineDecomp = 0;

        while (true) {
            displayInstructions(instructionWin, instructions, currentLineInstr);
            displayCFG(cfgWin, cfg, currentLineCFG);
            displayDecompiled(decompiledWin, decompiledCode, currentLineDecomp);

            int ch = getch();
            if (ch == 'q') break;
            else if (ch == KEY_DOWN) currentLineInstr++;
            else if (ch == KEY_UP) currentLineInstr = std::max(0, currentLineInstr - 1);
            else if (ch == 'c') currentLineCFG++;
            else if (ch == 'd') currentLineDecomp++;
        }
        endwin();
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }

    return 0;
}
