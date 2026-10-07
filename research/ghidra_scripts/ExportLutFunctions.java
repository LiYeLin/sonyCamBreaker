// Targeted, offline disassembly/decompilation. Never executes imported code.
// @category SonyResearch
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.math.BigInteger;

public class ExportLutFunctions extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path manifest = Paths.get(args[0]);
        Path output = Paths.get(args[1]);
        boolean thumb = args.length > 2 && args[2].equals("thumb");
        // Raw BinaryLoader sets the block origin separately from the program image base.
        long rebaseDelta = thumb ? 0x108000L - currentProgram.getMemory().getMinAddress().getOffset()
                                 : -currentProgram.getImageBase().getOffset();
        Files.createDirectories(output);
        Set<String> ownedNames = new HashSet<>();
        for (String line : Files.readAllLines(manifest)) {
            if (!line.isBlank() && !line.startsWith("#")) ownedNames.add(line.trim().split("\\s+")[2]);
        }
        // Ghidra rebases ET_DYN to 0x100000 by default. Our manifest uses original ELF VAs.
        if (rebaseDelta != 0) {
            List<Address> stale = new ArrayList<>();
            FunctionIterator old = currentProgram.getFunctionManager().getFunctions(true);
            while (old.hasNext()) {
                Function f = old.next();
                if (f.getSymbol().getSource() == SourceType.USER_DEFINED && ownedNames.contains(f.getName())) stale.add(f.getEntryPoint());
            }
            for (Address address : stale) currentProgram.getFunctionManager().removeFunction(address);
            currentProgram.setImageBase(currentProgram.getImageBase().add(rebaseDelta), true);
        }
        List<Function> functions = new ArrayList<>();
        for (String line : Files.readAllLines(manifest)) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] fields = line.trim().split("\\s+");
            Address entry = toAddr(Long.decode(fields[0]));
            Address end = toAddr(Long.decode(fields[1]) - 1);
            AddressSet body = new AddressSet(entry, end);
            if (thumb) {
                // Earlier flow-following may have decoded a new candidate in ARM mode.
                // Clear only code units inside this explicitly reviewed Thumb range.
                currentProgram.getListing().clearCodeUnits(entry, end, false);
                currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"), entry, end, BigInteger.ONE);
            }
            // Bounded linear disassembly also exposes switch destinations. Function ranges
            // come from reviewed assembly; they are not guesses based on the nearest prologue.
            for (Address pc = entry; pc.compareTo(end) <= 0; pc = pc.add(thumb ? 2 : 4)) {
                if (currentProgram.getListing().getInstructionContaining(pc) == null) {
                    DisassembleCommand command = new DisassembleCommand(pc, body, true);
                    command.applyTo(currentProgram, monitor);
                }
            }
            Function f = getFunctionAt(entry);
            if (f == null) {
                f = currentProgram.getFunctionManager().createFunction(fields[2], entry, body, SourceType.USER_DEFINED);
            } else {
                f.setName(fields[2], SourceType.USER_DEFINED);
                f.setBody(body);
            }
            // Reviewed body ends in __assert_fail@plt; do not fall through into the next function.
            if (fields[2].equals("assertion_failure_noreturn")) f.setNoReturn(true);
            functions.add(f);
        }
        if (!thumb) {
            for (Function f : functions) {
                InstructionIterator iterator = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (iterator.hasNext()) {
                    Instruction instruction = iterator.next();
                    if (instruction.getMnemonicString().equals("b")) {
                        for (Address target : instruction.getFlows()) {
                            if (target.getOffset() == 0x35aa4b4L) instruction.setFlowOverride(FlowOverride.CALL_RETURN);
                        }
                    }
                }
            }
        }
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            for (Function f : functions) {
                String prefix = f.getEntryPoint() + "_" + f.getName();
                byte[] original = new byte[(int)f.getBody().getNumAddresses()];
                currentProgram.getMemory().getBytes(f.getEntryPoint(), original);
                Files.writeString(output.resolve(prefix + ".bytes.hex"),
                    HexFormat.of().formatHex(original) + "\n", StandardCharsets.UTF_8);
                StringBuilder assembly = new StringBuilder();
                InstructionIterator instructions = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (instructions.hasNext()) {
                    Instruction ins = instructions.next();
                    assembly.append(ins.getAddress()).append("  ").append(ins).append("\n");
                }
                Files.writeString(output.resolve(prefix + ".asm"), assembly.toString(), StandardCharsets.UTF_8);
                DecompileResults result = decompiler.decompileFunction(f, 45, monitor);
                String c = result.decompileCompleted() ? result.getDecompiledFunction().getC() : result.getErrorMessage();
                Files.writeString(output.resolve(prefix + ".c"),
                    "/* Machine-generated pseudocode, not original source. Types require validation. */\n" + c,
                    StandardCharsets.UTF_8);
                println("EXPORTED " + prefix + " completed=" + result.decompileCompleted());
            }
        } finally { decompiler.dispose(); }
    }
}
