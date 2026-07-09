/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers the CS-relative switch tables in RTLink/Plus resident code, which the stock
 * decompiler-driven switch analysis gets wrong.
 * <p>
 * <b>Why the stock path fails.</b> A resident logical segment is based at a paragraph that is not a
 * 64KB-page boundary (e.g. {@code 1aea:000b}). The x86 {@code currentCS} subconstructor
 * ({@code ia.sinc}) does not read the CS register; it recomputes a code segment from the program
 * counter as {@code (inst_next >> 4) & 0xf000}, which for such a block yields the enclosing page
 * ({@code 0x1000}) instead of the real paragraph. That recompute exists on purpose — {@code CALLF}
 * ({@code ptr1616}) writes the callee's segment into CS and nothing restores it on return, so CS is
 * untrustworthy — but it is correct only when a code segment happens to start on a page boundary.
 * The write-back also lands <i>before</i> the memory operand's address is built, so both the table
 * load and the jump target resolve against the page segment: {@code JMP word ptr CS:[BX+0x22]} at
 * {@code 1aea:001d} reads its table at {@code 1000:0022} rather than {@code 1aea:0022} and scatters
 * computed-jump references across unrelated segments.
 * <p>
 * <b>What this does.</b> It matches the dispatch idiom, reads the table at the block's true
 * paragraph, and lays down the correct {@code COMPUTED_JUMP} references itself. That both fixes the
 * flow and — because {@link DecompilerSwitchAnalyzer} skips any computed branch that already carries
 * computed references — stops the stock analyzer from ever disassembling the bogus targets. It must
 * therefore run <i>before</i> {@code CODE_ANALYSIS}: once the wrong references and their wrong
 * disassembly exist, nothing rewrites them.
 * <p>
 * Fixing the references leaves the decompiler's own p-code still reading the table at the page
 * segment. {@link RTLinkSwitchOverrideAnalyzer} completes the repair once functions exist.
 * <p>
 * Overlay blocks are deliberately untouched: they are based at {@code 1000:0000}, so the paragraph
 * {@code currentCS} synthesises is already the right one.
 */
public class RTLinkSwitchTableAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Switch Table";
	private static final String DESCRIPTION =
		"Recovers CS-relative jump tables in resident code whose segment is not 64KB-page " +
			"aligned, which the x86 currentCS constructor resolves against the wrong paragraph.";

	/** {@code JMP word ptr CS:[BX + disp16]} — CS prefix, opcode FF /4, mod=10 r/m=111. */
	private static final byte[] DISPATCH_OPCODE = { 0x2e, (byte) 0xff, (byte) 0xa7 };
	private static final int DISPATCH_LENGTH = 5;

	/** Instructions to look back over for the {@code CMP} that bounds the switch index. */
	private static final int GUARD_SCAN_LIMIT = 8;

	/** Refuse absurd tables rather than trusting a mis-parsed guard. */
	private static final int MAX_TABLE_ENTRIES = 512;

	public RTLinkSwitchTableAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Before CODE_ANALYSIS, which is where DecompilerSwitchAnalyzer runs. It ignores any
		// computed branch that already has computed references, so winning this race is what
		// keeps the bogus targets from being disassembled into other segments.
		setPriority(AnalysisPriority.CODE_ANALYSIS.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return RTLinkOverlayAnalyzer.isSegmentedMzProgram(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		ReferenceManager refManager = program.getReferenceManager();
		AddressSet targets = new AddressSet();
		int recovered = 0;

		InstructionIterator instructions = program.getListing().getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();

			List<Address> destinations = recoverTable(program, instruction);
			if (destinations == null || hasComputedReference(refManager, instruction)) {
				continue;
			}
			for (Address destination : destinations) {
				refManager.addMemoryReference(instruction.getMinAddress(), destination,
					RefType.COMPUTED_JUMP, SourceType.ANALYSIS, Reference.MNEMONIC);
				targets.addRange(destination, destination);
			}
			recovered++;
		}

		if (recovered == 0) {
			return true;
		}
		// Disassemble the real targets now; leaving them undefined would let a later pass drift
		// back into the table bytes.
		new DisassembleCommand(targets, null, true).applyTo(program, monitor);

		String msg = String.format("RTLink/Plus: Recovered %d CS-relative switch table(s)",
			recovered);
		Msg.info(this, msg);
		log.appendMsg(msg);
		return true;
	}

	/**
	 * Returns the switch destinations for {@code instruction} if it is a resident CS-relative
	 * dispatch whose table can be read with confidence, otherwise null.
	 * <p>
	 * Shared with {@link RTLinkSwitchOverrideAnalyzer} so both passes agree, byte for byte, on
	 * which sites are dispatchers and where they go.
	 */
	static List<Address> recoverTable(Program program, Instruction instruction) {
		MemoryBlock block = residentUnalignedBlock(program, instruction.getMinAddress());
		if (block == null) {
			return null;
		}
		int displacement = dispatchDisplacement(instruction);
		if (displacement < 0) {
			return null;
		}
		int entries = tableEntryCount(instruction, block);
		if (entries < 0) {
			return null;
		}

		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		int segment = ((SegmentedAddress) block.getStart()).getSegment();

		// The table and every entry must live inside the segment they are addressed from; a
		// 16-bit offset that would wrap means the guard was misread, so give up rather than
		// invent targets.
		long lastByte = (long) displacement + 2L * entries - 1;
		if (lastByte > 0xffffL) {
			return null;
		}
		Address table = space.getAddress(segment, displacement);
		if (!block.contains(table) || !block.contains(space.getAddress(segment, (int) lastByte))) {
			return null;
		}

		Set<Address> destinations = new LinkedHashSet<>();
		try {
			for (int i = 0; i < entries; i++) {
				int offset = program.getMemory().getShort(table.add(2L * i)) & 0xffff;
				Address destination = space.getAddress(segment, offset);
				if (!block.contains(destination)) {
					return null;
				}
				destinations.add(destination);
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
		return new ArrayList<>(destinations);
	}

	/**
	 * The block containing {@code address}, if it is resident code based at a paragraph that is not
	 * a 64KB-page boundary — exactly the case {@code currentCS} gets wrong. Page-aligned blocks and
	 * overlays already resolve correctly and must not be touched.
	 */
	private static MemoryBlock residentUnalignedBlock(Program program, Address address) {
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block == null || block.isOverlay() || !block.isExecute()) {
			return null;
		}
		if (!(block.getStart() instanceof SegmentedAddress start)) {
			return null;
		}
		int pageSegment = (int) ((start.getOffset() >> 4) & 0xf000L);
		return start.getSegment() == pageSegment ? null : block;
	}

	/** The {@code disp16} of a {@code JMP word ptr CS:[BX + disp16]}, or -1 if not one. */
	private static int dispatchDisplacement(Instruction instruction) {
		if (!instruction.getFlowType().isComputed() || !instruction.getFlowType().isJump()) {
			return -1;
		}
		byte[] bytes;
		try {
			bytes = instruction.getBytes();
		}
		catch (MemoryAccessException e) {
			return -1;
		}
		if (bytes.length != DISPATCH_LENGTH) {
			return -1;
		}
		for (int i = 0; i < DISPATCH_OPCODE.length; i++) {
			if (bytes[i] != DISPATCH_OPCODE[i]) {
				return -1;
			}
		}
		return (bytes[3] & 0xff) | ((bytes[4] & 0xff) << 8);
	}

	/**
	 * Table length from the {@code CMP index,N} guard that bounds the switch, or -1 when the idiom
	 * does not match.
	 * <p>
	 * The scaling pair is required, not incidental: {@code SHL index,1} followed by
	 * {@code XCHG index,BX} is what proves the index addresses a table of <i>words</i>, which is
	 * the whole basis for reading {@code N + 1} shorts. The guard is then the nearest preceding
	 * {@code CMP} of that same index register.
	 * <p>
	 * Following the value rather than the instruction layout matters. Both
	 * {@code CMP AX,N; JA default} and {@code CMP AX,N; JBE body; JMP default} occur, and the
	 * latter puts an unconditional {@code JMP} between the guard and the scaling — skipping over
	 * it is safe, because any redefinition of the index register in between aborts the match.
	 * <p>
	 * Dispatches with no {@code CMP} at all are rejected: {@code 1d1d:19c0} indexes its table from
	 * an {@code XLAT} result, so nothing in the instruction stream bounds the table and the entry
	 * count would be a guess.
	 */
	private static int tableEntryCount(Instruction dispatch, MemoryBlock block) {
		Instruction exchange = dispatch.getPrevious();
		if (exchange == null || !"XCHG".equals(exchange.getMnemonicString())) {
			return -1;
		}
		Register index = otherRegister(exchange, "BX");
		if (index == null) {
			return -1;
		}
		Instruction scale = exchange.getPrevious();
		if (scale == null || !"SHL".equals(scale.getMnemonicString()) ||
			!index.equals(scale.getRegister(0)) || !isOne(scale.getScalar(1))) {
			return -1;
		}

		Instruction instruction = scale.getPrevious();
		for (int i = 0; i < GUARD_SCAN_LIMIT && instruction != null; i++) {
			if (!block.contains(instruction.getMinAddress())) {
				return -1;
			}
			if ("CMP".equals(instruction.getMnemonicString()) &&
				index.equals(instruction.getRegister(0))) {
				Scalar bound = instruction.getScalar(1);
				if (bound == null) {
					return -1;
				}
				long entries = bound.getUnsignedValue() + 1;
				return entries > MAX_TABLE_ENTRIES ? -1 : (int) entries;
			}
			if (defines(instruction, index)) {
				return -1; // the compared value is not the value that indexes the table
			}
			instruction = instruction.getPrevious();
		}
		return -1;
	}

	/** The register operand of {@code instruction} that is not {@code name}, or null. */
	private static Register otherRegister(Instruction instruction, String name) {
		Register first = instruction.getRegister(0);
		Register second = instruction.getRegister(1);
		if (first == null || second == null) {
			return null;
		}
		if (name.equals(first.getName())) {
			return second;
		}
		return name.equals(second.getName()) ? first : null;
	}

	private static boolean isOne(Scalar scalar) {
		return scalar != null && scalar.getUnsignedValue() == 1;
	}

	/** True if {@code instruction} writes {@code register}. */
	private static boolean defines(Instruction instruction, Register register) {
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register written && written.equals(register)) {
				return true;
			}
		}
		return false;
	}

	/** True if Ghidra already recorded a computed flow from this branch. */
	private static boolean hasComputedReference(ReferenceManager refManager,
			Instruction instruction) {
		for (Reference reference : refManager.getReferencesFrom(instruction.getMinAddress())) {
			if (reference.getReferenceType().isComputed()) {
				return true;
			}
		}
		return false;
	}
}
