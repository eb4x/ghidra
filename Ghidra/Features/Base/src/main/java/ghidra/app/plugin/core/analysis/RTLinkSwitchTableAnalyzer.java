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
import ghidra.program.model.listing.Listing;
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
 * <b>Overlay blocks</b> fail differently. They are based at {@code 1000:0000}, so the paragraph
 * {@code currentCS} synthesises is right — but only for the page's <i>first</i> module. RTLink
 * packs several link-time modules into one page, and each executes with CS = page frame + its own
 * base paragraph, so a dispatch in a later module reads its table (and interprets every entry)
 * relative to that module base, which nothing in the address stream reveals. The bases are
 * recorded per block by {@link RTLinkOverlayAnalyzer} when the overlay is created; the module
 * containing the dispatch is the one whose base is nearest at or below it.
 */
public class RTLinkSwitchTableAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Switch Table";
	private static final String DESCRIPTION =
		"Recovers CS-relative jump tables in resident code whose segment is not 64KB-page " +
			"aligned, which the x86 currentCS constructor resolves against the wrong paragraph, " +
			"and module-relative jump tables in overlay pages.";

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

		// Msg.info only — see RTLinkSwitchOverrideAnalyzer: a success count in the analysis
		// MessageLog pops the "warnings/errors issued during analysis" dialog.
		Msg.info(this, String.format("RTLink/Plus: Recovered %d CS-relative switch table(s)",
			recovered));
		return true;
	}

	/**
	 * Returns the switch destinations for {@code instruction} if it is a CS-relative
	 * dispatch whose table can be read with confidence, otherwise null.
	 * <p>
	 * Shared with {@link RTLinkSwitchOverrideAnalyzer} so both passes agree, byte for byte, on
	 * which sites are dispatchers and where they go.
	 */
	static List<Address> recoverTable(Program program, Instruction instruction) {
		MemoryBlock block = program.getMemory().getBlock(instruction.getMinAddress());
		if (block == null || !block.isExecute()) {
			return null;
		}
		if (block.isOverlay()) {
			return recoverOverlayTable(program, instruction, block);
		}
		if (!isUnalignedSegment(block)) {
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
	 * Overlay variant of {@link #recoverTable}. The dispatch's module is the one whose
	 * recorded base paragraph is nearest at or below it, ending at the next base (or the
	 * block end); the table displacement and every table entry are offsets from that
	 * base, mirroring the module's runtime CS.
	 * <p>
	 * The recorded base set is not exhaustive — a module referenced by no relocation
	 * does not appear — and a missing base would make this resolve against the previous
	 * module. Guarding against that, the table is rejected whole if it escapes the
	 * window up to the next recorded base or any entry lands in the middle of an
	 * existing instruction (overlay code reachable from dispatch stubs is already
	 * disassembled when this runs).
	 * <p>
	 * The <i>entries</i> themselves are only bounded by the block, not by the next
	 * recorded base: the bases are paragraph anchors taken from relocation seg_index
	 * values and stub module words, not strict module boundaries, and real case
	 * targets cross them (NEBULAR.EXE OVERLAY_78: dispatch at 0x31a anchored at base
	 * 0x30 has its default and one case at 0x356, past the recorded anchor 0x35).
	 * Rejecting on the next base there handed the table to DecompilerSwitchAnalyzer,
	 * which anchored it at the page start and wrote cross-segment garbage flows into
	 * resident code and dispatch stubs.
	 */
	private static List<Address> recoverOverlayTable(Program program, Instruction instruction,
			MemoryBlock block) {
		int displacement = dispatchDisplacement(instruction);
		if (displacement < 0) {
			return null;
		}
		int entries = tableEntryCount(instruction, block);
		if (entries < 0) {
			return null;
		}
		List<Integer> bases = moduleBases(program, block);
		if (bases == null) {
			return null; // no record (block predates it and no re-analysis ran) — leave alone
		}

		Address start = block.getStart();
		long blockSize = block.getEnd().subtract(start) + 1;
		long dispatchOffset = instruction.getMinAddress().subtract(start);
		long moduleStart = -1;
		long moduleEnd = blockSize;
		for (int base : bases) {
			long paragraphOffset = base * 16L;
			if (paragraphOffset <= dispatchOffset) {
				moduleStart = paragraphOffset;
			}
			else {
				moduleEnd = Math.min(paragraphOffset, blockSize);
				break;
			}
		}
		if (moduleStart < 0) {
			return null;
		}

		long lastByte = (long) displacement + 2L * entries - 1;
		if (lastByte > 0xffffL || moduleStart + lastByte >= moduleEnd) {
			return null;
		}
		Address table = start.add(moduleStart + displacement);

		Set<Address> destinations = new LinkedHashSet<>();
		Listing listing = program.getListing();
		try {
			for (int i = 0; i < entries; i++) {
				int offset = program.getMemory().getShort(table.add(2L * i)) & 0xffff;
				long destinationOffset = moduleStart + offset;
				if (destinationOffset >= blockSize) {
					return null;
				}
				Address destination = start.add(destinationOffset);
				Instruction existing = listing.getInstructionContaining(destination);
				if (existing != null && !existing.getMinAddress().equals(destination)) {
					return null; // mid-instruction target: the base resolution is wrong
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
	 * The module base paragraphs {@link RTLinkOverlayAnalyzer} recorded for {@code block}
	 * when it created the overlay, sorted ascending, or null if there is no (valid) record.
	 */
	private static List<Integer> moduleBases(Program program, MemoryBlock block) {
		String recorded = program.getOptions(Program.PROGRAM_INFO).getString(
			RTLinkOverlayAnalyzer.MODULE_BASES_PREFIX + block.getName(), null);
		if (recorded == null || recorded.isEmpty()) {
			return null;
		}
		List<Integer> bases = new ArrayList<>();
		for (String base : recorded.split(",")) {
			try {
				bases.add(Integer.parseInt(base.trim(), 16));
			}
			catch (NumberFormatException e) {
				return null;
			}
		}
		return bases;
	}

	/**
	 * True if {@code block} is based at a paragraph that is not a 64KB-page boundary —
	 * exactly the case {@code currentCS} gets wrong. Page-aligned blocks already resolve
	 * correctly and must not be touched.
	 */
	private static boolean isUnalignedSegment(MemoryBlock block) {
		if (!(block.getStart() instanceof SegmentedAddress start)) {
			return false;
		}
		int pageSegment = (int) ((start.getOffset() >> 4) & 0xf000L);
		return start.getSegment() != pageSegment;
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
	 * <p>
	 * One transformation of the index is allowed between the guard and the scaling: a
	 * byte divide by a constant. Borland emits it for switches over strided case values
	 * ({@code SUB AX,base; CMP AX,span; JA default; MOV BL,stride; DIV BL; OR AH,AH;
	 * JNZ default; SHL AX,1; ...} — NEBULAR.EXE OVERLAY_27::0100ff, cases 0x14,0x1e,..,0x8c),
	 * so the {@code CMP} bounds the pre-divide value and the table has
	 * {@code span/stride + 1} entries. The divisor must resolve to a {@code MOV reg,imm}
	 * in the scanned window; a divide whose constant is not found rejects the site
	 * rather than guessing.
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

		long divisor = 1;
		Register pendingDivisor = null; // divide crossed, its constant not yet seen
		Instruction instruction = scale.getPrevious();
		for (int i = 0; i < GUARD_SCAN_LIMIT && instruction != null; i++) {
			if (!block.contains(instruction.getMinAddress())) {
				return -1;
			}
			if ("CMP".equals(instruction.getMnemonicString()) &&
				index.equals(instruction.getRegister(0))) {
				Scalar bound = instruction.getScalar(1);
				if (bound == null || pendingDivisor != null) {
					return -1;
				}
				long entries = bound.getUnsignedValue() / divisor + 1;
				return entries > MAX_TABLE_ENTRIES ? -1 : (int) entries;
			}
			if (pendingDivisor != null && "MOV".equals(instruction.getMnemonicString()) &&
				pendingDivisor.equals(instruction.getRegister(0))) {
				Scalar value = instruction.getScalar(1);
				if (value == null || value.getUnsignedValue() == 0) {
					return -1;
				}
				divisor = value.getUnsignedValue();
				pendingDivisor = null;
			}
			else if (isByteDivideOf(instruction, index)) {
				if (divisor != 1 || pendingDivisor != null) {
					return -1; // a second divide: not an idiom this understands
				}
				pendingDivisor = instruction.getRegister(0);
			}
			else if (defines(instruction, index)) {
				return -1; // the compared value is not the value that indexes the table
			}
			instruction = instruction.getPrevious();
		}
		return -1;
	}

	/**
	 * True for {@code DIV r8} where {@code index} is AX — the only 8-bit divide form,
	 * quotient in AL/AX. The remainder lands in AH, so the {@code OR AH,AH; JNZ}
	 * exactness check between the divide and the scaling never writes the index
	 * register and needs no special handling here.
	 */
	private static boolean isByteDivideOf(Instruction instruction, Register index) {
		if (!"DIV".equals(instruction.getMnemonicString()) || !"AX".equals(index.getName())) {
			return false;
		}
		Register divisor = instruction.getRegister(0);
		return divisor != null && divisor.getMinimumByteSize() == 1;
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
