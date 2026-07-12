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

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Creates the cross-references that Ghidra's stock {@code OperandReferenceAnalyzer}
 * never produces for RTLink/Plus programs (its {@code canAnalyze} checks
 * {@code bitSize > 16}, so 16-bit address spaces are skipped entirely).  Two
 * independent passes share one instruction scan:
 * <ul>
 * <li><b>Overlay far calls/jumps</b> &mdash; instructions in overlay blocks with an
 * immediate far call ({@code 9A}) or far jump ({@code EA}) opcode get explicit
 * references to their targets in the main program's address space.  Active once
 * {@link RTLinkOverlayAnalyzer} has created the overlay blocks.</li>
 * <li><b>DS-relative data reads/writes</b> &mdash; DS-relative memory operands such
 * as {@code MOV AX,[0x540e]} or {@code MOV [0x540e],DX} get references to their
 * DGROUP globals.  {@link RTLinkOverlayAnalyzer} has already assumed
 * {@code DS = DGROUP} over executable memory (see its
 * {@code assumeDataSegmentRegister}), so the target {@code DGROUP:offset} is fully
 * known, and {@link Instruction#getOperandRefType(int)} distinguishes READ from
 * WRITE from the operand p-code.</li>
 * <li><b>Address-of immediates</b> &mdash; {@code PUSH imm16} and
 * {@code MOV BX/SI/DI,imm16} whose immediate, resolved against the same assumed
 * DS, lands in a mapped non-executable block get {@link RefType#DATA} references.
 * Globals only ever passed by address ({@code fread(&g_players, ...)} compiles to
 * {@code PUSH 0x540e}) otherwise show zero xrefs.  The block guard is the
 * false-positive bound: every small coincidental constant falls below the data
 * block's start offset.  Stock analysis never makes these &mdash;
 * {@code ConstantPropagationAnalyzer} disables param-constant refs on segmented
 * address spaces and resolves bare constants as segment-0 addresses.</li>
 * </ul>
 * Still out of scope: immediates of arithmetic/comparison instructions (only the
 * PUSH and MOV-into-address-register shapes are considered), {@code MOV AX,imm16}
 * (measured ~90% false positives: DOS int 21h AH:AL function selectors such as
 * {@code 0x3D00}/{@code 0x4200} and low words of 32-bit constants land in the data
 * extent), segment-overridden ({@code ES:}/{@code SS:}/{@code CS:}) accesses,
 * fully-computed operands with no displacement ({@code [BX+SI]}), and targets in
 * executable blocks (the initialized low-DGROUP region; stock constant
 * propagation covers those).
 */
public class RTLinkXrefAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Xref";
	private static final String DESCRIPTION =
		"Creates the cross-references the stock operand analyzer skips in 16-bit " +
			"address spaces: far call/jump xrefs from overlay code to main program " +
			"routines, DS-relative data read/write xrefs (DGROUP globals), and " +
			"address-of immediate xrefs (PUSH/MOV of a DGROUP data offset).";

	public RTLinkXrefAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
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
		boolean doOverlayXrefs = RTLinkOverlayAnalyzer.isOverlayAnalyzed(program);

		ProgramContext context = program.getProgramContext();
		Register ds = context.getRegister("DS");
		boolean doDataXrefs =
			RTLinkOverlayAnalyzer.isDataSegmentAssumed(program) && ds != null;

		if (!doOverlayXrefs && !doDataXrefs) {
			return false;
		}

		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		ReferenceManager refManager = program.getReferenceManager();
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();

		int overlayCount = 0;
		Counts counts = new Counts();

		InstructionIterator instrIter = listing.getInstructions(set, true);
		while (instrIter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instrIter.next();

			if (doOverlayXrefs) {
				overlayCount += addOverlayFarXref(instr, memory, refManager, space);
			}
			if (doDataXrefs) {
				addDataXrefs(instr, context, ds, memory, refManager, space, counts);
			}
		}

		if (overlayCount > 0) {
			Msg.info(this,
				"RTLink/Plus: Created " + overlayCount + " overlay far call/jump xrefs");
		}
		if (counts.deref > 0) {
			Msg.info(this, "RTLink/Plus: Created " + counts.deref + " DS-relative data xrefs");
		}
		if (counts.addressOf > 0) {
			Msg.info(this,
				"RTLink/Plus: Created " + counts.addressOf + " address-of immediate xrefs");
		}
		return true;
	}

	/**
	 * Far call/jump pass: create a reference from an overlay-block far call/jump
	 * to its main-program target.  Returns the number of references created (0 or 1).
	 */
	private static int addOverlayFarXref(Instruction instr, Memory memory,
			ReferenceManager refManager, SegmentedAddressSpace mainSpace) {
		MemoryBlock instrBlock = memory.getBlock(instr.getAddress());
		if (instrBlock == null || !instrBlock.isOverlay()) {
			return 0;
		}

		try {
			byte[] bytes = instr.getBytes();
			if (bytes.length < 5) {
				return 0;
			}

			boolean isFarCall = bytes[0] == RTLinkOverlayAnalyzer.OPCODE_CALLF;
			boolean isFarJump = bytes[0] == RTLinkOverlayAnalyzer.OPCODE_JMPF;

			if (!isFarCall && !isFarJump) {
				return 0;
			}

			int offset = (bytes[1] & 0xFF) | ((bytes[2] & 0xFF) << 8);
			int segment = (bytes[3] & 0xFF) | ((bytes[4] & 0xFF) << 8);

			Address targetAddr = mainSpace.getAddress(segment, offset);
			MemoryBlock targetBlock = memory.getBlock(targetAddr);
			if (targetBlock != null && !targetBlock.isOverlay()) {
				RefType refType = isFarCall
					? RefType.UNCONDITIONAL_CALL
					: RefType.UNCONDITIONAL_JUMP;
				refManager.addMemoryReference(instr.getAddress(), targetAddr,
					refType, SourceType.ANALYSIS, 0);
				return 1;
			}
		}
		catch (MemoryAccessException e) {
			// skip
		}
		return 0;
	}

	/** Per-run counters for the data pass, reported separately in {@link #added}. */
	static final class Counts {
		int deref; // DS-relative memory-operand READ/WRITE refs
		int addressOf; // address-of immediate DATA refs
	}

	/**
	 * Data pass: create READ/WRITE references for the instruction's DS-relative
	 * memory operands and DATA references for its address-of immediates.
	 * Package-private, with the counters passed in, so tests can drive it directly.
	 */
	static void addDataXrefs(Instruction instr, ProgramContext context, Register ds,
			Memory memory, ReferenceManager refManager, SegmentedAddressSpace space,
			Counts counts) {
		// The DS=DGROUP context is set only over executable blocks, so a present
		// value both confirms we are in code and gives the segment to resolve with.
		RegisterValue dsVal = context.getRegisterValue(ds, instr.getAddress());
		if (dsVal == null || !dsVal.hasValue()) {
			return;
		}
		int dgroup = dsVal.getUnsignedValue().intValue() & 0xffff;

		int numOps = instr.getNumOperands();
		for (int i = 0; i < numOps; i++) {
			int opType = instr.getOperandType(i);
			if (!OperandType.isDynamic(opType)) {
				// Not a memory operand; a pure immediate may still be an address-of.
				if (OperandType.isScalar(opType)) {
					counts.addressOf +=
						addAddressOfXref(instr, i, dgroup, memory, refManager, space);
				}
				continue;
			}

			Object[] opObjects = instr.getOpObjects(i);
			if (hasSegmentOverride(opObjects, ds) ||
				hasSegmentOverride(instr.getDefaultOperandRepresentation(i))) {
				continue;
			}

			Scalar disp = firstScalar(opObjects);
			if (disp == null) {
				continue; // e.g. [BX+SI] with no displacement
			}
			int offset = (int) (disp.getUnsignedValue() & 0xffff);

			RefType rt = instr.getOperandRefType(i);
			if (rt == null || (!rt.isRead() && !rt.isWrite())) {
				continue; // materialise READ / WRITE / READ_WRITE only
			}

			Address target = space.getAddress(dgroup, offset);
			if (!isMappedDataTarget(target, memory)) {
				continue;
			}

			refManager.addMemoryReference(instr.getAddress(), target, rt,
				SourceType.ANALYSIS, i);
			counts.deref++;
		}
	}

	/**
	 * Address-of pass: create a DATA reference for a pure imm16 operand of
	 * {@code PUSH imm16} or {@code MOV BX/SI/DI,imm16} whose value, resolved
	 * against DS=DGROUP, lands in a mapped non-executable block.  Returns the
	 * number of references created (0 or 1).
	 */
	private static int addAddressOfXref(Instruction instr, int opIndex, int dgroup,
			Memory memory, ReferenceManager refManager, SegmentedAddressSpace space) {
		String mnemonic = instr.getMnemonicString();
		if (mnemonic.equals("PUSH")) {
			if (opIndex != 0 || instr.getNumOperands() != 1) {
				return 0;
			}
		}
		else if (mnemonic.equals("MOV")) {
			// Only moves into a register plausibly used as a pointer.  CX and DX
			// carry counts and sizes; AX carries DOS int 21h AH:AL function
			// selectors and the low words of 32-bit constants, which dominate its
			// in-range immediates.
			if (opIndex != 1) {
				return 0;
			}
			Object[] dest = instr.getOpObjects(0);
			if (dest.length != 1 || !(dest[0] instanceof Register reg) ||
				!isAddressRegister(reg)) {
				return 0;
			}
		}
		else {
			return 0;
		}

		Object[] opObjects = instr.getOpObjects(opIndex);
		if (opObjects.length != 1 || !(opObjects[0] instanceof Scalar imm)) {
			return 0;
		}
		long value = imm.getUnsignedValue();
		if (value > 0xffff) {
			return 0;
		}

		Address target = space.getAddress(dgroup, (int) value);
		if (!isMappedDataTarget(target, memory)) {
			return 0;
		}

		refManager.addMemoryReference(instr.getAddress(), target, RefType.DATA,
			SourceType.ANALYSIS, opIndex);
		return 1;
	}

	private static boolean isAddressRegister(Register reg) {
		String name = reg.getName();
		return name.equals("BX") || name.equals("SI") || name.equals("DI");
	}

	/**
	 * True if the target lands in a mapped non-executable block.  DGROUP globals
	 * live in BSS, so uninitialized (rw-) data blocks are valid targets; only
	 * unmapped memory and executable (code) blocks are rejected.
	 */
	private static boolean isMappedDataTarget(Address target, Memory memory) {
		MemoryBlock block = memory.getBlock(target);
		return block != null && !block.isExecute();
	}

	/** True if the operand carries an explicit non-DS segment register (override prefix). */
	private static boolean hasSegmentOverride(Object[] opObjects, Register ds) {
		for (Object obj : opObjects) {
			if (obj instanceof Register reg && reg != ds && isSegmentRegister(reg)) {
				return true;
			}
		}
		return false;
	}

	/** Fallback: detect an {@code ES:}/{@code SS:}/{@code CS:}/{@code FS:}/{@code GS:} prefix. */
	private static boolean hasSegmentOverride(String representation) {
		return representation.contains("ES:") || representation.contains("SS:") ||
			representation.contains("CS:") || representation.contains("FS:") ||
			representation.contains("GS:");
	}

	private static boolean isSegmentRegister(Register reg) {
		String name = reg.getName();
		return name.equals("ES") || name.equals("SS") || name.equals("CS") ||
			name.equals("FS") || name.equals("GS") || name.equals("DS");
	}

	private static Scalar firstScalar(Object[] opObjects) {
		for (Object obj : opObjects) {
			if (obj instanceof Scalar scalar) {
				return scalar;
			}
		}
		return null;
	}
}
