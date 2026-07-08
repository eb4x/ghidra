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
 * </ul>
 * Scope of the data pass: DS-relative memory reads/writes into DGROUP only.
 * Address-of immediates ({@code PUSH 0x540e}), segment-overridden
 * ({@code ES:}/{@code SS:}/{@code CS:}) accesses, and fully-computed operands with
 * no displacement ({@code [BX+SI]}) are deliberately not materialised &mdash; those
 * remain a heuristic/on-demand concern.
 */
public class RTLinkXrefAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Xref";
	private static final String DESCRIPTION =
		"Creates the cross-references the stock operand analyzer skips in 16-bit " +
			"address spaces: far call/jump xrefs from overlay code to main program " +
			"routines, and DS-relative data read/write xrefs (DGROUP globals).";

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
		int dataCount = 0;

		InstructionIterator instrIter = listing.getInstructions(set, true);
		while (instrIter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instrIter.next();

			if (doOverlayXrefs) {
				overlayCount += addOverlayFarXref(instr, memory, refManager, space);
			}
			if (doDataXrefs) {
				dataCount += addDataXrefs(instr, context, ds, memory, refManager, space);
			}
		}

		if (overlayCount > 0) {
			Msg.info(this,
				"RTLink/Plus: Created " + overlayCount + " overlay far call/jump xrefs");
		}
		if (dataCount > 0) {
			Msg.info(this, "RTLink/Plus: Created " + dataCount + " DS-relative data xrefs");
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

	/**
	 * Data pass: create READ/WRITE references for the instruction's DS-relative
	 * memory operands.  Returns the number of references created.
	 */
	private static int addDataXrefs(Instruction instr, ProgramContext context, Register ds,
			Memory memory, ReferenceManager refManager, SegmentedAddressSpace space) {
		// The DS=DGROUP context is set only over executable blocks, so a present
		// value both confirms we are in code and gives the segment to resolve with.
		RegisterValue dsVal = context.getRegisterValue(ds, instr.getAddress());
		if (dsVal == null || !dsVal.hasValue()) {
			return 0;
		}
		int dgroup = dsVal.getUnsignedValue().intValue() & 0xffff;

		int count = 0;
		int numOps = instr.getNumOperands();
		for (int i = 0; i < numOps; i++) {
			// DS-relative memory operand only (a register-relative effective
			// address). Skip pure SCALAR immediates: address-of vs coincidental
			// constant is heuristic and out of scope.
			if (!OperandType.isDynamic(instr.getOperandType(i))) {
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
			MemoryBlock tb = memory.getBlock(target);
			if (tb == null || tb.isExecute()) {
				// Must land in a mapped data block; DGROUP globals live in BSS, so
				// uninitialized (rw-) data blocks are valid targets. Skip only
				// unmapped memory and executable (code) blocks.
				continue;
			}

			refManager.addMemoryReference(instr.getAddress(), target, rt,
				SourceType.ANALYSIS, i);
			count++;
		}
		return count;
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
