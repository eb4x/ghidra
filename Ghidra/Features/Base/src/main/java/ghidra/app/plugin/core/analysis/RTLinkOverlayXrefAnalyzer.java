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
import ghidra.app.util.opinion.MzLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Creates cross-references for far calls and jumps from RTLink/Plus overlay code
 * to the main program.
 * <p>
 * Ghidra's {@code OperandReferenceAnalyzer} skips 16-bit address spaces (its
 * {@code canAnalyze} checks {@code bitSize > 16}), leaving far calls in overlay
 * code without xrefs.  This analyzer fills that gap by scanning newly-created
 * instructions in overlay blocks for immediate far call ({@code 9A}) and far
 * jump ({@code EA}) opcodes, then creating explicit references to their targets
 * in the main program's address space.
 */
public class RTLinkOverlayXrefAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Overlay Xref";
	private static final String DESCRIPTION =
		"Creates cross-references for far calls and jumps from overlay code " +
			"to main program routines.";
	private static final String ANALYZED_FLAG = "RTLink Overlay Analyzed";

	public RTLinkOverlayXrefAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!MzLoader.MZ_NAME.equals(program.getExecutableFormat())) {
			return false;
		}
		return program.getAddressFactory()
				.getDefaultAddressSpace() instanceof SegmentedAddressSpace;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (!program.getOptions(Program.PROGRAM_INFO).getBoolean(ANALYZED_FLAG, false)) {
			return false;
		}

		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		ReferenceManager refManager = program.getReferenceManager();
		SegmentedAddressSpace mainSpace =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();

		int count = 0;

		InstructionIterator instrIter = listing.getInstructions(set, true);
		while (instrIter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instrIter.next();

			MemoryBlock instrBlock = memory.getBlock(instr.getAddress());
			if (instrBlock == null || !instrBlock.isOverlay()) {
				continue;
			}

			try {
				byte[] bytes = instr.getBytes();
				if (bytes.length < 5) {
					continue;
				}

				boolean isFarCall = bytes[0] == (byte) 0x9A;
				boolean isFarJump = bytes[0] == (byte) 0xEA;

				if (!isFarCall && !isFarJump) {
					continue;
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
					count++;
				}
			}
			catch (MemoryAccessException e) {
				// skip
			}
		}

		if (count > 0) {
			Msg.info(this, "RTLink/Plus: Created " + count + " overlay far call/jump xrefs");
		}
		return true;
	}
}
