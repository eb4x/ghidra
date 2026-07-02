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

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.FileBytesProvider;
import ghidra.app.util.bin.format.mz.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.MzLoader;
import ghidra.framework.options.Options;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Detects and loads RTLink/Plus overlay pages from DOS MZ executables.
 * <p>
 * RTLink/Plus was a widely-used overlay manager for late-DOS commercial
 * software (Microprose, Sierra, etc.). Overlay pages are stored at file offsets
 * past the MZ image end and are invisible to {@link MzLoader}'s static
 * analysis. This analyzer creates overlay memory blocks for each page, applies
 * segment relocations, and wires cross-references from dispatch stubs to
 * overlay functions.
 * <p>
 * Dispatch stubs are 12-byte sequences: {@code CALLF seg:0DAB} (5 bytes) +
 * {@code JMPF 0000:offset} (5 bytes) + page_id (2 bytes). Bits 0-13 of page_id
 * hold a 1-based descriptor index into the overlay descriptor table; index 1 is
 * the global overlay table, so the first code page is index 2 (the 1-based
 * overlay page number is therefore page_id - 1). The JMPF offset is the in-page
 * code offset.
 */
public class RTLinkOverlayAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Overlay";
	private static final String DESCRIPTION =
		"Detects and loads RTLink/Plus overlay pages from DOS MZ executables. " +
			"Creates overlay memory blocks, applies segment relocations, and " +
			"creates cross-references from dispatch stubs to overlay functions.";
	private static final String ANALYZED_FLAG = "RTLink Overlay Analyzed";

	private static final int INITIAL_SEGMENT_VAL = 0x1000;

	private static final byte OPCODE_CALLF = (byte) 0x9A;
	private static final byte OPCODE_JMPF = (byte) 0xEA;
	private static final int RTLINK_DISPATCH_OFFSET = 0x0DAB;
	private static final int PAGE_ID_MASK = 0x3FFF;

	private static final String OPTION_APPLY_RELOCS = "Apply Relocations";
	private static final String OPTION_CREATE_XREFS = "Create Stub Cross-References";
	private static final String OPTION_MARKUP_HEADERS = "Markup Page Headers";

	private boolean applyRelocations = true;
	private boolean createStubXrefs = true;
	private boolean markupHeaders = true;

	private long lastTxId = -1;

	public RTLinkOverlayAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
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
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		long txId = program.getCurrentTransactionInfo().getID();
		if (txId == lastTxId) {
			return true;
		}
		lastTxId = txId;

		if (isAlreadyAnalyzed(program)) {
			return true;
		}

		List<FileBytes> allFileBytes = program.getMemory().getAllFileBytes();
		if (allFileBytes.isEmpty()) {
			return false;
		}

		FileBytes fileBytes = allFileBytes.get(0);
		try (FileBytesProvider provider = new FileBytesProvider(fileBytes)) {
			BinaryReader reader = new BinaryReader(provider, true);

			OldDOSHeader header = new OldDOSHeader(reader);
			if (!header.isDosSignature()) {
				return false;
			}

			long imageEnd = computeImageEnd(header);
			long overlayStart = (imageEnd + 15) & ~15L;
			if (overlayStart <= 0 || overlayStart >= fileBytes.getSize()) {
				return false;
			}

			if (!detectRTLinkOverlay(reader, overlayStart, fileBytes.getSize())) {
				return false;
			}

			List<RTLinkOverlayPage> allPages =
				RTLinkOverlayPage.parseAllPages(reader, overlayStart, fileBytes.getSize());
			if (allPages.size() < 2) {
				return false;
			}

			List<RTLinkOverlayPage> codePages = allPages.subList(1, allPages.size());

			Msg.info(this, String.format(
				"RTLink/Plus: Found %d overlay pages (global table + %d code pages) " +
					"at file offset 0x%X",
				allPages.size(), codePages.size(), overlayStart));

			List<OverlayBlockInfo> overlayBlocks =
				createOverlayBlocks(program, fileBytes, codePages, log, monitor);

			if (applyRelocations && !overlayBlocks.isEmpty()) {
				int dataSegment = discoverDataSegment(program);
				monitor.setMessage("RTLink: Applying overlay relocations...");
				for (OverlayBlockInfo info : overlayBlocks) {
					monitor.checkCancelled();
					applyOverlayRelocations(program, info, dataSegment, log);
				}
			}

			if (createStubXrefs && !overlayBlocks.isEmpty()) {
				monitor.setMessage("RTLink: Discovering dispatch stubs...");
				discoverAndProcessStubs(program, overlayBlocks, log, monitor);
			}

			if (markupHeaders) {
				monitor.setMessage("RTLink: Marking up page headers...");
				markupOverlayHeaders(program, fileBytes, allPages, log, monitor);
			}

			program.getOptions(Program.PROGRAM_INFO).setBoolean(ANALYZED_FLAG, true);
			return true;
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			log.appendMsg("RTLink: Analysis failed: " + e.getMessage());
			Msg.error(this, "RTLink overlay analysis failed", e);
			return false;
		}
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_APPLY_RELOCS, applyRelocations, null,
			"Patch segment references in overlay code using the data segment value.");
		options.registerOption(OPTION_CREATE_XREFS, createStubXrefs, null,
			"Discover dispatch stubs and create cross-references to overlay functions.");
		options.registerOption(OPTION_MARKUP_HEADERS, markupHeaders, null,
			"Create data structures for RTLink page headers in the listing.");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		applyRelocations = options.getBoolean(OPTION_APPLY_RELOCS, applyRelocations);
		createStubXrefs = options.getBoolean(OPTION_CREATE_XREFS, createStubXrefs);
		markupHeaders = options.getBoolean(OPTION_MARKUP_HEADERS, markupHeaders);
	}

	// ---- Private implementation ----

	private record OverlayBlockInfo(RTLinkOverlayPage page, MemoryBlock block) {
	}

	/** A resolved dispatch stub awaiting thunk creation once its target is a real function. */
	private record StubTarget(Address stubAddr, Address targetAddr, int stubSize) {
	}

	private static boolean isAlreadyAnalyzed(Program program) {
		return program.getOptions(Program.PROGRAM_INFO).getBoolean(ANALYZED_FLAG, false);
	}

	private static long computeImageEnd(OldDOSHeader header) {
		int pages = Short.toUnsignedInt(header.e_cp());
		int lastPageBytes = Short.toUnsignedInt(header.e_cblp());
		if (pages == 0) {
			return 0;
		}
		if (lastPageBytes == 0) {
			return (long) pages * 512;
		}
		return ((long) (pages - 1)) * 512 + lastPageBytes;
	}

	private static boolean detectRTLinkOverlay(BinaryReader reader, long overlayStart,
			long fileLength) {
		if (overlayStart + RTLinkPageHeader.HEADER_SIZE > fileLength) {
			return false;
		}
		try {
			reader.setPointerIndex(overlayStart);
			RTLinkPageHeader first = new RTLinkPageHeader(reader);
			if (!first.isValid()) {
				return false;
			}
			if (first.getTotalSizeBytes() > fileLength - overlayStart) {
				return false;
			}

			long secondOffset = overlayStart + first.getTotalSizeBytes();
			if (secondOffset + RTLinkPageHeader.HEADER_SIZE <= fileLength) {
				reader.setPointerIndex(secondOffset);
				RTLinkPageHeader second = new RTLinkPageHeader(reader);
				if (second.isValid() && second.getFrameSize() == first.getFrameSize()) {
					return true;
				}
			}

			return true;
		}
		catch (IOException e) {
			return false;
		}
	}

	private List<OverlayBlockInfo> createOverlayBlocks(Program program, FileBytes fileBytes,
			List<RTLinkOverlayPage> codePages, MessageLog log, TaskMonitor monitor)
			throws Exception {
		List<OverlayBlockInfo> result = new ArrayList<>();
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		Address overlayBase = space.getAddress(INITIAL_SEGMENT_VAL, 0);
		long fileSize = fileBytes.getSize();

		for (RTLinkOverlayPage page : codePages) {
			monitor.checkCancelled();

			int codeSize = page.getCodeSize();
			if (codeSize <= 0) {
				log.appendMsg(
					"RTLink: Overlay page " + page.getPageIndex() + " has no code, skipping");
				continue;
			}

			// The final page's header-declared (paragraph-rounded) code size can run a
			// few bytes past the physical end of file, because the image is not padded
			// to a full paragraph. Clamp to the bytes actually present so block creation
			// does not read past FileBytes.
			long codeFileOffset = page.getCodeFileOffset();
			long available = fileSize - codeFileOffset;
			if (available <= 0) {
				log.appendMsg("RTLink: Overlay page " + page.getPageIndex() +
					" code starts past end of file, skipping");
				continue;
			}
			if (codeSize > available) {
				codeSize = (int) available;
			}

			String blockName = String.format("OVERLAY_%02d", page.getPageIndex() - 1);

			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, true,
				blockName, overlayBase, fileBytes, codeFileOffset, codeSize,
				String.format("RTLink/Plus overlay page %d (frame=0x%X)",
					page.getPageIndex() - 1, page.getFrameSize()),
				"RTLink", true, false, true, log);

			if (block != null) {
				result.add(new OverlayBlockInfo(page, block));
			}
			else {
				log.appendMsg(
					"RTLink: Failed to create block for page " + (page.getPageIndex() - 1));
			}
		}

		Msg.info(this, "RTLink/Plus: Created " + result.size() + " overlay memory blocks");
		return result;
	}

	private int discoverDataSegment(Program program) {
		Symbol entry = SymbolUtilities.getLabelOrFunctionSymbol(program, "entry",
			err -> { /* ignore */ });
		if (entry == null) {
			return INITIAL_SEGMENT_VAL;
		}

		var context = program.getProgramContext();
		var ds = context.getRegister("ds");
		if (ds != null) {
			BigInteger dsValue = context.getValue(ds, entry.getAddress(), false);
			if (dsValue != null) {
				return dsValue.intValue();
			}
		}

		try {
			Memory memory = program.getMemory();
			byte entryByte = memory.getByte(entry.getAddress());
			if (entryByte == (byte) 0xBA) {
				short imm = memory.getShort(entry.getAddress().add(1));
				return Short.toUnsignedInt(imm);
			}
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			// fall through
		}

		return INITIAL_SEGMENT_VAL;
	}

	private void applyOverlayRelocations(Program program, OverlayBlockInfo info,
			int dataSegment, MessageLog log) {
		Memory memory = program.getMemory();
		Address blockStart = info.block().getStart();
		RTLinkOverlayPage page = info.page();
		int pageDisplay = page.getPageIndex() - 1;

		for (RTLinkRelocation reloc : page.getRelocations()) {
			int offset = reloc.getOffset();

			try {
				Address relocAddr = blockStart.add(offset);
				int segmentValue;

				if (reloc.getSegmentIndex() == 0) {
					segmentValue = dataSegment;
				}
				else {
					short currentValue = memory.getShort(relocAddr);
					segmentValue =
						(INITIAL_SEGMENT_VAL + Short.toUnsignedInt(currentValue)) & 0xffff;
				}

				memory.setShort(relocAddr, (short) segmentValue);

				program.getRelocationTable().add(relocAddr, Status.APPLIED, 0,
					new long[] { reloc.getOffset(), reloc.getSegmentIndex(), segmentValue },
					2, null);
			}
			catch (MemoryAccessException | AddressOutOfBoundsException e) {
				log.appendMsg(String.format(
					"RTLink: Failed to apply relocation at offset 0x%04X in page %d: %s",
					offset, pageDisplay, e.getMessage()));
			}
		}
	}

	private void discoverAndProcessStubs(Program program,
			List<OverlayBlockInfo> overlayBlocks, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		AddressSet overlayEntryPoints = new AddressSet();
		List<StubTarget> pendingThunks = new ArrayList<>();

		int jmpfStubs = scanForJmpfStubs(program, overlayBlocks, overlayEntryPoints,
			pendingThunks, log, monitor);
		int int3fStubs = 0;

		if (jmpfStubs == 0) {
			int3fStubs = scanForInt3fStubs(program, overlayBlocks, overlayEntryPoints,
				pendingThunks, log, monitor);
		}

		int total = jmpfStubs + int3fStubs;
		if (total == 0) {
			log.appendMsg("RTLink: No dispatch stubs found");
			return;
		}

		// Disassemble the overlay code reachable from the resolved entry points and
		// promote each entry point to a function with a real body. Without this the
		// overlay pages hold no instructions, so intra-overlay calls and jumps never
		// get references and every overlay "function" is a one-byte husk.
		disassembleOverlayCode(program, overlayBlocks, overlayEntryPoints, log, monitor);

		// Now that the overlay targets are real functions, wire each dispatch stub to
		// its target as a thunk.
		FunctionManager funcMgr = program.getFunctionManager();
		for (StubTarget stub : pendingThunks) {
			monitor.checkCancelled();
			createThunkAtStub(funcMgr, stub.stubAddr(), stub.targetAddr(), stub.stubSize());
		}

		Msg.info(this, "RTLink/Plus: Resolved " + total + " dispatch stubs");
	}

	/**
	 * Disassemble overlay code starting from the resolved stub entry points, following
	 * intra-page flow but staying within the overlay blocks, then create a function with
	 * a computed body at each entry point.
	 * <p>
	 * This is what makes overlay code visible to the rest of Ghidra: the disassembler
	 * creates flow references for the near calls and jumps between overlay routines (which
	 * {@code OperandReferenceAnalyzer} never creates for 16-bit spaces), and the follow-on
	 * far-call analyzer then wires overlay-to-main references.
	 */
	private void disassembleOverlayCode(Program program, List<OverlayBlockInfo> overlayBlocks,
			AddressSet overlayEntryPoints, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		if (overlayEntryPoints.isEmpty()) {
			return;
		}

		AddressSet overlayRange = new AddressSet();
		for (OverlayBlockInfo info : overlayBlocks) {
			overlayRange.add(info.block().getStart(), info.block().getEnd());
		}

		monitor.setMessage("RTLink: Disassembling overlay code...");
		DisassembleCommand disCmd =
			new DisassembleCommand(overlayEntryPoints, overlayRange, true);
		if (!disCmd.applyTo(program, monitor)) {
			log.appendMsg("RTLink: Overlay disassembly reported: " + disCmd.getStatusMsg());
		}
		monitor.checkCancelled();

		monitor.setMessage("RTLink: Creating overlay functions...");
		CreateFunctionCmd funcCmd =
			new CreateFunctionCmd(overlayEntryPoints, SourceType.ANALYSIS);
		funcCmd.applyTo(program, monitor);

		AddressSetView disassembled = disCmd.getDisassembledAddressSet();
		long byteCount = disassembled == null ? 0 : disassembled.getNumAddresses();
		Msg.info(this, String.format(
			"RTLink/Plus: Disassembled %d overlay byte(s) from %d entry point(s)",
			byteCount, overlayEntryPoints.getNumAddresses()));
	}

	/**
	 * Scan for 0DAB dispatch stubs by finding JMPF instructions with segment 0x0000,
	 * then validating that a CALLF to offset 0x0DAB precedes them.
	 * <p>
	 * Stub layout (12 bytes):
	 * <pre>
	 *   [0-4]   9A AB 0D ss ss   CALLF seg:0DAB
	 *   [5-9]   EA oo oo 00 00   JMPF 0000:offset
	 *   [10-11] pp pp             page_id (bits 0-13 = 1-based descriptor index)
	 * </pre>
	 * page_id is a descriptor index in which 1 is the global overlay table, so the
	 * first code page is index 2; the 1-based overlay page number is page_id - 1.
	 * The JMPF offset is the in-page code offset. No external lookup table is needed.
	 */
	private int scanForJmpfStubs(Program program, List<OverlayBlockInfo> overlayBlocks,
			AddressSet overlayEntryPoints, List<StubTarget> pendingThunks,
			MessageLog log, TaskMonitor monitor) throws CancelledException {
		if (overlayBlocks.isEmpty()) {
			return 0;
		}

		Memory memory = program.getMemory();
		ReferenceManager refManager = program.getReferenceManager();
		SymbolTable symbolTable = program.getSymbolTable();
		int count = 0;

		for (MemoryBlock block : memory.getBlocks()) {
			if (block.isOverlay() || !block.isExecute() || !block.isInitialized()) {
				continue;
			}

			Address searchAddr = block.getStart();
			Address blockEnd = block.getEnd();

			while (searchAddr != null && searchAddr.compareTo(blockEnd) < 0) {
				monitor.checkCancelled();

				searchAddr = memory.findBytes(searchAddr, blockEnd,
					new byte[] { OPCODE_JMPF }, null, true, monitor);
				if (searchAddr == null) {
					break;
				}

				try {
					// Need 5 bytes before (CALLF) and 7 bytes after (JMPF + page_id)
					Address callfAddr = searchAddr.subtract(5);
					Address pageIdAddr = searchAddr.add(5);

					if (!block.contains(callfAddr) ||
						!block.contains(pageIdAddr.add(1))) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					int targetSegment =
						Short.toUnsignedInt(memory.getShort(searchAddr.add(3)));
					if (targetSegment != 0x0000) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					// Validate CALLF opcode and dispatch offset (0x0DAB)
					byte callfOpcode = memory.getByte(callfAddr);
					int callfOffset =
						Short.toUnsignedInt(memory.getShort(callfAddr.add(1)));
					if (callfOpcode != OPCODE_CALLF ||
						callfOffset != RTLINK_DISPATCH_OFFSET) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					int targetOffset =
						Short.toUnsignedInt(memory.getShort(searchAddr.add(1)));
					int pageId = Short.toUnsignedInt(memory.getShort(pageIdAddr));
					// The stored value is a 1-based descriptor index, NOT the overlay page
					// number: descriptor index 1 is the global overlay table, so the first
					// code page is index 2. Convert to a 1-based code-page number (used in
					// the OVLxx label convention) and a 0-based index into overlayBlocks
					// (which already excludes the global table at subList(1, ...)).
					int descriptorIndex = pageId & PAGE_ID_MASK;
					int pageNumber = descriptorIndex - 1;

					int blockIndex = pageNumber - 1;
					if (blockIndex < 0 || blockIndex >= overlayBlocks.size()) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					OverlayBlockInfo target = overlayBlocks.get(blockIndex);
					Address targetAddr = target.block().getStart().add(targetOffset);

					if (!target.block().contains(targetAddr)) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					Address stubAddr = callfAddr;
					refManager.addMemoryReference(stubAddr, targetAddr,
						RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);

					labelAddress(symbolTable,
						String.format("OVLSTUB_%02d_%04X", pageNumber, targetOffset),
						stubAddr);
					labelAddress(symbolTable,
						String.format("OVL%02d_%04X", pageNumber, targetOffset),
						targetAddr);

					symbolTable.addExternalEntryPoint(targetAddr);
					overlayEntryPoints.add(targetAddr);
					pendingThunks.add(new StubTarget(stubAddr, targetAddr, 12));
					count++;
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					// skip
				}

				searchAddr = searchAddr.add(1);
			}
		}
		return count;
	}

	/**
	 * Scan for INT 3Fh (CD 3F) stubs used by older RTLink versions.
	 * Pattern: CD 3F xx xx yy yy (INT 3Fh, overlay_id, offset)
	 */
	private int scanForInt3fStubs(Program program, List<OverlayBlockInfo> overlayBlocks,
			AddressSet overlayEntryPoints, List<StubTarget> pendingThunks,
			MessageLog log, TaskMonitor monitor) throws CancelledException {
		Memory memory = program.getMemory();
		ReferenceManager refManager = program.getReferenceManager();
		SymbolTable symbolTable = program.getSymbolTable();
		byte[] pattern = { (byte) 0xCD, (byte) 0x3F };
		int count = 0;

		for (MemoryBlock block : memory.getBlocks()) {
			if (block.isOverlay() || !block.isExecute() || !block.isInitialized()) {
				continue;
			}

			Address searchAddr = block.getStart();
			Address blockEnd = block.getEnd();

			while (searchAddr != null && searchAddr.compareTo(blockEnd) < 0) {
				monitor.checkCancelled();

				searchAddr = memory.findBytes(searchAddr, blockEnd, pattern, null, true,
					monitor);
				if (searchAddr == null) {
					break;
				}

				try {
					Address idAddr = searchAddr.add(2);
					Address offAddr = searchAddr.add(4);

					if (!block.contains(offAddr.add(1))) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					int overlayId = Short.toUnsignedInt(memory.getShort(idAddr));
					int targetOffset = Short.toUnsignedInt(memory.getShort(offAddr));

					if (overlayId < overlayBlocks.size()) {
						OverlayBlockInfo info = overlayBlocks.get(overlayId);
						Address targetAddr =
							info.block().getStart().add(targetOffset);

						if (info.block().contains(targetAddr)) {
							refManager.addMemoryReference(searchAddr, targetAddr,
								RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);

							int pageNum = info.page().getPageIndex() - 1;
							labelAddress(symbolTable,
								String.format("OVLSTUB_%02d_%04X", pageNum,
									targetOffset),
								searchAddr);
							labelAddress(symbolTable,
								String.format("OVL%02d_%04X", pageNum, targetOffset),
								targetAddr);

							symbolTable.addExternalEntryPoint(targetAddr);
							overlayEntryPoints.add(targetAddr);
							pendingThunks.add(new StubTarget(searchAddr, targetAddr, 6));
							count++;
						}
					}
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					// skip
				}

				searchAddr = searchAddr.add(1);
			}
		}
		return count;
	}

	private static void createThunkAtStub(FunctionManager funcMgr, Address stubAddr,
			Address targetAddr, int stubSize) {
		Function overlayFunc = funcMgr.getFunctionAt(targetAddr);
		if (overlayFunc == null) {
			try {
				overlayFunc = funcMgr.createFunction(null, targetAddr,
					new AddressSet(targetAddr, targetAddr), SourceType.ANALYSIS);
			}
			catch (Exception e) {
				return;
			}
		}

		Function existingStub = funcMgr.getFunctionAt(stubAddr);
		if (existingStub != null) {
			try {
				existingStub.setThunkedFunction(overlayFunc);
			}
			catch (IllegalArgumentException e) {
				// ignore
			}
		}
		else {
			try {
				AddressSet stubBody =
					new AddressSet(stubAddr, stubAddr.add(stubSize - 1));
				funcMgr.createThunkFunction(null, null, stubAddr, stubBody,
					overlayFunc, SourceType.ANALYSIS);
			}
			catch (OverlappingFunctionException e) {
				// ignore
			}
		}
	}

	private static void labelAddress(SymbolTable symbolTable, String label, Address addr) {
		try {
			Symbol existing = symbolTable.getPrimarySymbol(addr);
			if (existing == null || existing.isDynamic()) {
				symbolTable.createLabel(addr, label, SourceType.ANALYSIS);
			}
		}
		catch (InvalidInputException e) {
			// ignore
		}
	}

	private void markupOverlayHeaders(Program program, FileBytes fileBytes,
			List<RTLinkOverlayPage> allPages, MessageLog log, TaskMonitor monitor)
			throws Exception {
		for (RTLinkOverlayPage page : allPages) {
			monitor.checkCancelled();

			int headerAndRelocSize = page.getHeader().getOverheadSizeBytes();
			Address headerBase = AddressSpace.OTHER_SPACE.getAddress(0);
			String name = String.format("RTLINK_HDR_%02d", page.getPageIndex());

			MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, true,
				name, headerBase, fileBytes, page.getFileOffset(), headerAndRelocSize,
				"RTLink page " + page.getPageIndex() + " header", "RTLink",
				false, false, false, log);

			if (headerBlock == null) {
				continue;
			}

			try {
				Address addr = headerBlock.getStart();
				DataUtilities.createData(program, addr, page.getHeader().toDataType(), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

				if (!page.getRelocations().isEmpty()) {
					var relocType = page.getRelocations().get(0).toDataType();
					int relocSize = relocType.getLength();
					Address relocAddr = addr.add(RTLinkPageHeader.HEADER_SIZE);
					for (int j = 0; j < page.getRelocations().size(); j++) {
						monitor.checkCancelled();
						DataUtilities.createData(program,
							relocAddr.add((long) j * relocSize), relocType, -1,
							DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
					}
				}
			}
			catch (Exception e) {
				log.appendMsg(
					"RTLink: Failed to markup header for page " + page.getPageIndex());
			}
		}
	}
}
