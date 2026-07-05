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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
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
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.scalar.Scalar;
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
 * Dispatch stubs are 12- or 14-byte sequences: {@code CALLF seg:0DAB} (5 bytes) +
 * {@code JMPF 0000:offset} (5 bytes) + page_id (2 bytes) + an optional module_word
 * (2 bytes). Bits 0-13 of page_id hold a 1-based descriptor index into the overlay
 * descriptor table; index 1 is the global overlay table, so the first code page is
 * index 2 (the 1-based overlay page number is therefore page_id - 1).
 * <p>
 * Pages contain multiple link-time modules, each with its own segment base
 * (CS = page frame + module base paragraph), so the JMPF offset is
 * module-relative. 12-byte stubs target module 0 (JMPF offset = in-page code
 * offset); 14-byte stubs carry the target module's base paragraph in module_word,
 * and the in-page code offset is {@code JMPF offset + module_word * 16}. See
 * {@link #scanForJmpfStubs} for how the two forms are told apart.
 */
public class RTLinkOverlayAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink/Plus Overlay";
	private static final String DESCRIPTION =
		"Detects and loads RTLink/Plus overlay pages from DOS MZ executables. " +
			"Creates overlay memory blocks, applies segment relocations, and " +
			"creates cross-references from dispatch stubs to overlay functions.";
	/**
	 * PROGRAM_INFO property set when overlay analysis completes; gates
	 * {@link RTLinkOverlayXrefAnalyzer}.
	 */
	static final String ANALYZED_FLAG = "RTLink Overlay Analyzed";
	/** PROGRAM_INFO property set once DS (DGROUP) has been assumed, so re-runs don't redo it. */
	static final String DS_ASSUMED_FLAG = "RTLink Data Segment Assumed";

	private static final int INITIAL_SEGMENT_VAL = 0x1000;

	static final byte OPCODE_CALLF = (byte) 0x9A;
	static final byte OPCODE_JMPF = (byte) 0xEA;
	private static final int PAGE_ID_MASK = 0x3FFF;

	// A real overlay dispatcher is the CALLF target shared by many stubs. Any
	// physical address hit by at least this many CALLF+JMPF stub candidates is
	// treated as a dispatcher, replacing the old hardcoded 0x0DAB dispatch offset
	// so the analyzer adapts to binaries linked with the dispatcher elsewhere.
	private static final int MIN_DISPATCHER_STUB_COUNT = 4;

	private static final String OPTION_APPLY_RELOCS = "Apply Relocations";
	private static final String OPTION_CREATE_XREFS = "Create Stub Cross-References";
	private static final String OPTION_MARKUP_HEADERS = "Markup Page Headers";
	private static final String OPTION_ASSUME_DS = "Assume Data Segment (DS)";

	/** Max instructions to decode when hunting the DGROUP load in the C startup. */
	private static final int STARTUP_SCAN_LIMIT = 200;

	private boolean applyRelocations = true;
	private boolean createStubXrefs = true;
	private boolean markupHeaders = true;
	private boolean assumeDataSegment = true;

	private long lastTxId = -1;

	public RTLinkOverlayAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setDefaultEnablement(true);
		// Offer this analyzer in Analysis -> One Shot so it can be re-run on an
		// already-analyzed program to retrofit the assumed data segment (DS/DGROUP)
		// and overlay markup without re-importing.
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return isSegmentedMzProgram(program);
	}

	/**
	 * Returns true if {@code program} is an MZ executable with a segmented (16-bit
	 * real mode) default address space — the only programs RTLink overlay analysis
	 * applies to.
	 */
	static boolean isSegmentedMzProgram(Program program) {
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

		if (isOverlayAnalyzed(program)) {
			// Overlays were processed by a prior run; still retrofit DS on re-analysis so an
			// already-analyzed program benefits without re-importing.
			maybeAssumeDataSegment(program, log);
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
				monitor.setMessage("RTLink: Applying overlay relocations...");
				for (OverlayBlockInfo info : overlayBlocks) {
					monitor.checkCancelled();
					applyOverlayRelocations(program, info, log);
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

			monitor.setMessage("RTLink: Determining data segment (DGROUP)...");
			maybeAssumeDataSegment(program, log);

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
			"Rebase unrelocated segment words in overlay code by the image base, " +
				"at the sites given by each page's relocation table.");
		options.registerOption(OPTION_CREATE_XREFS, createStubXrefs, null,
			"Discover dispatch stubs and create cross-references to overlay functions.");
		options.registerOption(OPTION_MARKUP_HEADERS, markupHeaders, null,
			"Create data structures for RTLink page headers in the listing.");
		options.registerOption(OPTION_ASSUME_DS, assumeDataSegment, null,
			"Detect DGROUP from the C startup and assume it for DS over all code, so the " +
				"decompiler resolves DS-relative data accesses (bare offsets like " +
				"*(int *)0x8542) to real addresses.");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		applyRelocations = options.getBoolean(OPTION_APPLY_RELOCS, applyRelocations);
		createStubXrefs = options.getBoolean(OPTION_CREATE_XREFS, createStubXrefs);
		markupHeaders = options.getBoolean(OPTION_MARKUP_HEADERS, markupHeaders);
		assumeDataSegment = options.getBoolean(OPTION_ASSUME_DS, assumeDataSegment);
	}

	// ---- Private implementation ----

	private record OverlayBlockInfo(RTLinkOverlayPage page, MemoryBlock block) {
	}

	/** A resolved dispatch stub awaiting thunk creation once its target is a real function. */
	private record StubTarget(Address stubAddr, Address targetAddr, int stubSize) {
	}

	static boolean isOverlayAnalyzed(Program program) {
		return program.getOptions(Program.PROGRAM_INFO).getBoolean(ANALYZED_FLAG, false);
	}

	static boolean isDataSegmentAssumed(Program program) {
		return program.getOptions(Program.PROGRAM_INFO).getBoolean(DS_ASSUMED_FLAG, false);
	}

	/** Assume DS once, if the option is on and it hasn't been done for this program yet. */
	private void maybeAssumeDataSegment(Program program, MessageLog log) {
		if (assumeDataSegment && !isDataSegmentAssumed(program)) {
			assumeDataSegmentRegister(program, log);
		}
	}

	/**
	 * Establish the data segment (DGROUP) so the decompiler can resolve DS-relative data
	 * accesses. In the small-data DOS model DS == SS == DGROUP, loaded once in the C startup
	 * (e.g. {@code MOV DI,DGROUP; MOV SS,DI; PUSH SS; POP DS}). We follow the entry's initial
	 * far jump into the startup, linearly decode it while tracking register immediates, and
	 * take the value moved into SS/DS as DGROUP. That value is then assumed for DS over all
	 * executable memory; without it every DS-relative global collapses to a bare offset in an
	 * unmapped space (e.g. {@code *(int *)0x8542}) that ignores applied data types.
	 */
	private void assumeDataSegmentRegister(Program program, MessageLog log) {
		Register ds = program.getLanguage().getRegister("DS");
		if (ds == null) {
			return;
		}
		Address entry = firstEntryPoint(program);
		if (entry == null) {
			return;
		}
		Integer dgroup = detectDataSegment(program, entry);
		if (dgroup == null) {
			log.appendMsg("RTLink: could not determine DGROUP from startup; DS left unset");
			return;
		}
		ProgramContext context = program.getProgramContext();
		BigInteger value = BigInteger.valueOf(dgroup & 0xffffL);
		int blocks = 0;
		try {
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (block.isExecute()) {
					context.setValue(ds, block.getStart(), block.getEnd(), value);
					blocks++;
				}
			}
		}
		catch (ContextChangeException e) {
			log.appendMsg("RTLink: failed to assume DS: " + e.getMessage());
			return;
		}
		program.getOptions(Program.PROGRAM_INFO).setBoolean(DS_ASSUMED_FLAG, true);
		Msg.info(this, String.format(
			"RTLink: Assuming DS = 0x%04X (DGROUP) over %d executable blocks", dgroup, blocks));
		log.appendMsg(String.format("RTLink: Assuming DS = 0x%04X (DGROUP)", dgroup));
	}

	private static Address firstEntryPoint(Program program) {
		AddressIterator it = program.getSymbolTable().getExternalEntryPointIterator();
		return it.hasNext() ? it.next() : null;
	}

	/**
	 * Follow the entry's initial unconditional (far) jump into the C startup, then linearly
	 * decode instructions tracking each general register's last immediate. Returns the segment
	 * value moved into SS or DS (DGROUP), or null if not found within {@link #STARTUP_SCAN_LIMIT}
	 * instructions. Decoding is done with a {@link PseudoDisassembler} so it works before the
	 * program is disassembled and commits nothing.
	 */
	private static Integer detectDataSegment(Program program, Address entry) {
		Register ss = program.getLanguage().getRegister("SS");
		Register ds = program.getLanguage().getRegister("DS");
		PseudoDisassembler disassembler = new PseudoDisassembler(program);

		// Follow the entry's first unconditional jump (entry -> ... -> startup).
		Address addr = entry;
		for (int i = 0; i < 8 && addr != null; i++) {
			PseudoInstruction instr = safeDecode(disassembler, addr);
			if (instr == null) {
				break;
			}
			FlowType flow = instr.getFlowType();
			if (flow.isJump() && !flow.isConditional()) {
				Address[] flows = instr.getFlows();
				if (flows != null && flows.length == 1) {
					addr = flows[0];
					break;
				}
			}
			addr = nextLinear(instr);
		}
		if (addr == null) {
			addr = entry;
		}

		// Linearly decode the startup, watching for the SS/DS segment load.
		Map<Register, Long> regImm = new HashMap<>();
		for (int i = 0; i < STARTUP_SCAN_LIMIT; i++) {
			PseudoInstruction instr = safeDecode(disassembler, addr);
			if (instr == null) {
				return null;
			}
			if ("MOV".equals(instr.getMnemonicString())) {
				Register dest = instr.getRegister(0);
				if (dest != null && (dest.equals(ss) || dest.equals(ds))) {
					Register src = instr.getRegister(1);
					Long imm = src != null ? regImm.get(src) : null;
					if (imm != null) {
						return (int) (imm.longValue() & 0xffffL);
					}
				}
				else if (dest != null) {
					int type = instr.getOperandType(1);
					Register src = instr.getRegister(1);
					Scalar scalar = instr.getScalar(1);
					if (scalar != null && OperandType.isScalar(type) &&
						!OperandType.isAddress(type)) {
						// A true immediate (not a memory displacement like [0x2]).
						regImm.put(dest, scalar.getUnsignedValue());
					}
					else if (src != null && regImm.containsKey(src)) {
						regImm.put(dest, regImm.get(src));
					}
					else {
						regImm.remove(dest);
					}
				}
			}
			else {
				// Any other write to a tracked register invalidates its known immediate.
				for (Object result : instr.getResultObjects()) {
					if (result instanceof Register reg) {
						regImm.remove(reg);
					}
				}
			}
			addr = nextLinear(instr);
			if (addr == null) {
				return null;
			}
		}
		return null;
	}

	private static PseudoInstruction safeDecode(PseudoDisassembler disassembler, Address addr) {
		try {
			return disassembler.disassemble(addr);
		}
		catch (Exception e) {
			return null;
		}
	}

	/** The next physical instruction address (fall-through preferred), or null past the block. */
	private static Address nextLinear(PseudoInstruction instr) {
		Address fallThrough = instr.getFallThrough();
		if (fallThrough != null) {
			return fallThrough;
		}
		try {
			return instr.getAddress().add(instr.getLength());
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
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

			// Note the module bases known from the relocation table in the block
			// comment; CS-relative absolute offsets in module code (e.g. switch jump
			// tables) are relative to these paragraphs, not to the page start.
			StringBuilder comment = new StringBuilder(
				String.format("RTLink/Plus overlay page %d (frame=0x%X)",
					page.getPageIndex() - 1, page.getFrameSize()));
			SortedSet<Integer> moduleBases = page.getModuleBases();
			if (moduleBases.size() > 1) {
				comment.append(", module base paragraphs:");
				for (int base : moduleBases) {
					comment.append(String.format(" 0x%X", base));
				}
			}

			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, true,
				blockName, overlayBase, fileBytes, codeFileOffset, codeSize,
				comment.toString(), "RTLink", true, false, true, log);

			if (block != null) {
				result.add(new OverlayBlockInfo(page, block));
			}
			else {
				log.appendMsg(
					"RTLink: Failed to create block for page " + (page.getPageIndex() - 1));
			}
		}

		Msg.debug(this, "RTLink/Plus: Created " + result.size() + " overlay memory blocks");
		return result;
	}

	private void applyOverlayRelocations(Program program, OverlayBlockInfo info,
			MessageLog log) {
		Memory memory = program.getMemory();
		Address blockStart = info.block().getStart();
		RTLinkOverlayPage page = info.page();
		int pageDisplay = page.getPageIndex() - 1;

		// The runtime fixup loop (210d:2e59 in VICEROY.EXE) addresses each patch
		// site as (frame + seg_index):offset — page-linear seg_index*16 + offset —
		// and adds the same load delta to the unrelocated segment word found there,
		// regardless of seg_index. The delta is the segment the resident image was
		// loaded at: MzLoader bases it at INITIAL_SEGMENT_VAL without setting the
		// program image base, so getImageBase() would yield 0 here.
		int loadDelta = INITIAL_SEGMENT_VAL;

		for (RTLinkRelocation reloc : page.getRelocations()) {
			int siteOffset = reloc.getSiteOffset();

			try {
				Address relocAddr = blockStart.add(siteOffset);
				short currentValue = memory.getShort(relocAddr);
				int segmentValue =
					(Short.toUnsignedInt(currentValue) + loadDelta) & 0xffff;

				memory.setShort(relocAddr, (short) segmentValue);

				program.getRelocationTable().add(relocAddr, Status.APPLIED, 0,
					new long[] { reloc.getOffset(), reloc.getSegmentIndex(), segmentValue },
					2, null);
			}
			catch (MemoryAccessException | AddressOutOfBoundsException e) {
				log.appendMsg(String.format(
					"RTLink: Failed to apply relocation at offset 0x%04X in page %d: %s",
					siteOffset, pageDisplay, e.getMessage()));
			}
		}
	}

	private void discoverAndProcessStubs(Program program,
			List<OverlayBlockInfo> overlayBlocks, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		AddressSet overlayEntryPoints = new AddressSet();
		List<StubTarget> pendingThunks = new ArrayList<>();

		Set<Long> dispatchers = discoverDispatchers(program, monitor);
		if (!dispatchers.isEmpty()) {
			Msg.debug(this, "RTLink/Plus: Discovered " + dispatchers.size() +
				" overlay dispatcher entry point(s)");
		}

		int jmpfStubs = scanForJmpfStubs(program, overlayBlocks, dispatchers,
			overlayEntryPoints, pendingThunks, log, monitor);
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
			createThunkAtStub(funcMgr, stub.stubAddr(), stub.targetAddr(), stub.stubSize(), log);
		}

		Msg.info(this, "RTLink/Plus: Resolved " + total + " dispatch stubs");
	}

	/**
	 * Discover overlay dispatcher entry points instead of hardcoding one offset.
	 * <p>
	 * Every dispatch stub begins with {@code CALLF seg:disp} immediately followed by
	 * {@code JMPF ...}. The dispatcher is therefore the CALLF target shared by a large
	 * number of such CALLF+JMPF pairs. This scans every executable non-overlay block,
	 * tallies the physical CALLF target of each candidate pair, and returns those hit at
	 * least {@link #MIN_DISPATCHER_STUB_COUNT} times. Keying on the physical (flat)
	 * address collapses the many segment:offset aliases that resolve to one dispatcher.
	 */
	private Set<Long> discoverDispatchers(Program program, TaskMonitor monitor)
			throws CancelledException {
		Memory memory = program.getMemory();
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		Map<Long, Integer> counts = new HashMap<>();

		for (MemoryBlock block : memory.getBlocks()) {
			if (block.isOverlay() || !block.isExecute() || !block.isInitialized()) {
				continue;
			}

			Address searchAddr = block.getStart();
			Address blockEnd = block.getEnd();

			while (searchAddr != null && searchAddr.compareTo(blockEnd) < 0) {
				monitor.checkCancelled();

				searchAddr = memory.findBytes(searchAddr, blockEnd,
					new byte[] { OPCODE_CALLF }, null, true, monitor);
				if (searchAddr == null) {
					break;
				}

				try {
					Address jmpfAddr = searchAddr.add(5);
					if (block.contains(jmpfAddr) &&
						memory.getByte(jmpfAddr) == OPCODE_JMPF) {
						int off = Short.toUnsignedInt(memory.getShort(searchAddr.add(1)));
						int seg = Short.toUnsignedInt(memory.getShort(searchAddr.add(3)));
						long target = space.getAddress(seg, off).getOffset();
						counts.merge(target, 1, Integer::sum);
					}
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					// skip
				}

				searchAddr = searchAddr.add(1);
			}
		}

		Set<Long> dispatchers = new HashSet<>();
		for (Map.Entry<Long, Integer> e : counts.entrySet()) {
			if (e.getValue() >= MIN_DISPATCHER_STUB_COUNT) {
				dispatchers.add(e.getKey());
			}
		}
		return dispatchers;
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
		Msg.debug(this, String.format(
			"RTLink/Plus: Disassembled %d overlay byte(s) from %d entry point(s)",
			byteCount, overlayEntryPoints.getNumAddresses()));
	}

	/**
	 * Scan for dispatch stubs by finding JMPF instructions with segment 0x0000, then
	 * validating that a CALLF to a {@link #discoverDispatchers discovered dispatcher}
	 * precedes them.
	 * <p>
	 * Stub layout (12 or 14 bytes):
	 * <pre>
	 *   [0-4]   9A oo oo ss ss   CALLF seg:disp   (seg:disp resolves to a dispatcher)
	 *   [5-9]   EA oo oo 00 00   JMPF 0000:offset
	 *   [10-11] pp pp             page_id (bits 0-13 = 1-based descriptor index)
	 *   [12-13] mm mm             module_word (14-byte form only)
	 * </pre>
	 * page_id is a descriptor index in which 1 is the global overlay table, so the
	 * first code page is index 2; the 1-based overlay page number is page_id - 1.
	 * The JMPF offset is relative to the target module's base paragraph within the
	 * page: 12-byte stubs target module 0, so it is the in-page code offset directly;
	 * 14-byte stubs carry the module's base paragraph in module_word, and the in-page
	 * code offset is JMPF offset + module_word * 16.
	 * <p>
	 * Nothing in page_id flags the stub length (bits 14-15 are always clear), so the
	 * two forms are told apart structurally: if the bytes at +12 begin another
	 * dispatcher stub (a CALLF whose target is a discovered dispatcher), the stub is
	 * 12 bytes; otherwise a word at +12 smaller than the page's total paragraph count
	 * is a module_word. The module_word cannot be validated against the page's
	 * relocation seg_index values ({@link RTLinkOverlayPage#getModuleBases()}) — a
	 * module referenced only by stubs never appears there.
	 */
	private int scanForJmpfStubs(Program program, List<OverlayBlockInfo> overlayBlocks,
			Set<Long> dispatchers, AddressSet overlayEntryPoints,
			List<StubTarget> pendingThunks, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		if (overlayBlocks.isEmpty() || dispatchers.isEmpty()) {
			return 0;
		}

		Memory memory = program.getMemory();
		ReferenceManager refManager = program.getReferenceManager();
		SymbolTable symbolTable = program.getSymbolTable();
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		int count = 0;
		int moduleResolved = 0;

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

					// Validate CALLF opcode and that it targets a discovered dispatcher.
					byte callfOpcode = memory.getByte(callfAddr);
					int callfOffset =
						Short.toUnsignedInt(memory.getShort(callfAddr.add(1)));
					int callfSegment =
						Short.toUnsignedInt(memory.getShort(callfAddr.add(3)));
					long callfTarget = space.getAddress(callfSegment, callfOffset).getOffset();
					if (callfOpcode != OPCODE_CALLF || !dispatchers.contains(callfTarget)) {
						searchAddr = searchAddr.add(1);
						continue;
					}

					int jmpfOffset =
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

					// Distinguish the 12- and 14-byte stub forms (see the method javadoc):
					// the bytes at +12 either begin the next stub (12-byte form, module 0)
					// or hold the target module's base paragraph within the page.
					int stubSize = 12;
					int moduleBase = 0;
					Address moduleWordAddr = callfAddr.add(12);
					if (block.contains(moduleWordAddr.add(1)) &&
						!isDispatcherCallf(memory, space, block, dispatchers,
							moduleWordAddr)) {
						int word = Short.toUnsignedInt(memory.getShort(moduleWordAddr));
						if (word < target.page().getHeader().getTotalParagraphs()) {
							stubSize = 14;
							moduleBase = word;
						}
					}
					int targetOffset = jmpfOffset + moduleBase * 16;

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

					overlayEntryPoints.add(targetAddr);
					pendingThunks.add(new StubTarget(stubAddr, targetAddr, stubSize));
					if (moduleBase != 0) {
						moduleResolved++;
					}
					count++;
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					// skip
				}

				searchAddr = searchAddr.add(1);
			}
		}
		if (moduleResolved > 0) {
			Msg.debug(this, "RTLink/Plus: " + moduleResolved +
				" stub(s) resolved through a nonzero module base");
		}
		return count;
	}

	/**
	 * Returns true if the 5 bytes at {@code addr} form a far call to one of the
	 * discovered overlay dispatchers — i.e. the start of another dispatch stub.
	 */
	private static boolean isDispatcherCallf(Memory memory, SegmentedAddressSpace space,
			MemoryBlock block, Set<Long> dispatchers, Address addr) {
		try {
			if (!block.contains(addr) || !block.contains(addr.add(4))) {
				return false;
			}
			if (memory.getByte(addr) != OPCODE_CALLF) {
				return false;
			}
			int off = Short.toUnsignedInt(memory.getShort(addr.add(1)));
			int seg = Short.toUnsignedInt(memory.getShort(addr.add(3)));
			return dispatchers.contains(space.getAddress(seg, off).getOffset());
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return false;
		}
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
			Address targetAddr, int stubSize, MessageLog log) {
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
			// Already the correct thunk (e.g. a re-run) — nothing to do.
			if (existingStub.isThunk() &&
				overlayFunc.equals(existingStub.getThunkedFunction(false))) {
				return;
			}
			try {
				existingStub.setThunkedFunction(overlayFunc);
				return;
			}
			catch (IllegalArgumentException e) {
				// A plain function was already carved at the stub (auto-analysis
				// reaches it from a real CALLF before we run) and cannot be
				// converted in place. Remove it and recreate below as a thunk so
				// the stub still forwards to its overlay target.
				log.appendMsg(String.format(
					"RTLink: recreating stub thunk at %s -> %s (%s)",
					stubAddr, targetAddr, e.getMessage()));
				funcMgr.removeFunction(stubAddr);
			}
		}

		try {
			AddressSet stubBody = new AddressSet(stubAddr, stubAddr.add(stubSize - 1));
			funcMgr.createThunkFunction(null, null, stubAddr, stubBody,
				overlayFunc, SourceType.ANALYSIS);
		}
		catch (OverlappingFunctionException e) {
			log.appendMsg(String.format(
				"RTLink: could not create stub thunk at %s -> %s: %s",
				stubAddr, targetAddr, e.getMessage()));
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
