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

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for {@link RTLinkFlowRepairAnalyzer}: the two ways real code ends up buried
 * under junk in this corpus, and — as important — the cases the analyzer must refuse
 * to touch.
 * <p>
 * The layouts are the corpus idioms in miniature. The relocation case is MSC's
 * startup error exit ({@code CALL __exit_vector} followed by an inline relocated
 * {@code dw DGROUP}); the conflict case is ROE2MAIN's {@code 1a5e:001c}, where junk
 * one byte into a {@code CALLF} buries it and the real code is reached by
 * fall-through.
 */
public class RTLinkFlowRepairAnalyzerTest extends AbstractGenericTest {

	/** Run a detector inside a transaction and hand back what it repaired. */
	private static int repairRelocations(ProgramBuilder builder) throws Exception {
		Program program = builder.getProgram();
		int txId = program.startTransaction("repair relocations");
		try {
			return RTLinkFlowRepairAnalyzer.repairRelocationFallthroughs(program,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private static int arbitrateConflicts(ProgramBuilder builder) throws Exception {
		Program program = builder.getProgram();
		int txId = program.startTransaction("arbitrate conflicts");
		try {
			return RTLinkFlowRepairAnalyzer.arbitrateConflictBookmarks(program,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	/**
	 * {@code CALL 0x180} whose fall-through is a relocated segment word, a pad byte,
	 * then a routine that something else calls directly.
	 * <pre>
	 *   0100  e8 7d 00     CALL 0x0180        ; the exit-vector call
	 *   0103  34 12        &lt;relocated word&gt;   ; decodes as XOR AL,0x12
	 *   0105  90           &lt;pad&gt;              ; decodes as NOP
	 *   0106  b8 ff 00     MOV AX,0xff        ; real code, called from 0140
	 *   0109  c3           RET
	 *   0140  e8 c3 ff     CALL 0x0106        ; the evidence
	 *   0180  c3           RET                ; the callee
	 * </pre>
	 */
	private static final String RELOC_CODE = "e8 7d 00 34 12 90 b8 ff 00 c3";
	private static final String RELOC_CALLER = "e8 c3 ff";
	private static final String RELOC_CALLEE = "c3";
	/** {@code CALL 0x0100} — the exit call must be real code, as it is in the corpus. */
	private static final String EXIT_CALLER = "e8 dd ff";
	private static final String CALL = "0x1000:0x0100";
	private static final String WORD = "0x1000:0x0103";
	private static final String BURIED = "0x1000:0x0106";

	/**
	 * ROE2MAIN {@code 1a5e:001c} in miniature: junk seeded one byte into a
	 * {@code CALLF} that real fall-through reaches.
	 * <pre>
	 *   0100  55           PUSH BP
	 *   0101  8b ec        MOV BP,SP          ; falls through to 0103
	 *   0103  9a 3c 00 b6 27  CALLF 27b6:003c ; buried by junk at 0104
	 *   0108  c3           RET
	 *   0150  e8 ad ff     CALL 0x0100        ; evidence root
	 *   0160  e8 a1 ff     CALL 0x0104        ; evidence for the JUNK (decline test)
	 * </pre>
	 */
	private static final String CONFLICT_CODE = "55 8b ec 9a 3c 00 b6 27 c3";
	private static final String CONFLICT_CALLER = "e8 ad ff";
	private static final String JUNK_CALLER = "e8 a1 ff";
	private static final String CONFLICT_ENTRY = "0x1000:0x0100";
	private static final String CONFLICT_BURIED = "0x1000:0x0103";
	private static final String CONFLICT_JUNK = "0x1000:0x0104";

	private ProgramBuilder relocProgram(boolean withRelocation) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("RELOC", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x200);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100", RELOC_CODE);
			builder.setBytes("0x1000:0x0120", EXIT_CALLER);
			builder.setBytes("0x1000:0x0140", RELOC_CALLER);
			builder.setBytes("0x1000:0x0180", RELOC_CALLEE);

			Program program = builder.getProgram();
			if (withRelocation) {
				builder.withTransaction(() -> program.getRelocationTable()
						.add(builder.addr(WORD), Status.APPLIED, 0,
							new long[] { 0x100, 0x103, 0x2000 }, 2, null));
			}
			// The two callers first — their CALL references are what make the exit call
			// and the buried routine evidenced code. Then the exit call itself, whose
			// flow decodes the relocated word as junk and runs on into the routine,
			// exactly as a fresh import does. Each disassemble is restricted to the
			// bytes it is given, so the regions are seeded one at a time.
			builder.disassemble("0x1000:0x0120", 3, true);
			builder.disassemble("0x1000:0x0140", 3, true);
			builder.disassemble("0x1000:0x0100", 10, true);
			ok = true;
			return builder;
		}
		finally {
			if (!ok) {
				builder.dispose();
			}
		}
	}

	@Test
	public void testRelocatedWordBehindCallIsSealed() throws Exception {
		ProgramBuilder builder = relocProgram(true);
		try {
			Program program = builder.getProgram();
			Listing listing = program.getListing();
			assertNotNull("setup: junk must be decoded from the relocated word",
				listing.getInstructionAt(builder.addr(WORD)));

			assertEquals(1, repairRelocations(builder));

			Instruction call = listing.getInstructionAt(builder.addr(CALL));
			assertEquals("the call can no longer fall through into the word",
				FlowOverride.CALL_RETURN, call.getFlowOverride());
			assertNull(call.getFallThrough());

			assertNull("junk decoded from the word must be gone",
				listing.getInstructionAt(builder.addr(WORD)));
			assertNotNull("the word must be sealed as data",
				listing.getDefinedDataAt(builder.addr(WORD)));

			Instruction buried = listing.getInstructionAt(builder.addr(BURIED));
			assertNotNull("the called routine must survive", buried);
			assertEquals("MOV", buried.getMnemonicString());
			assertNotNull("and become a function",
				program.getFunctionManager().getFunctionAt(builder.addr(BURIED)));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testWithoutRelocationNothingIsTouched() throws Exception {
		ProgramBuilder builder = relocProgram(false);
		try {
			Program program = builder.getProgram();
			Listing listing = program.getListing();

			assertEquals("no relocation, no claim", 0, repairRelocations(builder));

			assertEquals(FlowOverride.NONE,
				listing.getInstructionAt(builder.addr(CALL)).getFlowOverride());
			assertNotNull("the junk stays: nothing proves it is not code",
				listing.getInstructionAt(builder.addr(WORD)));
			assertNull(listing.getDefinedDataAt(builder.addr(WORD)));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testRelocationRepairIsIdempotent() throws Exception {
		ProgramBuilder builder = relocProgram(true);
		try {
			repairRelocations(builder);
			assertEquals("a sealed word is not repaired twice", 0,
				repairRelocations(builder));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * The SPHERE shape: the relocated word never decoded at all (its bytes are not a
	 * valid instruction), so the disassembler left an ERROR bookmark instead of junk.
	 * The call must still be sealed, and the bookmark dropped.
	 */
	@Test
	public void testUndecodableWordIsSealedAndUnbookmarked() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("SPH", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x200);
			builder.withTransaction(() -> code.setExecute(true));
			// CALL 0x0180; then the word — left undefined, as if it had not decoded.
			builder.setBytes("0x1000:0x0100", "e8 7d 00 34 12 90 b8 ff 00 c3");
			builder.setBytes("0x1000:0x0120", EXIT_CALLER);
			builder.setBytes("0x1000:0x0180", RELOC_CALLEE);
			builder.disassemble("0x1000:0x0120", 3, true);  // evidence for the exit call
			builder.disassemble("0x1000:0x0100", 3, false); // the CALL alone, no flow

			Program program = builder.getProgram();
			Address word = builder.addr(WORD);
			builder.withTransaction(() -> {
				program.getRelocationTable().add(word, Status.APPLIED, 0,
					new long[] { 0x100, 0x103, 0x2000 }, 2, null);
				program.getBookmarkManager().setBookmark(word, BookmarkType.ERROR,
					Disassembler.ERROR_BOOKMARK_CATEGORY,
					"Unable to resolve constructor at 1000:0103 (flow from 1000:0100)");
			});

			assertEquals(1, repairRelocations(builder));
			assertEquals(FlowOverride.CALL_RETURN, program.getListing()
					.getInstructionAt(builder.addr(CALL))
					.getFlowOverride());
			assertNotNull("the word is sealed even when nothing decoded it",
				program.getListing().getDefinedDataAt(word));
			assertNull("its stale error bookmark must be gone",
				program.getBookmarkManager()
						.getBookmark(word, BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY));
		}
		finally {
			builder.dispose();
		}
	}

	private ProgramBuilder conflictProgram(boolean evidenceForJunk) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("CONF", ProgramBuilder._X86_16_REAL_MODE);
		boolean ok = false;
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x200);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes(CONFLICT_ENTRY, CONFLICT_CODE);
			builder.setBytes("0x1000:0x0150", CONFLICT_CALLER);
			if (evidenceForJunk) {
				builder.setBytes("0x1000:0x0160", JUNK_CALLER);
			}

			// Junk first — as a stray flow would have seeded it — then the caller (whose
			// CALL reference is the evidence root), then the real code, which now cannot
			// decode the CALLF at 0103 because 0104 is taken. That is the conflict the
			// disassembler bookmarks in the wild; the mark is placed the same way it
			// does (Disassembler.markCallConflict), at the blocked address.
			builder.disassemble(CONFLICT_JUNK, 4, true);
			builder.disassemble("0x1000:0x0150", 3, true);
			if (evidenceForJunk) {
				builder.disassemble("0x1000:0x0160", 3, true);
			}
			builder.disassemble(CONFLICT_ENTRY, 9, true);

			Program program = builder.getProgram();
			builder.withTransaction(() -> {
				program.getBookmarkManager()
						.setBookmark(builder.addr(CONFLICT_BURIED), BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY,
							"Failed to disassemble at 1000:0103 due to conflicting " +
								"instruction (flow from 1000:0101)");
			});
			ok = true;
			return builder;
		}
		finally {
			if (!ok) {
				builder.dispose();
			}
		}
	}

	@Test
	public void testBuriedCodeWinsOverUnreferencedJunk() throws Exception {
		ProgramBuilder builder = conflictProgram(false);
		try {
			Program program = builder.getProgram();
			Listing listing = program.getListing();
			assertNotNull("setup: junk must exist at 0104",
				listing.getInstructionAt(builder.addr(CONFLICT_JUNK)));
			assertNull("setup: the CALLF must be buried",
				listing.getInstructionAt(builder.addr(CONFLICT_BURIED)));

			assertEquals(1, arbitrateConflicts(builder));

			Instruction buried = listing.getInstructionAt(builder.addr(CONFLICT_BURIED));
			assertNotNull("the buried CALLF must be recovered", buried);
			assertEquals("CALLF", buried.getMnemonicString());
			assertEquals("and take all five of its bytes", 5, buried.getLength());
			assertNull("the junk must be gone",
				listing.getInstructionAt(builder.addr(CONFLICT_JUNK)));
			assertNull("and its bookmark with it",
				program.getBookmarkManager()
						.getBookmark(builder.addr(CONFLICT_BURIED), BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testConflictWithEvidenceOnBothSidesIsDeclined() throws Exception {
		ProgramBuilder builder = conflictProgram(true);
		try {
			Program program = builder.getProgram();
			Listing listing = program.getListing();

			assertEquals("something calls the junk: this is not ours to decide", 0,
				arbitrateConflicts(builder));
			assertNotNull("the junk stays",
				listing.getInstructionAt(builder.addr(CONFLICT_JUNK)));
			assertNotNull("and so does the bookmark",
				program.getBookmarkManager()
						.getBookmark(builder.addr(CONFLICT_BURIED), BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * The negative control that matters: a disassembly island over data, reached by
	 * nothing, conflicting with bytes that are also reached by nothing. Neither side
	 * has evidence, so the analyzer must leave the whole thing alone.
	 */
	@Test
	public void testUnevidencedConflictIsLeftAlone() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("ISLE", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0000", 0x200);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x01c0", "9a 3c 00 b6 27 c3");
			builder.disassemble("0x1000:0x01c1", 4, true); // island, referenced by nothing

			Program program = builder.getProgram();
			Address buried = builder.addr("0x1000:0x01c0");
			builder.withTransaction(() -> program.getBookmarkManager()
					.setBookmark(buried, BookmarkType.ERROR,
						Disassembler.ERROR_BOOKMARK_CATEGORY,
						"Failed to disassemble at 1000:01c0 due to conflicting " +
							"instruction (flow from 1000:01bd)"));

			assertEquals("nothing is evidenced here; nothing may be cleared", 0,
				arbitrateConflicts(builder));
			assertNotNull("the island stays",
				program.getListing().getInstructionAt(builder.addr("0x1000:0x01c1")));
			assertNotNull("the bookmark stays",
				program.getBookmarkManager()
						.getBookmark(buried, BookmarkType.ERROR,
							Disassembler.ERROR_BOOKMARK_CATEGORY));
		}
		finally {
			builder.dispose();
		}
	}

	@Test
	public void testConflictArbitrationIsIdempotent() throws Exception {
		ProgramBuilder builder = conflictProgram(false);
		try {
			arbitrateConflicts(builder);
			assertEquals("a repaired conflict is not repaired twice", 0,
				arbitrateConflicts(builder));
		}
		finally {
			builder.dispose();
		}
	}

	private static int fillGaps(ProgramBuilder builder) throws Exception {
		Program program = builder.getProgram();
		int txId = program.startTransaction("fill code gaps");
		try {
			return RTLinkFlowRepairAnalyzer.fillCodeGaps(program, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	/**
	 * ROE2MAIN {@code 122e:51a0} in miniature: a routine nothing references, whose
	 * bytes were cleared out from under the pattern seeders, so no pass ever reaches
	 * it. Its prologue and its stranded epilogue are both undefined runs bounded by
	 * code — and both decode exactly onto the code that follows them.
	 * <pre>
	 *   0100  55 8b ec 83 ec 12   PUSH BP; MOV BP,SP; SUB SP,0x12   ; gap 1 (prologue)
	 *   0106  eb 02               JMP 0x010a                        ; disassembled: the
	 *   0108  eb fc               JMP 0x0106                        ; only code flow
	 *   010a  8b e5 5d cb         MOV SP,BP; POP BP; RETF           ; gap 2 (epilogue)
	 *   010e  55 8b ec 5d cb      the next function
	 * </pre>
	 */
	@Test
	public void testUnreachedPrologueAndEpilogueAreRecovered() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("GAP", ProgramBuilder._X86_16_REAL_MODE);
		try {
			// The block starts at the routine: a gap is a run of undefined bytes
			// between code, and the block's own unused tail is not one.
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x20);
			builder.withTransaction(() -> code.setExecute(true));
			builder.setBytes("0x1000:0x0100",
				"55 8b ec 83 ec 12 eb 02 eb fc 8b e5 5d cb 55 8b ec 5d cb");
			// Only the little JMP loop is reachable, exactly as flow-only recovery
			// leaves it; the prologue above and the epilogue below stay undefined.
			builder.disassemble("0x1000:0x0106", 4, true);
			builder.disassemble("0x1000:0x010e", 5, true);
			builder.createFunction("0x1000:0x010e");

			Program program = builder.getProgram();
			Listing listing = program.getListing();
			assertNull("setup: the prologue must start out buried",
				listing.getInstructionAt(builder.addr("0x1000:0x0100")));
			assertNull("setup: so must the epilogue",
				listing.getInstructionAt(builder.addr("0x1000:0x010a")));

			assertEquals("both gaps are routines, not padding", 2, fillGaps(builder));

			Instruction prologue = listing.getInstructionAt(builder.addr("0x1000:0x0100"));
			assertNotNull("the prologue must be recovered", prologue);
			assertEquals("PUSH", prologue.getMnemonicString());
			assertNotNull("and become a function",
				program.getFunctionManager().getFunctionAt(builder.addr("0x1000:0x0100")));

			Instruction epilogue = listing.getInstructionAt(builder.addr("0x1000:0x010a"));
			assertNotNull("the stranded epilogue must be recovered", epilogue);
			assertEquals("MOV", epilogue.getMnemonicString());
			assertNotNull("all the way to its return",
				listing.getInstructionAt(builder.addr("0x1000:0x010d")));
		}
		finally {
			builder.dispose();
		}
	}

	/**
	 * The other negative control: alignment padding and data-shaped runs between
	 * routines must never be decoded, however cleanly they would parse.
	 */
	@Test
	public void testPaddingAndOutOfPhaseGapsAreLeftAlone() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("PAD", ProgramBuilder._X86_16_REAL_MODE);
		try {
			MemoryBlock code = builder.createMemory("CODE", "0x1000:0x0100", 0x20);
			builder.withTransaction(() -> code.setExecute(true));
			// 0100: a routine; 0104..0107: four zero bytes of padding; 0108: the next
			// routine. The zeros would decode (as ADD [BX+SI],AL) and land exactly on
			// 0108 — the phase test alone would accept them. Only the repeated-byte
			// rule rejects them.
			builder.setBytes("0x1000:0x0100", "55 8b ec cb 00 00 00 00 55 8b ec cb");
			builder.disassemble("0x1000:0x0100", 4, true);
			builder.disassemble("0x1000:0x0108", 4, true);
			builder.createFunction("0x1000:0x0108");

			assertEquals("padding is not code", 0, fillGaps(builder));
			assertNull("the zeros must stay undefined", builder.getProgram()
					.getListing()
					.getInstructionAt(builder.addr("0x1000:0x0104")));
		}
		finally {
			builder.dispose();
		}
	}
}
