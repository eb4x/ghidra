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
import java.util.Iterator;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Repairs <b>buried code</b>: real, evidenced instructions that stay undisassembled
 * because junk from a bad flow covers their bytes. Runs dead last, after every pass
 * that plants flows or stamps conflict bookmarks, and enforces one invariant —
 * <i>referenced code always wins over unreferenced junk</i>.
 * <p>
 * <b>Detector A — relocation fall-throughs.</b> An address carrying a loader
 * relocation is a patched <i>operand word</i> (MZ header relocations and the RTLink
 * overlay relocations both record the 2-byte segment word itself; see
 * {@code MzLoader.processRelocations} and
 * {@code RTLinkOverlayAnalyzer.applyOverlayRelocations}), so it can never be the
 * first byte of a real instruction. A CALL whose fall-through lands exactly on such
 * a word therefore never returns there, whatever its callee does. The corpus shape
 * is MSC's startup error exit — {@code MOV AX,0xFF; PUSH AX; PUSH CS;
 * CALL word ptr [__exit_vector]} followed by an inline {@code dw DGROUP} (VICEROY
 * {@code 1d1d:0241}, NEBULAR {@code 1417:00fd}, SPHERE {@code 160f:0109}, ROE2MAIN
 * {@code 122e:011c}) — where the junk parsed from the relocated word buries the
 * directly-called routine that follows it. The repair: mark the call
 * {@link FlowOverride#CALL_RETURN}, clear the junk, seal the word as data so no
 * later pass can decode it again, and resurrect the referenced follower.
 * Synthetic relocation records with a nonzero type (e.g.
 * {@code EmulatedFloatPatcher}'s rewrite audit trail, stamped at instruction
 * starts) are excluded; only type-0 segment-word relocations carry the invariant.
 * <p>
 * <b>Detector B — conflict-bookmark arbitration.</b> When the disassembler cannot
 * decode a flow target because junk already covers it, it stamps an ERROR
 * "Bad Instruction" bookmark <i>at the blocked address</i> ("Failed to disassemble
 * at X due to conflicting instruction (flow from Z)" — see
 * {@code Disassembler.markCallConflict}). For each such bookmark, if the blocked
 * address has evidence (a flow reference, or fall-through from an instruction whose
 * fall-from chain reaches a function entry, a referenced address, or a user symbol)
 * and every conflicting instruction chain has none, the junk is cleared
 * ({@link ClearFlowAndRepairCmd}, which prunes anything with outside evidence) and
 * the blocked address disassembled. Both-sides-evidenced conflicts are declined
 * with a warning; no-evidence conflicts (e.g. disassembly islands over zeroed data,
 * seeded refless by pattern search) are left exactly as they are. On ROE2MAIN this
 * recovers a trampoline {@code CALLF} at {@code 1a5e:001c}, two overlay PUSHes at
 * {@code OVERLAY_052::044721}, and a function epilogue at {@code 122e:51be} whose
 * bookmark names the page-segment alias {@code 1000:749e} — same flat byte, which
 * is why the moved-mark guard compares parsed addresses, never strings.
 * <p>
 * Junk buried this way is known to come from passes that disassemble without
 * leaving references — {@code DecompilerSwitchAnalysisCmd} gives its default case
 * no reference and resolves decompiler-recovered flat offsets into page-segment
 * addresses (an upstream gap, noted here rather than patched: adding a default-case
 * reference would change flow modeling for every program this fork opens).
 * <p>
 * Ordering inside a repair is load-bearing, learned the hard way from
 * {@code ClearFlowAndRepairCmd.repairFallThroughsInto}: the CALL's fall-through
 * must be overridden <i>before</i> the clear (or the repair step walks backward,
 * finds the live fall-through, and regenerates the junk), and a junk instruction's
 * unevidenced fall-from chain must be cleared <i>with</i> it (or its predecessor
 * resurrects it).
 */
public class RTLinkFlowRepairAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RTLink Buried Code Repair";
	private static final String DESCRIPTION =
		"Repairs code buried under junk instructions from bad flows: removes the " +
			"impossible fall-through of calls that land on loader-relocated segment " +
			"words, and arbitrates the disassembler's conflicting-instruction " +
			"bookmarks in favor of referenced code over unreferenced junk. Re-run " +
			"as a one-shot to repair conflicts introduced after the initial pass.";

	/** Backward fall-from walk bound; exhaustion counts as evidence (never clear). */
	private static final int JUNK_CHAIN_WALK_LIMIT = 64;

	/** How far past a relocated word to look for a referenced, buried follower. */
	private static final int FOLLOWER_SCAN_LIMIT = 8;

	/** A gap shorter than this cannot be a routine, and a longer one is not a gap. */
	private static final int MIN_GAP_LENGTH = 2;
	private static final int MAX_GAP_LENGTH = 64;

	/** Rounds to run the gap filler for; it converges in two or three on this corpus. */
	private static final int GAP_FILL_ROUNDS = 10;

	private long lastTxId = -1;

	public RTLinkFlowRepairAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// Dead last: every pass that disassembles, plants flows or stamps conflict
		// bookmarks — including DecompilerSwitchAnalyzer at CODE_ANALYSIS and all
		// four RTLink analyzers — has finished its first wave by then.
		setPriority(AnalysisPriority.LOW_PRIORITY.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return RTLinkOverlayAnalyzer.isSegmentedMzProgram(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		long txId = program.getCurrentTransactionInfo().getID();
		if (txId == lastTxId) {
			return true; // our own repairs re-trigger byte analysis; run once per txn
		}
		lastTxId = txId;

		int fallthroughs = repairRelocationFallthroughs(program, monitor);
		int conflicts = arbitrateConflictBookmarks(program, monitor);

		// Filling a gap creates a function, and a function is what identifies the
		// stranded epilogue of the routine above it — so each round exposes the next.
		// Run to a fixpoint rather than leaving code for a second invocation to find.
		int gaps = 0;
		for (int round = 0; round < GAP_FILL_ROUNDS; round++) {
			int filled = fillCodeGaps(program, monitor);
			if (filled == 0) {
				break;
			}
			gaps += filled;
		}
		// Last: a conflict mark whose blocked address now holds code is a fossil,
		// whether this analyzer cleared the junk or an earlier pass already had.
		sweepRepairedConflictBookmarks(program, monitor);

		// Msg.info only — content in the MessageLog pops the analysis warnings dialog.
		if (fallthroughs > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Sealed %d relocated word(s) behind non-returning calls",
				fallthroughs));
		}
		if (conflicts > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Recovered %d buried instruction run(s) from junk conflicts",
				conflicts));
		}
		if (gaps > 0) {
			Msg.info(this, String.format(
				"RTLink/Plus: Disassembled %d unreached code gap(s) between routines", gaps));
		}
		return true;
	}

	/**
	 * Detector A. For every type-0 (segment word) relocation whose address is the
	 * fall-through of a CALL: override the call to {@link FlowOverride#CALL_RETURN},
	 * clear any junk decoded from the word, drop the ERROR bookmarks confined to it,
	 * seal it as word data, and resurrect referenced code buried behind it.
	 */
	static int repairRelocationFallthroughs(Program program, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		int repaired = 0;

		Iterator<Relocation> relocations = program.getRelocationTable().getRelocations();
		while (relocations.hasNext()) {
			monitor.checkCancelled();
			Relocation relocation = relocations.next();
			if (relocation.getType() != 0) {
				continue; // synthetic record (e.g. emulated-FP rewrite), not a word patch
			}
			Address word = relocation.getAddress();

			Instruction caller = callFallingThroughTo(program, word);
			if (caller == null) {
				continue;
			}
			if (listing.getDefinedDataAt(word) != null) {
				continue; // already sealed by an earlier run
			}

			// Kill the fall-through FIRST: the clear's repair step re-disassembles
			// fall-throughs into the cleared range, and must not find this one.
			caller.setFlowOverride(FlowOverride.CALL_RETURN);

			if (listing.getInstructionAt(word) != null) {
				new ClearFlowAndRepairCmd(word, false, false, true)
						.applyTo(program, monitor);
			}

			program.getBookmarkManager()
					.removeBookmarks(new AddressSet(word, word.add(1)),
						BookmarkType.ERROR, monitor);

			sealRelocationWord(program, word);
			resurrectAfterWord(program, word, monitor);
			repaired++;
		}
		return repaired;
	}

	/**
	 * The evidenced CALL instruction whose fall-through is exactly {@code word}, or
	 * null. A relocation that is the <i>operand</i> of a live instruction (a
	 * {@code CALLF} segment word, a {@code MOV AX,SEG} immediate) sits inside an
	 * instruction that starts before it, and is skipped.
	 */
	private static Instruction callFallingThroughTo(Program program, Address word) {
		Listing listing = program.getListing();
		Instruction covering = listing.getInstructionContaining(word);
		if (covering != null && !covering.getMinAddress().equals(word)) {
			return null; // operand of a live instruction
		}
		Address before = word.previous();
		if (before == null) {
			return null;
		}
		Instruction caller = listing.getInstructionContaining(before);
		if (caller == null || !caller.getFlowType().isCall()) {
			return null;
		}
		Address fallThrough = caller.getFallThrough();
		if (fallThrough == null || !fallThrough.equals(word)) {
			return null;
		}
		// The caller itself must be real code: junk callers repair nothing.
		if (program.getFunctionManager()
				.getFunctionContaining(caller.getMinAddress()) == null &&
			!isEvidencedInstruction(program, caller)) {
			return null;
		}
		return caller;
	}

	/**
	 * Define the loader-patched word as data so no later pass can ever decode junk
	 * from it again. Failure to place the data (bytes claimed by something else in
	 * the meantime) is tolerated: the {@code CALL_RETURN} override alone already
	 * removes the flow that created the junk.
	 */
	private static void sealRelocationWord(Program program, Address word) {
		try {
			DataUtilities.createData(program, word, WordDataType.dataType, 2,
				ClearDataMode.CHECK_FOR_SPACE);
			program.getListing()
					.setComment(word, CodeUnit.EOL_COMMENT,
						"Loader-relocated segment word: data, never code " +
							"(RTLink Buried Code Repair)");
		}
		catch (Exception e) {
			Msg.warn(RTLinkFlowRepairAnalyzer.class,
				"RTLink: could not seal relocated word at " + word + ": " + e.getMessage());
		}
	}

	/**
	 * Bring back the code the junk was covering. Evidence first: every
	 * flow-referenced but undefined address within {@value #FOLLOWER_SCAN_LIMIT}
	 * bytes after the word is disassembled (the corpus followers are all direct
	 * call targets — e.g. NEBULAR {@code 1417:0104}, called from {@code 1417:00b1}).
	 * When nothing is referenced and nothing is defined, fall back to the idiom: the
	 * inline word is followed by an optional single zero pad byte, then code
	 * (ROE2MAIN has no pad; the other three do).
	 */
	private static void resurrectAfterWord(Program program, Address word,
			TaskMonitor monitor) {
		Listing listing = program.getListing();
		AddressSet targets = new AddressSet();
		Address after = word.add(2);
		for (int i = 0; i < FOLLOWER_SCAN_LIMIT; i++) {
			Address candidate = after.add(i);
			if (listing.getInstructionAt(candidate) != null) {
				// Code already lives here — either it was never buried, or the clear
				// pruned it as evidenced. Nothing to disassemble, but a routine that
				// something calls still deserves to be a function.
				promoteIfCalled(program, candidate, monitor);
				return;
			}
			if (hasFlowReferenceTo(program, candidate)) {
				targets.add(candidate);
			}
		}
		if (targets.isEmpty() && listing.getUndefinedDataAt(after) != null) {
			try {
				byte pad = program.getMemory().getByte(after);
				targets.add(pad == 0 ? after.add(1) : after);
			}
			catch (MemoryAccessException e) {
				return;
			}
		}
		if (targets.isEmpty()) {
			return;
		}
		new DisassembleCommand(targets, null, true).applyTo(program, monitor);
		for (Address target : targets.getAddresses(true)) {
			promoteIfCalled(program, target, monitor);
		}
	}

	/**
	 * Detector B. Arbitrate every "Failed to disassemble ... due to conflicting
	 * instruction" bookmark: the bookmark sits at the buried address; when the
	 * buried side has evidence and the junk side has none, the junk loses.
	 */
	static int arbitrateConflictBookmarks(Program program, TaskMonitor monitor)
			throws CancelledException {
		BookmarkManager bookmarks = program.getBookmarkManager();
		Listing listing = program.getListing();

		List<Bookmark> conflicts = new ArrayList<>();
		Iterator<Bookmark> iterator = bookmarks.getBookmarksIterator(BookmarkType.ERROR);
		while (iterator.hasNext()) {
			Bookmark bookmark = iterator.next();
			if (Disassembler.ERROR_BOOKMARK_CATEGORY.equals(bookmark.getCategory()) &&
				bookmark.getComment().startsWith("Failed to disassemble at ") &&
				bookmark.getComment().contains("due to conflicting instruction")) {
				conflicts.add(bookmark);
			}
		}

		int repaired = 0;
		for (Bookmark bookmark : conflicts) {
			monitor.checkCancelled();
			Address buried = bookmark.getAddress();

			if (movedMark(program, bookmark)) {
				continue; // stamped at the flow source, not the blocked address
			}
			if (listing.getInstructionAt(buried) != null) {
				continue; // already repaired (idempotency for one-shot re-runs)
			}

			int length = pseudoLength(program, buried);
			if (length <= 0) {
				continue; // the buried bytes do not decode; nothing to arbitrate
			}

			AddressSet junkStarts = collectJunkClearStarts(program, buried, length);
			if (junkStarts == null) {
				Msg.warn(RTLinkFlowRepairAnalyzer.class,
					"RTLink: conflict at " + buried +
						" has evidence on both sides; left for manual review");
				continue;
			}
			if (junkStarts.isEmpty()) {
				continue; // no conflicting instruction found anymore
			}

			AddressSet evidence = new AddressSet();
			if (!buriedHasEvidence(program, buried, junkStarts, evidence)) {
				continue; // no evidence: leave it exactly as it is
			}

			new ClearFlowAndRepairCmd(junkStarts, evidence, false, false, true)
					.applyTo(program, monitor);
			if (listing.getInstructionAt(buried) == null) {
				new DisassembleCommand(buried, null, true).applyTo(program, monitor);
			}
			if (listing.getInstructionAt(buried) == null) {
				continue; // repair failed; the disassembler re-marks as needed
			}

			fixupAround(program, buried, evidence, monitor);
			bookmarks.removeBookmark(bookmark);
			repaired++;
		}
		return repaired;
	}

	/**
	 * Drop the conflict bookmarks whose blocked address now holds an instruction. The
	 * disassembler stamps these when it cannot decode a flow target, and never takes
	 * them back — so a mark survives its own repair, including repairs made by a pass
	 * that cleared the junk without re-marking (ROE2MAIN's {@code 122e:51be} is left
	 * that way by {@link EmulatedFloatPatcher}: the junk it complains about is long
	 * gone, and the code it blocked is recovered by {@link #fillCodeGaps}).
	 */
	static int sweepRepairedConflictBookmarks(Program program, TaskMonitor monitor)
			throws CancelledException {
		BookmarkManager bookmarks = program.getBookmarkManager();
		Listing listing = program.getListing();

		List<Bookmark> stale = new ArrayList<>();
		Iterator<Bookmark> iterator = bookmarks.getBookmarksIterator(BookmarkType.ERROR);
		while (iterator.hasNext()) {
			monitor.checkCancelled();
			Bookmark bookmark = iterator.next();
			if (Disassembler.ERROR_BOOKMARK_CATEGORY.equals(bookmark.getCategory()) &&
				bookmark.getComment().startsWith("Failed to disassemble at ") &&
				listing.getInstructionAt(bookmark.getAddress()) != null) {
				stale.add(bookmark);
			}
		}
		for (Bookmark bookmark : stale) {
			bookmarks.removeBookmark(bookmark);
		}
		return stale.size();
	}

	/**
	 * True when the bookmark was relocated away from the blocked address
	 * ({@code Disassembler.markInstructionError} moves marks that cannot be placed
	 * in uninitialized memory). Compared as parsed <i>addresses</i>, never strings:
	 * ROE2MAIN's bookmark at {@code 122e:51be} names {@code 1000:749e} — the same
	 * flat byte through the page segment.
	 */
	private static boolean movedMark(Program program, Bookmark bookmark) {
		String comment = bookmark.getComment();
		int start = "Failed to disassemble at ".length();
		int end = comment.indexOf(" due to ");
		if (end <= start) {
			return false; // unparseable: trust the bookmark address
		}
		Address named = program.getAddressFactory().getAddress(comment.substring(start, end));
		return named != null && !named.equals(bookmark.getAddress());
	}

	/** The decoded length of the buried instruction, or -1 if it does not decode. */
	private static int pseudoLength(Program program, Address buried) {
		try {
			// Null, not an exception, is how undecodable bytes are reported.
			PseudoInstruction decoded = new PseudoDisassembler(program).disassemble(buried);
			return decoded == null ? -1 : decoded.getLength();
		}
		catch (Exception e) {
			return -1;
		}
	}

	/**
	 * The clear seeds for the junk burying {@code buried}: the instruction covering
	 * it, every instruction starting inside its would-be extent, and each one's
	 * unevidenced fall-from chain root (a junk predecessor left alone would just
	 * fall through and resurrect the junk). Returns null when any junk instruction
	 * turns out to carry evidence of its own — that is a both-sides conflict this
	 * analyzer must not decide.
	 */
	private static AddressSet collectJunkClearStarts(Program program, Address buried,
			int length) {
		Listing listing = program.getListing();
		AddressSet junkStarts = new AddressSet();

		List<Instruction> conflicting = new ArrayList<>();
		Instruction covering = listing.getInstructionContaining(buried);
		if (covering != null && !covering.getMinAddress().equals(buried)) {
			conflicting.add(covering);
		}
		for (int i = 1; i < length; i++) {
			Instruction inside = listing.getInstructionAt(buried.add(i));
			if (inside != null) {
				conflicting.add(inside);
			}
		}

		for (Instruction junk : conflicting) {
			Address root = junkChainRoot(program, junk);
			if (root == null) {
				return null; // evidenced junk: both sides real, decline
			}
			junkStarts.add(root, root);
			junkStarts.add(junk.getMinAddress(), junk.getMinAddress());
		}
		return junkStarts;
	}

	/**
	 * Walk {@code junk}'s fall-from chain to its root, requiring every node to be
	 * unevidenced. Null means a node carried evidence (or the walk bound was hit,
	 * which is treated the same — never clear what cannot be proven junk).
	 */
	private static Address junkChainRoot(Program program, Instruction junk) {
		Listing listing = program.getListing();
		Instruction current = junk;
		for (int i = 0; i < JUNK_CHAIN_WALK_LIMIT; i++) {
			if (isEvidencedInstruction(program, current)) {
				return null;
			}
			Address fallFrom = current.getFallFrom();
			if (fallFrom == null) {
				return current.getMinAddress();
			}
			Instruction predecessor = listing.getInstructionContaining(fallFrom);
			if (predecessor == null) {
				return current.getMinAddress();
			}
			Address predecessorFt = predecessor.getFallThrough();
			if (predecessorFt == null ||
				!predecessorFt.equals(current.getMinAddress())) {
				return current.getMinAddress(); // not actually flowed into
			}
			current = predecessor;
		}
		return null; // bound exhausted: treat as evidenced
	}

	/**
	 * Direct evidence that {@code instruction} is real code: a flow reference to
	 * its entry, a function entry, an external entry point, or a non-default
	 * symbol. Function <i>containment</i> is deliberately not evidence — junk gets
	 * absorbed into function bodies.
	 */
	private static boolean isEvidencedInstruction(Program program, Instruction instruction) {
		Address entry = instruction.getMinAddress();
		if (hasFlowReferenceTo(program, entry)) {
			return true;
		}
		if (program.getFunctionManager().getFunctionAt(entry) != null) {
			return true;
		}
		if (program.getSymbolTable().isExternalEntryPoint(entry)) {
			return true;
		}
		Symbol primary = program.getSymbolTable().getPrimarySymbol(entry);
		return primary != null && primary.getSource() != SourceType.DEFAULT;
	}

	private static boolean hasFlowReferenceTo(Program program, Address address) {
		for (Reference reference : program.getReferenceManager().getReferencesTo(address)) {
			if (reference.getReferenceType().isFlow()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Evidence that {@code buried} is real code, collected into {@code evidence}
	 * (the protected set for the clear): a flow reference from outside the junk, or
	 * fall-through from an instruction whose own fall-from chain carries evidence.
	 */
	private static boolean buriedHasEvidence(Program program, Address buried,
			AddressSetView junkStarts, AddressSet evidence) {
		Listing listing = program.getListing();
		boolean found = false;

		for (Reference reference : program.getReferenceManager().getReferencesTo(buried)) {
			if (!reference.getReferenceType().isFlow()) {
				continue;
			}
			Address from = reference.getFromAddress();
			Instruction source = listing.getInstructionContaining(from);
			if (source == null || junkStarts.contains(source.getMinAddress())) {
				continue;
			}
			evidence.add(source.getMinAddress(), source.getMaxAddress());
			found = true;
		}

		Address before = buried.previous();
		Instruction predecessor = before == null ? null : listing.getInstructionContaining(before);
		if (predecessor != null && buried.equals(predecessor.getFallThrough()) &&
			!junkStarts.contains(predecessor.getMinAddress()) &&
			evidencedThroughChain(program, predecessor)) {
			evidence.add(predecessor.getMinAddress(), predecessor.getMaxAddress());
			found = true;
		}

		if (program.getSymbolTable().isExternalEntryPoint(buried)) {
			found = true;
		}
		return found;
	}

	/** Evidence via the bounded fall-from chain: any node directly evidenced. */
	private static boolean evidencedThroughChain(Program program, Instruction instruction) {
		Listing listing = program.getListing();
		Instruction current = instruction;
		for (int i = 0; i < JUNK_CHAIN_WALK_LIMIT && current != null; i++) {
			if (isEvidencedInstruction(program, current)) {
				return true;
			}
			Address fallFrom = current.getFallFrom();
			if (fallFrom == null) {
				return false;
			}
			current = listing.getInstructionContaining(fallFrom);
		}
		return false;
	}

	/**
	 * After a successful resurrection: absorb the recovered flow into the evidence
	 * function's body, and promote the buried address to a function when something
	 * calls it directly.
	 */
	private static void fixupAround(Program program, Address buried,
			AddressSetView evidence, TaskMonitor monitor) throws CancelledException {
		promoteIfCalled(program, buried, monitor);
		if (!evidence.isEmpty()) {
			Function owner = program.getFunctionManager()
					.getFunctionContaining(evidence.getMinAddress());
			if (owner != null) {
				CreateFunctionCmd.fixupFunctionBody(program, program.getListing()
						.getInstructionAt(owner.getEntryPoint()), monitor);
			}
		}
	}

	/**
	 * Detector C. Disassemble the code gaps that flow never reaches.
	 * <p>
	 * A routine whose entry nothing references and whose bytes were cleared out from
	 * under the pattern seeders is reachable by no pass at all: it is simply left as
	 * undefined bytes between two runs of code. ROE2MAIN has both halves of one such
	 * routine — the prologue at {@code 122e:51a0} ({@code PUSH BP; MOV BP,SP;
	 * SUB SP,0x12}, byte-for-byte its sibling {@code FUN_122e_5177}) and its epilogue
	 * at {@code 122e:51be} ({@code MOV SP,BP; POP BP; RETF}) — orphaned when
	 * {@link EmulatedFloatPatcher} cleared the emulator-call window around them and
	 * re-disassembled by flow, which reaches neither.
	 * <p>
	 * The gap is claimed only when its bytes account for themselves exactly: every
	 * instruction decodes, and the run ends precisely on the boundary of the next
	 * defined code unit — one byte over or under and this is not an in-phase run of
	 * code. That alone would also swallow alignment padding, so the gap must in
	 * addition <i>look like</i> a routine: it begins with a frame prologue, or it ends
	 * with a return right where the next function begins (a stranded epilogue), or the
	 * instruction above it falls straight into it. A run of one repeated byte is
	 * padding by definition and is never claimed — which is what keeps this off the
	 * zero-filled islands in the C library's data.
	 */
	static int fillCodeGaps(Program program, TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		AddressSet gapStarts = new AddressSet();

		for (MemoryBlock block : program.getMemory().getBlocks()) {
			monitor.checkCancelled();
			if (!block.isExecute() || !block.isInitialized()) {
				continue;
			}
			AddressIterator undefined = listing.getUndefinedRanges(
				new AddressSet(block.getStart(), block.getEnd()), true, monitor)
					.getAddresses(true);
			Address gapStart = null;
			Address previous = null;
			while (undefined.hasNext()) {
				monitor.checkCancelled();
				Address current = undefined.next();
				if (gapStart == null) {
					gapStart = current;
				}
				else if (previous != null && !current.equals(previous.next())) {
					if (isRecoverableGap(program, gapStart, previous)) {
						gapStarts.add(inSegmentOf(block, gapStart));
					}
					gapStart = current;
				}
				previous = current;
			}
			if (gapStart != null && previous != null &&
				isRecoverableGap(program, gapStart, previous)) {
				gapStarts.add(inSegmentOf(block, gapStart));
			}
		}

		if (gapStarts.isEmpty()) {
			return 0;
		}
		int filled = 0;
		for (Address start : gapStarts.getAddresses(true)) {
			monitor.checkCancelled();
			// Restricted to the gap: flow out of it is already disassembled, and a
			// runaway would be exactly the mis-phased decode this guards against.
			new DisassembleCommand(start, null, false).applyTo(program, monitor);
			if (listing.getInstructionAt(start) == null) {
				continue;
			}
			promoteIfPrologue(program, start, monitor);
			filled++;
		}
		return filled;
	}

	/**
	 * The same byte, addressed through the paragraph its block is based at.
	 * <p>
	 * Iterating a segmented space hands back addresses built from the flat offset, and
	 * {@code SegmentedAddressSpace} renders those through the 64KB <i>page</i> segment
	 * ({@code getDefaultSegmentFromFlat}) — so a gap in a block based at {@code 122e}
	 * arrives as {@code 1000:7480}. It is the same location and compares equal, but a
	 * function created at it is named for the page, and every label the repair leaves
	 * behind reads as if it belonged to a segment the code never runs in.
	 */
	private static Address inSegmentOf(MemoryBlock block, Address address) {
		if (!(block.getStart() instanceof SegmentedAddress start) ||
			!(address.getAddressSpace() instanceof SegmentedAddressSpace space) ||
			!address.getAddressSpace().equals(start.getAddressSpace())) {
			return address;
		}
		long offset = address.getOffset() - (long) start.getSegment() * 16;
		if (offset < 0 || offset > 0xffffL) {
			return address; // not addressable from this block's paragraph
		}
		return space.getAddress(start.getSegment(), (int) offset);
	}

	/**
	 * True when the undefined run {@code [start, end]} is a routine the analysis
	 * missed rather than padding or data: in-phase (it decodes exactly onto the next
	 * code unit) and shaped like code (prologue, stranded epilogue, or fallen into).
	 */
	private static boolean isRecoverableGap(Program program, Address start, Address end) {
		long length = end.subtract(start) + 1;
		if (length < MIN_GAP_LENGTH || length > MAX_GAP_LENGTH) {
			return false;
		}
		byte[] bytes = new byte[(int) length];
		try {
			if (program.getMemory().getBytes(start, bytes) != bytes.length) {
				return false;
			}
		}
		catch (MemoryAccessException e) {
			return false;
		}
		if (isRepeatedByte(bytes)) {
			return false; // padding, not code
		}

		PseudoDisassembler pseudo = new PseudoDisassembler(program);
		Address at = start;
		Instruction last = null;
		long consumed = 0;
		while (consumed < length) {
			PseudoInstruction decoded;
			try {
				// Undecodable bytes come back as null here, not as an exception.
				decoded = pseudo.disassemble(at);
			}
			catch (Exception e) {
				decoded = null;
			}
			if (decoded == null) {
				return false; // does not decode: not code
			}
			last = decoded;
			consumed += decoded.getLength();
			at = at.add(decoded.getLength());
		}
		if (consumed != length) {
			return false; // out of phase: the run overshoots the code that follows
		}

		return startsWithPrologue(bytes) || isStrandedEpilogue(program, end, last) ||
			fallsInto(program, start);
	}

	/** {@code PUSH BP; MOV BP,SP} — the frame prologue every routine here opens with. */
	private static boolean startsWithPrologue(byte[] bytes) {
		return bytes.length >= 3 && bytes[0] == 0x55 && bytes[1] == (byte) 0x8b &&
			bytes[2] == (byte) 0xec;
	}

	/**
	 * True when the gap ends in a return and the next code unit starts a function —
	 * the epilogue of the routine above it, stranded when nothing flowed into it.
	 */
	private static boolean isStrandedEpilogue(Program program, Address end,
			Instruction last) {
		if (last == null || !last.getFlowType().isTerminal()) {
			return false;
		}
		Address next = end.next();
		return next != null && program.getFunctionManager().getFunctionAt(next) != null;
	}

	/** True when the instruction above the gap falls straight into it. */
	private static boolean fallsInto(Program program, Address start) {
		Address before = start.previous();
		if (before == null) {
			return false;
		}
		Instruction previous = program.getListing().getInstructionContaining(before);
		return previous != null && start.equals(previous.getFallThrough());
	}

	private static boolean isRepeatedByte(byte[] bytes) {
		for (int i = 1; i < bytes.length; i++) {
			if (bytes[i] != bytes[0]) {
				return false;
			}
		}
		return true;
	}

	/** Make a recovered prologue a function; its callers, if any, are indirect. */
	private static void promoteIfPrologue(Program program, Address start,
			TaskMonitor monitor) {
		if (program.getFunctionManager().getFunctionContaining(start) != null) {
			return;
		}
		try {
			byte[] bytes = new byte[3];
			if (program.getMemory().getBytes(start, bytes) == 3 &&
				startsWithPrologue(bytes)) {
				new CreateFunctionCmd(start).applyTo(program, monitor);
			}
		}
		catch (MemoryAccessException e) {
			// leave it as code without a function
		}
	}

	/** Create a function at {@code target} when it is call-referenced and unowned. */
	private static void promoteIfCalled(Program program, Address target,
			TaskMonitor monitor) {
		if (program.getListing().getInstructionAt(target) == null) {
			return;
		}
		if (program.getFunctionManager().getFunctionContaining(target) != null) {
			return;
		}
		for (Reference reference : program.getReferenceManager().getReferencesTo(target)) {
			if (reference.getReferenceType().isCall()) {
				new CreateFunctionCmd(target).applyTo(program, monitor);
				return;
			}
		}
	}
}
