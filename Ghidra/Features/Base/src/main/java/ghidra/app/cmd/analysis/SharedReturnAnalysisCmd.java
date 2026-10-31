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
package ghidra.app.cmd.analysis;

import java.util.*;

import ghidra.app.cmd.disassemble.SetFlowOverrideCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Identifies functions to which Jump references exist and converts 
 * the associated branching instruction flow to a CALL-RETURN
 */
public class SharedReturnAnalysisCmd extends BackgroundCommand<Program> {

	// a longer walk from a jump target is taken to be a whole function, entered only at its start
	private static final int MAX_TARGET_INSTRUCTIONS = 10000;

	private AddressSetView set;
	private final Map<Address, Boolean> rejoinsBranching = new HashMap<>();
	private boolean assumeContiguousFunctions = false;
	private boolean considerConditionalBranches = false;

	/**
	 * Constructor
	 * @param set set of addresses over which destination functions will be
	 * examined for Jump reference to those functions.
	 * @param assumeContiguousFunctions if true it will be assumed that any unconditional
	 * jump over another function will trigger a call-return override and the creation of
	 * @param considerConditionalBranches if true conditional jumps can also be considered for jumping
	 * to another function as a shared return.
	 * a function at the destination.
	 */
	public SharedReturnAnalysisCmd(AddressSetView set, boolean assumeContiguousFunctions,
			boolean considerConditionalBranches) {
		super("Shared Return Analysis", false, true, false);
		this.set = set;
		this.assumeContiguousFunctions = assumeContiguousFunctions;
		this.considerConditionalBranches = considerConditionalBranches;
	}

	@Override
	public boolean applyTo(Program program, TaskMonitor monitor) {

		try {

			// Check destination functions within set
			SymbolTable symbolTable = program.getSymbolTable();
			SymbolIterator fnSymbols = symbolTable.getSymbols(set, SymbolType.FUNCTION, true);
			while (fnSymbols.hasNext()) {
				monitor.checkCancelled();
				Symbol s = fnSymbols.next();
				Address entry = s.getAddress();

				processFunctionJumpReferences(program, entry, monitor);
			}

			AddressSetPropertyMap coldMap =
				program.getAddressSetPropertyMap(Program.COLD_ENTRY_MAP_NAME);
			Set<Address> ownConditionalJumpTargets = new HashSet<>();
			Set<Address> convertibleJumpTargets = new HashSet<>();
			if (assumeContiguousFunctions) {
				// assume if checkAllJumpReferences then set is much more than new function starts

				AddressSet jumpScanSet = new AddressSet();

				fnSymbols = symbolTable.getSymbols(set, SymbolType.FUNCTION, true);
				while (fnSymbols.hasNext()) {
					monitor.checkCancelled();
					Symbol s = fnSymbols.next();
					checkAboveFunction(s, jumpScanSet);
					checkBelowFunction(s, jumpScanSet);
				}

				// Used for caching forward/backward function lookups as we
				// move forward through jump references
				Address functionAfterSrc = null;
				Address functionBeforeSrc = null;

				ReferenceManager refMgr = program.getReferenceManager();
				AddressIterator refSrcIter = refMgr.getReferenceSourceIterator(jumpScanSet, true);
				while (refSrcIter.hasNext()) {
					monitor.checkCancelled();
					Address srcAddr = refSrcIter.next();
					RefType flow = null;
					Address destAddr = null;
					for (Reference ref : refMgr.getReferencesFrom(srcAddr)) {
						RefType refType = ref.getReferenceType();
						if (refType.isFlow()) {
							if (flow != null) {
								// ignore points with multiple flows
								break;
							}
							flow = refType;
							destAddr = ref.getToAddress();
						}
					}
					if (destAddr == null || flow == null || !flow.isJump() ||
						!flow.isUnConditional()) {
						continue;
					}
					if (srcAddr.getAddressSpace() != destAddr.getAddressSpace()) {
						continue; // can't handle flows between different spaces/overlays
					}

					// skip .cold targets
					if (coldMap != null) {
						if (coldMap.contains(destAddr)) {
							continue;
						}
					}

					if (!considerConditionalBranches) {
						if (ownConditionalJumpTargets.contains(destAddr)) {
							continue;
						}

						if (!convertibleJumpTargets.contains(destAddr)) {
							//haven't checked the flow refs to destAddr yet
							if (isConditionalTargetOfOneFunction(program, destAddr)) {
								ownConditionalJumpTargets.add(destAddr);
								continue;
							}
							convertibleJumpTargets.add(destAddr);
						}
					}

					// Reset cached functions if we transition to a different space/overlay
					if (functionAfterSrc != null &&
						functionAfterSrc.getAddressSpace() != srcAddr.getAddressSpace()) {
						functionAfterSrc = null;
					}
					if (functionBeforeSrc != null &&
						functionBeforeSrc.getAddressSpace() != srcAddr.getAddressSpace()) {
						functionBeforeSrc = null;
					}

					if (srcAddr.compareTo(destAddr) < 0) {
						// forward jump
						if (functionAfterSrc == Address.NO_ADDRESS) {
							continue; // no function after srcAddr
						}
						if (functionAfterSrc == null || functionAfterSrc.compareTo(srcAddr) <= 0) {
							Function nextFunction = getFunctionAfter(program, srcAddr);
							if (nextFunction != null) {
								functionAfterSrc = nextFunction.getEntryPoint();
							}
							else {
								functionAfterSrc = Address.NO_ADDRESS;
								continue; // no function after srcAddr
							}
						}
						if (destAddr.compareTo(functionAfterSrc) >= 0) {
							createFunction(program, destAddr, monitor);
						}
					}
					else {

						// prime lastFunctionAfterSrc if not previously set
						if (functionAfterSrc == null) {
							Function nextFunction = getFunctionAfter(program, srcAddr);
							if (nextFunction != null) {
								functionAfterSrc = nextFunction.getEntryPoint();
							}
							else {
								functionAfterSrc = Address.NO_ADDRESS;
							}
						}

						// backward jump
						if (functionBeforeSrc == Address.NO_ADDRESS) {
							if (functionAfterSrc == Address.NO_ADDRESS) {
								continue; // no functions exist - rare
							}
							if (srcAddr.compareTo(functionAfterSrc) < 0) {
								continue; // we have not passed next function - no function before
							}
							functionBeforeSrc = null; // must re-query - lastFunctionAfterSrc is also invalid
							Function nextFunction = getFunctionAfter(program, srcAddr);
							if (nextFunction != null) {
								functionAfterSrc = nextFunction.getEntryPoint();
							}
							else {
								functionAfterSrc = Address.NO_ADDRESS;
							}
						}

						// if we have not passed lastFunctionAfter then no change to lastFunctionBefore
						if (functionBeforeSrc != null && (functionAfterSrc == Address.NO_ADDRESS ||
							srcAddr.compareTo(functionAfterSrc) < 0)) {
							// we have not passed lastFunctionAfterSrc - no change to lastFunctionBeforeSrc
						}
						else {
							Function prevFunction = getFunctionBefore(program, srcAddr);
							if (prevFunction != null) {
								functionBeforeSrc = prevFunction.getEntryPoint();
							}
							else {
								functionBeforeSrc = Address.NO_ADDRESS;
								continue; // no function before srcAddr
							}
						}

						if (destAddr.compareTo(functionBeforeSrc) < 0) {
							createFunction(program, destAddr, monitor);
						}

					}
				}
			}

		}
		catch (CancelledException e) {
			// ignore
		}

		return true;
	}

	private Function getFunctionBefore(Program program, Address addr) {
		Listing listing = program.getListing();
		FunctionIterator prevFunctionIter =
			listing.getFunctions(getRangeBefore(program, addr), false);
		if (prevFunctionIter.hasNext()) {
			return prevFunctionIter.next();
		}
		return null;
	}

	private AddressSetView getRangeBefore(Program program, Address addr) {
		AddressSpace space = addr.getAddressSpace();
		Address min = space.getMinAddress();
		if (addr.equals(min)) {
			return new AddressSet();
		}
		try {
			return new AddressSet(min, addr.subtractNoWrap(1));
		}
		catch (AddressOverflowException e) {
			throw new AssertException(e);
		}
	}

	/**
	 * A conditional branch target is part of the function that branches to it, such as its cold
	 * part, unless flows reach it from more than one function: then it is a tail they share.
	 * A flow from outside any function counts as coming from another function.
	 */
	private boolean isConditionalTargetOfOneFunction(Program program, Address destAddr) {
		FunctionManager functionMgr = program.getFunctionManager();
		boolean conditional = false;
		Function source = null;
		for (Reference ref : program.getReferenceManager().getReferencesTo(destAddr)) {
			RefType refType = ref.getReferenceType();
			if (!refType.isFlow()) {
				continue;
			}
			Function f = functionMgr.getFunctionContaining(ref.getFromAddress());
			if (f == null || (source != null && !f.equals(source))) {
				return false;
			}
			source = f;
			conditional |= refType.isConditional();
		}
		return conditional;
	}

	private Function getFunctionAfter(Program program, Address addr) {
		Listing listing = program.getListing();
		FunctionIterator nextFunctionIter =
			listing.getFunctions(getRangeAfter(program, addr), true);
		if (nextFunctionIter.hasNext()) {
			return nextFunctionIter.next();
		}
		return null;
	}

	private AddressSetView getRangeAfter(Program program, Address addr) {
		AddressSpace space = addr.getAddressSpace();
		Address max = space.getMaxAddress();
		if (addr.equals(max)) {
			return new AddressSet();
		}
		try {
			return new AddressSet(addr.addNoWrap(1), max);
		}
		catch (AddressOverflowException e) {
			throw new AssertException(e);
		}
	}

	private void createFunction(Program program, Address entry, TaskMonitor monitor)
			throws CancelledException {
		if (program.getFunctionManager().getFunctionAt(entry) != null) {
			processFunctionJumpReferences(program, entry, monitor);
		}
		else {
			// check if there could be any fallthru flow to the potential entry point
			if (checkIfCouldHaveFallThruTo(program, entry)) {
				// if there could be, even later in analysis, don't create the function
				return;
			}
			if (rejoinsBranching.computeIfAbsent(entry, a -> rejoinsBranchingFunction(program, a))) {
				// a block that jumps back into the function that branched to it belongs to it
				return;
			}
			AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
			analysisMgr.createFunction(entry, false);
		}
	}

	/**
	 * Whether the code reached from {@code start} jumps back into a function that branches to
	 * {@code start}: a flow from that function's body enters the code at a later instruction.
	 * The code reached is what falls through or jumps from {@code start}, without following
	 * calls, up to the entry of another function or a call target, where it leaves by a tail
	 * call. Entries from other code don't count, so tails that run into each other, as a
	 * runtime library's exit routines do, stay tails; nor does a return instruction that other
	 * code also reaches, since sharing it shares no other code.
	 */
	private boolean rejoinsBranchingFunction(Program program, Address start) {
		Set<Function> sources = getBranchingFunctions(program, start);
		if (sources.isEmpty()) {
			return false;
		}
		AddressSet code = new AddressSet();
		Listing listing = program.getListing();
		Deque<Address> pending = new ArrayDeque<>(List.of(start));
		int count = 0;
		while (!pending.isEmpty()) {
			Address addr = pending.pop();
			if (code.contains(addr) || (!addr.equals(start) && isEntry(program, addr))) {
				continue;
			}
			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				continue;
			}
			if (++count > MAX_TARGET_INSTRUCTIONS) {
				return false;
			}
			code.add(instr.getMinAddress(), instr.getMaxAddress());
			if (instr.getFallThrough() != null) {
				pending.push(instr.getFallThrough());
			}
			if (instr.getFlowType().isJump()) {
				pending.addAll(List.of(instr.getFlows()));
			}
		}
		for (Instruction instr : listing.getInstructions(code, true)) {
			if (instr.getMinAddress().equals(start) || instr.getFlowType().isTerminal()) {
				continue;
			}
			if (isEnteredFrom(sources, instr, code)) {
				return true;
			}
		}
		return false;
	}

	private Set<Function> getBranchingFunctions(Program program, Address start) {
		FunctionManager functionMgr = program.getFunctionManager();
		Set<Function> sources = new HashSet<>();
		for (Reference ref : program.getReferenceManager().getReferencesTo(start)) {
			if (!ref.getReferenceType().isJump()) {
				continue;
			}
			Function f = functionMgr.getFunctionContaining(ref.getFromAddress());
			if (f != null) {
				sources.add(f);
			}
		}
		return sources;
	}

	private boolean isEntry(Program program, Address addr) {
		if (program.getFunctionManager().getFunctionAt(addr) != null) {
			return true;
		}
		for (Reference ref : program.getReferenceManager().getReferencesTo(addr)) {
			if (ref.getReferenceType().isCall()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether a jump or fall-through from outside {@code code}, in the body of one of
	 * {@code functions}, enters {@code instr}.
	 */
	private boolean isEnteredFrom(Set<Function> functions, Instruction instr, AddressSetView code) {
		for (Reference ref : instr.getReferenceIteratorTo()) {
			Address from = ref.getFromAddress();
			if (ref.getReferenceType().isJump() && !code.contains(from) && isIn(functions, from)) {
				return true;
			}
		}
		Address fallFrom = instr.getFallFrom();
		if (fallFrom == null || code.contains(fallFrom) || !isIn(functions, fallFrom)) {
			return false;
		}
		Instruction fallInstr = instr.getProgram().getListing().getInstructionContaining(fallFrom);
		return fallInstr != null && instr.getMinAddress().equals(fallInstr.getFallThrough());
	}

	private static boolean isIn(Set<Function> functions, Address addr) {
		return functions.stream().anyMatch(f -> f.getBody().contains(addr));
	}

	private boolean checkIfCouldHaveFallThruTo(Program program, Address location) {
		Instruction instr = program.getListing().getInstructionAt(location);
		if (instr == null) {
			return true;
		}
		Address fallFrom = instr.getFallFrom();
		if (fallFrom != null) {
			Instruction fallInstr = program.getListing().getInstructionContaining(fallFrom);
			if (fallInstr != null && location.equals(fallInstr.getFallThrough())) {
				// if there is no instruction yet, function may not be created yet
				return true;
			}
		}

		if (instr.getFlowType() == RefType.TERMINATOR) {
			// a single instruction that is terminal consider
			// as having a possible future fallthru to
			return true;
		}
		return false;
	}

	private void checkAboveFunction(Symbol functionSymbol, AddressSet jumpScanSet) {

		Program program = functionSymbol.getProgram();
		Address fnAddr = functionSymbol.getAddress();
		Function prevFunction = getFunctionBefore(program, fnAddr);
		if (prevFunction != null) {
			// Must scan everything from previous function down to functionSymbol
			jumpScanSet.addRange(prevFunction.getEntryPoint(), fnAddr);
			return;
		}

		// Must scan everything above function
		jumpScanSet.addRange(fnAddr.getAddressSpace().getMinAddress(), fnAddr);
	}

	private void checkBelowFunction(Symbol functionSymbol, AddressSet jumpScanSet) {

		Function function = (Function) functionSymbol.getObject();
		AddressSetView body = function.getBody();
		if (body.getNumAddressRanges() > 1) {
			jumpScanSet.add(body);
		}

		Program program = functionSymbol.getProgram();
		Address fnAddr = functionSymbol.getAddress();
		Function nextFunction = getFunctionAfter(program, fnAddr);
		if (nextFunction != null) {
			// Must scan everything from this function down to next functionSymbol
			// If function body has single range - omit from scan
			jumpScanSet.addRange(fnAddr, nextFunction.getEntryPoint().subtract(1));
			if (body.getNumAddressRanges() <= 1) {
				jumpScanSet.delete(body);
			}
			return;
		}

		// Must scan everything below function
		// If function body has single range - omit from scan
		jumpScanSet.addRange(fnAddr, fnAddr.getAddressSpace().getMaxAddress());
		if (body.getNumAddressRanges() <= 1) {
			jumpScanSet.delete(body);
		}

	}

//	private void checkAllJumpReferences(Program program, TaskMonitor monitor)
//			throws CancelledException {
//
//		SymbolTable symbolTable = program.getSymbolTable();
//
//		InstructionIterator instructionIter = program.getListing().getInstructions(set, true);
//		while (instructionIter.hasNext()) {
//			monitor.checkCancelled();
//			Instruction instr = instructionIter.next();
//			FlowType ft = instr.getFlowType();
//			if (!ft.isJump()) {
//				continue;
//			}
//			Reference ref = getSingleFlowReferenceFrom(instr);
//			if (ref == null) {
//				continue;
//			}
//			// if there is a function at this address, this is a thunk
//			//    Handle differently
//			if (program.getFunctionManager().getFunctionAt(instr.getMinAddress()) != null) {
//				continue;
//			}
//			Symbol s = symbolTable.getPrimarySymbol(ref.getToAddress());
//			if (s != null && s.getSymbolType() == SymbolType.FUNCTION) {
//				if (instr.getFlowOverride() != FlowOverride.NONE) {
//					continue;
//				}
//				SetFlowOverrideCmd cmd =
//					new SetFlowOverrideCmd(instr.getMinAddress(), FlowOverride.CALL_RETURN);
//				cmd.applyTo(program);
//			}
//		}
//	}

	private void processFunctionJumpReferences(Program program, Address entry, TaskMonitor monitor)
			throws CancelledException {

		// since reference fixup will occur when flow override is done,
		// avoid concurrent modification during reference iterator use
		// by building list of jump references
		List<Reference> fnRefList = getJumpRefsToFunction(program, entry, monitor);
		if (fnRefList == null) {
			return;
		}

		FunctionManager funcMgr = program.getFunctionManager();

		for (Reference ref : fnRefList) {
			monitor.checkCancelled();
			Instruction instr = program.getListing().getInstructionAt(ref.getFromAddress());
			if (instr == null) {
				continue;
			}
			Reference checkRef = getSingleFlowReferenceFrom(instr);
			if (checkRef == null) {
				continue;
			}

			// if there is a function at this address, this is a thunk
			//    Handle differently
			Address refInstrAddr = instr.getMinAddress();

			if (funcMgr.getFunctionAt(refInstrAddr) != null) {
				continue;
			}

			// if this instruction is contained in the body of the function
			// then it is just an internal jump reference to the top of the
			// function
			Function functionContaining = funcMgr.getFunctionContaining(refInstrAddr);
			if (functionContaining != null && functionContaining.getEntryPoint().equals(entry)) {
				continue;
			}

			if (checkRef.getToAddress().equals(ref.getToAddress())) {
				if (instr.getFlowOverride() != FlowOverride.NONE) {
					continue;
				}
				SetFlowOverrideCmd cmd =
					new SetFlowOverrideCmd(refInstrAddr, FlowOverride.CALL_RETURN);
				cmd.applyTo(program);
			}
		}
	}

	private List<Reference> getJumpRefsToFunction(Program program, Address entry,
			TaskMonitor monitor) throws CancelledException {
		List<Reference> fnRefList = null;
		ReferenceIterator referencesTo = program.getReferenceManager().getReferencesTo(entry);
		while (referencesTo.hasNext()) {
			monitor.checkCancelled();
			Reference ref = referencesTo.next();
			if (!ref.getReferenceType().isJump()) {
				continue;
			}
			if (ref.getReferenceType().isConditional() && !considerConditionalBranches) {
				// any conditional jumps don't count, only pure jumps are considered.
				//   
				continue;
			}
			if (fnRefList == null) {
				fnRefList = new ArrayList<Reference>();
			}
			fnRefList.add(ref);
		}
		return fnRefList;
	}

	private Reference getSingleFlowReferenceFrom(Instruction instr) {
		Reference ref = null;
		int flowCnt = 0;
		for (Reference refFrom : instr.getReferencesFrom()) {
			if (!refFrom.isMemoryReference() || !refFrom.getReferenceType().isFlow()) {
				continue;
			}
			if (++flowCnt > 1) {
				return null; // only change if single flow
			}
			ref = refFrom;
		}
		return ref;
	}
}
