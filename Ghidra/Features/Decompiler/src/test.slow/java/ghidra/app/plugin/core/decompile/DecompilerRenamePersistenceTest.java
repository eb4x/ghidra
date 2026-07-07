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
package ghidra.app.plugin.core.decompile;

import static org.junit.Assert.*;

import java.util.Iterator;

import org.junit.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.NumericUtilities;
import ghidra.util.task.TaskMonitor;

/**
 * Verify that renaming a decompiler variable survives a re-decompile when the variable
 * is merged from multiple identical defining ops (e.g. a register repeatedly re-loaded
 * from the same global) and so must be recorded with dynamic (hash) storage.
 *
 * The program uses a 16-bit segmented address space deliberately: the Java-side
 * DynamicHash must hash as many op-address bytes as the decompiler process, which sees
 * the 21-bit real-mode space, and every overlay of it, as a 4-byte space.  If the counts
 * differ, every committed dynamic symbol fails to re-attach on the next decompile and
 * the rename silently reverts.
 */
public class DecompilerRenamePersistenceTest extends AbstractGhidraHeadedIntegrationTest {

	// f() re-loads the near pointer at DS:0x8542 into BX three times and stores
	// through it after each load; the identical BX definitions get merged into
	// single display variables with no fixed storage:
	//   mov bx,[0x8542]; mov [bx],ax;   mov [bx+2],cx
	//   mov bx,[0x8542]; mov [bx+4],dx; mov [bx+6],si
	//   mov bx,[0x8542]; mov [bx+8],di; mov word [bx+0xa],5
	//   ret
	private static final String CODE =
		"8b 1e 42 85 89 07 89 4f 02 8b 1e 42 85 89 57 04 89 77 06 8b 1e 42 85 89 7f 08 c7 47 0a 05 00 c3";
	private static final int CODE_SIZE = 0x20;

	private ProgramBuilder builder;
	private Program prog;
	private DecompInterface decompiler;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("segmented", ProgramBuilder._X86_16_REAL_MODE);
		prog = builder.getProgram();
	}

	@After
	public void tearDown() {
		if (decompiler != null) {
			decompiler.dispose();
		}
		if (builder != null) {
			builder.dispose();
		}
	}

	private void openDecompiler() {
		decompiler = new DecompInterface();
		decompiler.openProgram(prog);
	}

	private Function createFunction(Address entry) throws Exception {
		byte[] bytes = NumericUtilities.convertStringToBytes(CODE);
		AddressSet body = new AddressSet(entry, entry.add(CODE_SIZE - 1));
		prog.withTransaction("create function", () -> {
			prog.getMemory().setBytes(entry, bytes);
			new DisassembleCommand(body, body, true).applyTo(prog);
			new CreateFunctionCmd(entry).applyTo(prog);
		});
		Function func = prog.getListing().getFunctionAt(entry);
		assertNotNull(func);
		return func;
	}

	private HighFunction decompile(Function func) {
		DecompileResults results = decompiler.decompileFunction(func,
			DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
		HighFunction highFunction = results.getHighFunction();
		assertNotNull(results.getErrorMessage(), highFunction);
		return highFunction;
	}

	private static HighSymbol findMultiInstanceLocal(HighFunction highFunction) {
		HighSymbol best = null;
		int bestCount = 1;
		Iterator<HighSymbol> iter = highFunction.getLocalSymbolMap().getSymbols();
		while (iter.hasNext()) {
			HighSymbol sym = iter.next();
			if (sym.isParameter()) {
				continue;
			}
			HighVariable high = sym.getHighVariable();
			if (high == null) {
				continue;
			}
			int count = high.getInstances().length;
			if (count > bestCount) {
				bestCount = count;
				best = sym;
			}
		}
		return best;
	}

	private static HighSymbol findSymbol(HighFunction highFunction, String name) {
		Iterator<HighSymbol> iter = highFunction.getLocalSymbolMap().getSymbols();
		while (iter.hasNext()) {
			HighSymbol sym = iter.next();
			if (name.equals(sym.getName())) {
				return sym;
			}
		}
		return null;
	}

	private void assertRenameOfMergedLocalPersists(Function func) throws Exception {
		HighFunction highFunction = decompile(func);
		HighSymbol target = findMultiInstanceLocal(highFunction);
		assertNotNull("expected a local variable merged from multiple definitions", target);
		int instanceCount = target.getHighVariable().getInstances().length;
		assertTrue(instanceCount > 1);
		assertTrue("expected the merged local to require dynamic storage",
			target.getHighVariable().requiresDynamicStorage());

		prog.withTransaction("rename local", () -> HighFunctionDBUtil.updateDBVariable(target,
			"col", null, SourceType.USER_DEFINED));

		decompiler.flushCache();
		HighFunction highFunction2 = decompile(func);
		HighSymbol renamed = findSymbol(highFunction2, "col");
		assertNotNull("rename of merged multi-def variable did not survive re-decompile",
			renamed);
		HighVariable high = renamed.getHighVariable();
		assertNotNull("renamed symbol is no longer attached to a variable", high);
		assertEquals("name did not reapply to every merged instance", instanceCount,
			high.getInstances().length);
	}

	@Test
	public void testRenameOfMergedMultiDefVariablePersists() throws Exception {
		MemoryBlock block = builder.createMemory("code", "1000:0000", CODE_SIZE);
		Function func = createFunction(block.getStart());
		openDecompiler();
		assertRenameOfMergedLocalPersists(func);
	}

	@Test
	public void testRenameOfMergedMultiDefVariableInOverlayPersists() throws Exception {
		MemoryBlock block = builder.createOverlayMemory("ov", "2000:0000", CODE_SIZE);
		Function func = createFunction(block.getStart());
		assertTrue("expected the function in an overlay space",
			func.getEntryPoint().getAddressSpace().isOverlaySpace());
		openDecompiler();
		assertRenameOfMergedLocalPersists(func);
	}
}
