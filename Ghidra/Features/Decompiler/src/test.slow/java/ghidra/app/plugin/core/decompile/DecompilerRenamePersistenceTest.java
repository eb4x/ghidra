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

import ghidra.app.decompiler.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitor;

/**
 * Verify that renaming a decompiler variable survives a re-decompile when the variable
 * is merged from multiple identical defining ops (e.g. a register repeatedly re-loaded
 * from the same global) and so must be recorded with dynamic (hash) storage.
 * 
 * The program uses a 16-bit segmented address space deliberately: the Java-side
 * DynamicHash historically hashed a different number of op-address bytes than the
 * decompiler process for segmented spaces (21-bit space vs 4-byte space), so every
 * committed dynamic symbol failed to re-attach on the next decompile and the rename
 * silently reverted.
 */
public class DecompilerRenamePersistenceTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramBuilder builder;
	private Program prog;
	private DecompInterface decompiler;
	private Function func;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("segmented", ProgramBuilder._X86_16_REAL_MODE);
		builder.createMemory("code", "1000:0000", 0x20);
		// f() re-loads the near pointer at DS:0x8542 into BX three times and stores
		// through it after each load; the identical BX definitions get merged into
		// single display variables with no fixed storage:
		//   mov bx,[0x8542]; mov [bx],ax;   mov [bx+2],cx
		//   mov bx,[0x8542]; mov [bx+4],dx; mov [bx+6],si
		//   mov bx,[0x8542]; mov [bx+8],di; mov word [bx+0xa],5
		//   ret
		builder.setBytes("1000:0000",
			"8b 1e 42 85 89 07 89 4f 02 8b 1e 42 85 89 57 04 89 77 06 8b 1e 42 85 89 7f 08 c7 47 0a 05 00 c3");
		builder.disassemble("1000:0000", 0x20);
		builder.createFunction("1000:0000");
		prog = builder.getProgram();
		func = prog.getListing()
				.getFunctionAt(prog.getAddressFactory().getAddress("1000:0000"));
		assertNotNull(func);

		decompiler = new DecompInterface();
		decompiler.openProgram(prog);
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

	private HighFunction decompile() {
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

	@Test
	public void testRenameOfMergedMultiDefVariablePersists() throws Exception {
		HighFunction highFunction = decompile();
		HighSymbol target = findMultiInstanceLocal(highFunction);
		assertNotNull("expected a local variable merged from multiple definitions", target);
		int instanceCount = target.getHighVariable().getInstances().length;
		assertTrue(instanceCount > 1);
		assertTrue("expected the merged local to require dynamic storage",
			target.getHighVariable().requiresDynamicStorage());

		int txId = prog.startTransaction("rename local");
		try {
			HighFunctionDBUtil.updateDBVariable(target, "col", null, SourceType.USER_DEFINED);
		}
		finally {
			prog.endTransaction(txId, true);
		}

		decompiler.flushCache();
		HighFunction highFunction2 = decompile();
		HighSymbol renamed = findSymbol(highFunction2, "col");
		assertNotNull("rename of merged multi-def variable did not survive re-decompile",
			renamed);
		HighVariable high = renamed.getHighVariable();
		assertNotNull("renamed symbol is no longer attached to a variable", high);
		assertEquals("name did not reapply to every merged instance", instanceCount,
			high.getInstances().length);
	}
}
