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

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.cmd.function.DecompilerSwitchAnalysisCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.DecompilerSwitchAnalyzer;
import ghidra.app.plugin.core.analysis.SwitchAnalysisDecompileConfigurer;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * DecompilerSwitchAnalysisCmd replaces the references on a switch's jump with the
 * decompiler's jump table, but must keep the references a user or an importer placed there.
 */
public class DecompilerSwitchAnalysisUserRefTest extends AbstractGenericTest {

	private static final String SWITCH_JUMP = "0x001011a7";

	// the ten case targets the decompiler recovers from the table at 0x102054
	private static final String[] CASES = { "0x001011aa", "0x001011be", "0x001011d2",
		"0x001011e6", "0x001011f7", "0x00101208", "0x00101219", "0x0010122a", "0x0010123b",
		"0x0010124c" };

	// instructions in the default case's block, not targets of the table
	private static final String USER_TARGET = "0x0010126c";
	private static final String ANALYSIS_TARGET = "0x00101264";

	private static final String TABLE = "0x00102054";

	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		// same switch as DecompilerSwitchAnalyzerTest: a gcc x86-64 switch on 0..9 with a default
		builder = new ProgramBuilder("SwitchUserRefTest", "x86:LE:64:default", "gcc", null);
		builder.setBytes("0x101169",
			"f30f1efa554889" +
			"e54883ec10897dfc488975f0837dfc09" +
			"0f87d70000008b45fc488d1485000000" +
			"00488d05bc0e00008b04024898488d15" +
			"b00e00004801d03effe0488d05530e00" +
			"004889c7e8a7feffffe9ae000000488d" +
			"05460e00004889c7e893feffffe99a00" +
			"0000488d05390e00004889c7e87ffeff" +
			"ffe986000000488d052c0e00004889c7" +
			"e86bfeffffeb75488d05220e00004889" +
			"c7e85afeffffeb64488d05180e000048" +
			"89c7e849feffffeb53488d050e0e0000" +
			"4889c7e838feffffeb42488d05040e00" +
			"004889c7e827feffffeb31488d05fa0d" +
			"00004889c7e816feffffeb20488d05f0" +
			"0d00004889c7e805feffffeb0f488d05" +
			"e60d00004889c7e8f4fdffffbf000000" +
			"00e8fafdffff");
		builder.setBytes("0x102054",
			"56f1ffff6af1ffff7ef1ffff" +
			"92f1ffffa3f1ffffb4f1ffffc5f1ffff" +
			"d6f1ffffe7f1fffff8f1ffff011b033b");
		builder.disassemble("0x101169", 64);
		builder.createFunction("0x101169");

		program = builder.getProgram();
		program.startTransaction("Test");
		assertNotNull("Bad instruction disassembly",
			program.getListing().getInstructionAt(addr(SWITCH_JUMP)));
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	/**
	 * The analyzer only visits a jump without a computed reference, so a user's data
	 * reference to the table is what it meets in auto-analysis.
	 */
	@Test
	public void testAnalyzerKeepsUserAndImportedOperandReferences() throws Exception {
		Address jump = addr(SWITCH_JUMP);
		ReferenceManager refMgr = program.getReferenceManager();
		refMgr.addMemoryReference(jump, addr(TABLE), RefType.DATA, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(jump, addr(USER_TARGET), RefType.DATA, SourceType.IMPORTED,
			Reference.MNEMONIC);

		new DecompilerSwitchAnalyzer().added(program, new AddressSet(jump, jump.add(0x200)),
			TaskMonitor.DUMMY, null);

		assertCaseReferences(jump);
		assertReference(jump, addr(TABLE), 0, SourceType.USER_DEFINED);
		assertReference(jump, addr(USER_TARGET), Reference.MNEMONIC, SourceType.IMPORTED);
	}

	/**
	 * A user-defined computed jump that differs from the decompiler's table survives switch
	 * recovery; an earlier analysis guess is replaced.
	 */
	@Test
	public void testSwitchCmdKeepsUserDefinedFlowReferences() throws Exception {
		Address jump = addr(SWITCH_JUMP);
		ReferenceManager refMgr = program.getReferenceManager();
		refMgr.addMemoryReference(jump, addr(USER_TARGET), RefType.COMPUTED_JUMP,
			SourceType.USER_DEFINED, Reference.MNEMONIC);
		refMgr.addMemoryReference(jump, addr(CASES[0]), RefType.COMPUTED_JUMP,
			SourceType.USER_DEFINED, Reference.MNEMONIC);
		refMgr.addMemoryReference(jump, addr(ANALYSIS_TARGET), RefType.COMPUTED_JUMP,
			SourceType.ANALYSIS, Reference.MNEMONIC);

		runSwitchCmd(program.getFunctionManager().getFunctionAt(addr("0x101169")));

		assertCaseReferences(jump);
		assertReference(jump, addr(USER_TARGET), Reference.MNEMONIC, SourceType.USER_DEFINED);
		// the decompiler's reference to the same target doesn't downgrade the user's
		assertReference(jump, addr(CASES[0]), Reference.MNEMONIC, SourceType.USER_DEFINED);
		assertNull("Analysis guess replaced",
			refMgr.getReference(jump, addr(ANALYSIS_TARGET), Reference.MNEMONIC));
	}

	private void runSwitchCmd(Function function) {
		DecompInterface decompiler = new DecompInterface();
		try {
			new SwitchAnalysisDecompileConfigurer(program).configure(decompiler);
			assertTrue("Decompiler open", decompiler.openProgram(program));
			DecompileResults results = decompiler.decompileFunction(function, 60, TaskMonitor.DUMMY);
			assertTrue("Decompiled", results.decompileCompleted());
			new DecompilerSwitchAnalysisCmd(results).applyTo(program, TaskMonitor.DUMMY);
		}
		finally {
			decompiler.dispose();
		}
	}

	private void assertCaseReferences(Address jump) {
		ReferenceManager refMgr = program.getReferenceManager();
		for (String target : CASES) {
			assertNotNull("Missing case reference to " + target,
				refMgr.getReference(jump, addr(target), Reference.MNEMONIC));
		}
	}

	private void assertReference(Address from, Address to, int opIndex, SourceType source) {
		Reference ref = program.getReferenceManager().getReference(from, to, opIndex);
		assertNotNull("Missing reference to " + to + " on operand " + opIndex, ref);
		assertEquals("Source of reference to " + to, source, ref.getSource());
	}

	private Address addr(String address) {
		return builder.addr(address);
	}
}
