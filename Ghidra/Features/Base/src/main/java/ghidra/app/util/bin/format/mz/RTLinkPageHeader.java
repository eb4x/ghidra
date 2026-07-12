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
package ghidra.app.util.bin.format.mz;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Parses a 16-byte RTLink/Plus overlay page header.
 *
 * <pre>
 * struct rtlink_page_header {
 *     uint16 total_paragraphs;     // total record size in 16-byte paragraphs
 *     uint16 overhead_paragraphs;  // header+relocs+padding; code starts after
 *     uint16 frame_size;           // overlay frame size in paragraphs (700 / 510)
 *     uint16 reloc_start_index;    // entry index the first relocation list starts at
 *     uint16 reloc_count;          // entries in the first relocation list
 *     uint16 reloc_count_2;        // entries in the second list, if any
 *     uint16 reloc_count_3;        // entries in the third list, if any
 *     uint16 reserved;             // always 0
 * };
 * </pre>
 * <p>
 * Every field here is a word. Reading {@code frame_size} or {@code reloc_count} as a
 * 32-bit value happens to work on VICEROY.EXE, where the word following each is always
 * zero — an overfit to the one binary this analyzer was first written against, and one
 * that has already cost us twice. NEBULAR.EXE (Rex Nebular) carries a second relocation
 * list on 15 of its 79 pages; read as a dword, page 1's {@code reloc_count} of 94 becomes
 * 131166, {@link #isValid()} rejects it, and the page walk stops before it starts — which
 * is why that binary once imported with no overlay blocks at all. ROE2MAIN.EXE failed
 * more quietly still: 27 of its 171 pages parsed and the rest were dropped.
 * <p>
 * The layout above is confirmed against the RTLink runtime's own relocation code (traced
 * in VICEROY at 210d:2318, which drives the fixup subroutine at 210d:2e59). That routine
 * reads {@code reloc_start_index} and {@code reloc_count} as separate words, and reaches
 * the later lists through {@code reloc_count_2} and {@code reloc_count_3}. Relocation
 * lists are addressed by <i>entry index</i>, not byte offset: the runtime rounds the index
 * up to a multiple of 4 between the first and second list, which is why the second list
 * lands on a paragraph boundary (4 entries × 4 bytes = 16). See {@link #getRelocOffset()}
 * and friends.
 * <p>
 * <b>Only the first list is applied.</b> The other two are parsed and exposed (see
 * {@link RTLinkOverlayPage#getSecondRelocations()}) but never written to memory, because
 * they do not take the image-base delta. The runtime applies the first list at initial
 * load; the second and third are driven only from the page-move path, and their addend is
 * a <i>difference</i> against a runtime structure rather than the load delta. Nothing is
 * added to those sites at image-base time, so leaving them alone is what a static image
 * should do. {@code reloc_count_3} is zero on all 281 pages across VICEROY, NEBULAR and
 * ROE2MAIN, so the third list has never actually been observed in the wild.
 */
public class RTLinkPageHeader implements StructConverter {

	public static final String NAME = "RTLink_Page_Header";
	public static final int HEADER_SIZE = 16;

	private int totalParagraphs;
	private int overheadParagraphs;
	private int frameSize;
	private int relocStartIndex;
	private int relocCount;
	private int secondRelocCount;
	private int thirdRelocCount;
	private int reserved;

	/**
	 * Constructs a new RTLink/Plus page header
	 *
	 * @param reader A {@link BinaryReader} positioned at the start of the header
	 * @throws IOException if there was an IO-related error
	 */
	public RTLinkPageHeader(BinaryReader reader) throws IOException {
		totalParagraphs = Short.toUnsignedInt(reader.readNextShort());
		overheadParagraphs = Short.toUnsignedInt(reader.readNextShort());
		frameSize = Short.toUnsignedInt(reader.readNextShort());
		relocStartIndex = Short.toUnsignedInt(reader.readNextShort());
		relocCount = Short.toUnsignedInt(reader.readNextShort());
		secondRelocCount = Short.toUnsignedInt(reader.readNextShort());
		thirdRelocCount = Short.toUnsignedInt(reader.readNextShort());
		reserved = Short.toUnsignedInt(reader.readNextShort());
	}

	public int getTotalParagraphs() {
		return totalParagraphs;
	}

	public int getOverheadParagraphs() {
		return overheadParagraphs;
	}

	public int getFrameSize() {
		return frameSize;
	}

	/** Entry index at which the first relocation list starts; 0 in every page seen. */
	public int getRelocStartIndex() {
		return relocStartIndex;
	}

	public int getRelocCount() {
		return relocCount;
	}

	/** Entries in the second relocation list; 0 when the page has none. */
	public int getSecondRelocCount() {
		return secondRelocCount;
	}

	/** Entries in the third relocation list; 0 in every page seen. */
	public int getThirdRelocCount() {
		return thirdRelocCount;
	}

	/** Byte offset, from the start of the header, of the first relocation list. */
	public int getRelocOffset() {
		return HEADER_SIZE + relocStartIndex * 4;
	}

	/**
	 * Byte offset, from the start of the header, of the second relocation list. The
	 * runtime rounds the <i>entry index</i> past the first list up to a multiple of 4,
	 * which puts the second list on a paragraph boundary.
	 */
	public int getSecondRelocOffset() {
		return HEADER_SIZE + roundUpToEntryGroup(relocStartIndex + relocCount) * 4;
	}

	/**
	 * Byte offset, from the start of the header, of the third relocation list. Unlike the
	 * second, it follows the previous list immediately — the runtime advances the entry
	 * index by the second list's count without rounding.
	 */
	public int getThirdRelocOffset() {
		return getSecondRelocOffset() + secondRelocCount * 4;
	}

	private static int roundUpToEntryGroup(int entryIndex) {
		return (entryIndex + 3) & ~3;
	}

	public int getReserved() {
		return reserved;
	}

	public int getTotalSizeBytes() {
		return totalParagraphs * 16;
	}

	public int getOverheadSizeBytes() {
		return overheadParagraphs * 16;
	}

	public int getCodeSizeBytes() {
		return getTotalSizeBytes() - getOverheadSizeBytes();
	}

	/**
	 * Checks whether this looks like a valid RTLink/Plus page header
	 *
	 * @return true if the header fields are structurally consistent
	 */
	public boolean isValid() {
		if (totalParagraphs <= 0) {
			return false;
		}
		if (overheadParagraphs <= 0 || overheadParagraphs > totalParagraphs) {
			return false;
		}
		if (frameSize <= 0) {
			return false;
		}
		if (reserved != 0) {
			return false;
		}
		// All three relocation lists live in the overhead area, ahead of the code. The
		// lists run in order, so the end of the last one bounds them all.
		long overheadBytes = (long) overheadParagraphs * 16;
		long lastListEnd = (long) getThirdRelocOffset() + (long) thirdRelocCount * 4;
		return lastListEnd <= overheadBytes;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(WORD, "total_paragraphs", "Total record size in 16-byte paragraphs");
		struct.add(WORD, "overhead_paragraphs", "Header+relocs+padding paragraphs");
		struct.add(WORD, "frame_size", "Overlay frame size in paragraphs");
		struct.add(WORD, "reloc_start_index", "Entry index the first relocation list starts at");
		struct.add(WORD, "reloc_count", "Entries in the first relocation list");
		struct.add(WORD, "reloc_count_2", "Entries in the second relocation list (0 if none)");
		struct.add(WORD, "reloc_count_3", "Entries in the third relocation list (0 if none)");
		struct.add(WORD, "reserved", "Reserved (always 0)");
		struct.setCategoryPath(new CategoryPath("/DOS/RTLink"));
		return struct;
	}

	@Override
	public String toString() {
		return String.format(
			"RTLinkPageHeader[total=%d overhead=%d frame=0x%X relocs=%d/%d/%d]",
			totalParagraphs, overheadParagraphs, frameSize, relocCount, secondRelocCount,
			thirdRelocCount);
	}
}
