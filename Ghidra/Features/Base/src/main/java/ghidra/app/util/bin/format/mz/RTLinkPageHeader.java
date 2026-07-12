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
 *     uint32 frame_size;           // overlay frame size in bytes
 *     uint16 reloc_count;          // number of 4-byte relocation entries
 *     uint16 reloc_count_2;        // entries in the second relocation list, if any
 *     uint32 reserved;             // always 0
 * };
 * </pre>
 * <p>
 * {@code reloc_count} is 16 bits, not 32: the word after it is a second, independent
 * relocation count. VICEROY.EXE has {@code reloc_count_2 == 0} on every page, so reading
 * the pair as one 32-bit count happened to give the right answer there — but not
 * elsewhere. In NEBULAR.EXE (Rex Nebular) 15 of 79 pages carry a second list, and the
 * 32-bit read turns page 1's count of 94 into 131166, so {@link #isValid()} rejects it
 * and the page walk stops before it starts. ROE2MAIN.EXE is worse: it parses 27 of its
 * 171 pages and then stops early, which looks like success.
 * <p>
 * The second list, when present, holds {@code reloc_count_2} entries of the same
 * {@link RTLinkRelocation} shape, starting at the next paragraph boundary after the first
 * list and followed by zero padding up to the code. It is parsed (see
 * {@link RTLinkOverlayPage#getSecondRelocations()}) but deliberately <b>not applied</b>:
 * whether those sites take the same load-delta fixup as the first list is unverified, and
 * applying the wrong fixup corrupts bytes. Tracing the runtime fixup loop in a binary that
 * has one (as was done for VICEROY at 210d:2e59) is what would settle it.
 */
public class RTLinkPageHeader implements StructConverter {

	public static final String NAME = "RTLink_Page_Header";
	public static final int HEADER_SIZE = 16;

	private int totalParagraphs;
	private int overheadParagraphs;
	private long frameSize;
	private int relocCount;
	private int secondRelocCount;
	private long reserved;

	/**
	 * Constructs a new RTLink/Plus page header
	 *
	 * @param reader A {@link BinaryReader} positioned at the start of the header
	 * @throws IOException if there was an IO-related error
	 */
	public RTLinkPageHeader(BinaryReader reader) throws IOException {
		totalParagraphs = Short.toUnsignedInt(reader.readNextShort());
		overheadParagraphs = Short.toUnsignedInt(reader.readNextShort());
		frameSize = Integer.toUnsignedLong(reader.readNextInt());
		relocCount = Short.toUnsignedInt(reader.readNextShort());
		secondRelocCount = Short.toUnsignedInt(reader.readNextShort());
		reserved = Integer.toUnsignedLong(reader.readNextInt());
	}

	public int getTotalParagraphs() {
		return totalParagraphs;
	}

	public int getOverheadParagraphs() {
		return overheadParagraphs;
	}

	public long getFrameSize() {
		return frameSize;
	}

	public int getRelocCount() {
		return relocCount;
	}

	/** Entries in the second relocation list; 0 when the page has none. */
	public int getSecondRelocCount() {
		return secondRelocCount;
	}

	/**
	 * Byte offset, relative to the start of the header, of the second relocation list:
	 * the next paragraph boundary after the first list. Only meaningful when
	 * {@link #getSecondRelocCount()} is nonzero.
	 */
	public int getSecondRelocOffset() {
		return (HEADER_SIZE + relocCount * 4 + 15) & ~15;
	}

	public long getReserved() {
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
		if (frameSize <= 0 || frameSize > 0x10000) {
			return false;
		}
		if (reserved != 0) {
			return false;
		}
		// Both relocation lists live in the overhead area, ahead of the code.
		if (HEADER_SIZE + (long) relocCount * 4 > (long) overheadParagraphs * 16) {
			return false;
		}
		if (secondRelocCount > 0 && getSecondRelocOffset() + (long) secondRelocCount * 4 >
			(long) overheadParagraphs * 16) {
			return false;
		}
		return true;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(WORD, "total_paragraphs", "Total record size in 16-byte paragraphs");
		struct.add(WORD, "overhead_paragraphs", "Header+relocs+padding paragraphs");
		struct.add(DWORD, "frame_size", "Overlay frame size in bytes");
		struct.add(WORD, "reloc_count", "Number of 4-byte relocation entries");
		struct.add(WORD, "reloc_count_2", "Entries in the second relocation list (0 if none)");
		struct.add(DWORD, "reserved", "Reserved (always 0)");
		struct.setCategoryPath(new CategoryPath("/DOS/RTLink"));
		return struct;
	}

	@Override
	public String toString() {
		return String.format(
			"RTLinkPageHeader[total=%d overhead=%d frame=0x%X relocs=%d relocs2=%d]",
			totalParagraphs, overheadParagraphs, frameSize, relocCount, secondRelocCount);
	}
}
