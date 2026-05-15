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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

/**
 * Parses the RTLink/Plus function directory from the global overlay table.
 * <p>
 * The directory is an array of {@code uint32} entries stored in the code region of the
 * global overlay table (the first "page" in the overlay data).  Each entry maps a
 * virtual function ID to a {@code (page_number, offset_within_page)} pair, enabling
 * resolution of JMPF dispatch stubs to their target overlay functions.
 * <p>
 * The directory encoding is auto-detected: entries are tried as
 * {@code page = high_word, offset = low_word} first, falling back to the reversed
 * interpretation if that produces no valid entries.
 */
public class RTLinkFunctionDirectory {

	/**
	 * A single directory entry mapping to a specific overlay page and offset.
	 *
	 * @param pageNumber  1-based overlay page number (1 = first code page)
	 * @param offsetInPage  byte offset within the page's code region
	 */
	public record DirectoryEntry(int pageNumber, int offsetInPage) {}

	private final List<DirectoryEntry> entries;
	private final boolean useByteOffset;

	/**
	 * Parses the function directory from the global overlay table's code region.
	 *
	 * @param reader             A {@link BinaryReader} for the file
	 * @param directoryFileOffset File offset where the directory starts (code region
	 *                           of the global overlay table)
	 * @param maxEntries         Maximum number of entries to attempt reading
	 * @param numCodePages       Number of overlay code pages (for validation)
	 * @param frameSize          Overlay frame size in bytes (for validation)
	 * @throws IOException if there was an IO-related error
	 */
	public RTLinkFunctionDirectory(BinaryReader reader, long directoryFileOffset,
			int maxEntries, int numCodePages, long frameSize) throws IOException {

		List<DirectoryEntry> primaryEntries =
			tryParse(reader, directoryFileOffset, maxEntries, numCodePages, frameSize, false);
		List<DirectoryEntry> altEntries =
			tryParse(reader, directoryFileOffset, maxEntries, numCodePages, frameSize, true);

		if (altEntries.size() > primaryEntries.size()) {
			entries = altEntries;
		}
		else {
			entries = primaryEntries;
		}

		useByteOffset = detectResolutionMode();
	}

	/**
	 * Resolves a virtual offset (from a JMPF stub) to a directory entry.
	 *
	 * @param virtualOffset The 16-bit offset from the JMPF instruction
	 * @return The resolved directory entry, or {@code null} if unresolvable
	 */
	public DirectoryEntry resolve(int virtualOffset) {
		int index;
		if (useByteOffset) {
			if (virtualOffset % 4 != 0) {
				return null;
			}
			index = virtualOffset / 4;
		}
		else {
			index = virtualOffset;
		}

		if (index < 0 || index >= entries.size()) {
			return null;
		}
		return entries.get(index);
	}

	/**
	 * Returns the number of parsed directory entries.
	 *
	 * @return entry count
	 */
	public int getEntryCount() {
		return entries.size();
	}

	private static List<DirectoryEntry> tryParse(BinaryReader reader, long fileOffset,
			int maxEntries, int numCodePages, long frameSize, boolean reversed)
			throws IOException {
		List<DirectoryEntry> result = new ArrayList<>();
		reader.setPointerIndex(fileOffset);

		int consecutiveInvalid = 0;
		for (int i = 0; i < maxEntries; i++) {
			int value = reader.readNextInt();

			int page;
			int offset;
			if (reversed) {
				page = value & 0xFFFF;
				offset = (value >>> 16) & 0xFFFF;
			}
			else {
				page = (value >>> 16) & 0xFFFF;
				offset = value & 0xFFFF;
			}

			if (value == 0) {
				result.add(new DirectoryEntry(0, 0));
				consecutiveInvalid = 0;
				continue;
			}

			if (page >= 1 && page <= numCodePages && offset < frameSize) {
				result.add(new DirectoryEntry(page, offset));
				consecutiveInvalid = 0;
			}
			else {
				consecutiveInvalid++;
				if (consecutiveInvalid >= 3) {
					break;
				}
				result.add(new DirectoryEntry(page, offset));
			}
		}

		while (!result.isEmpty()) {
			DirectoryEntry last = result.get(result.size() - 1);
			if (last.pageNumber() < 1 || last.pageNumber() > numCodePages) {
				result.remove(result.size() - 1);
			}
			else {
				break;
			}
		}

		return result;
	}

	/**
	 * Detect whether JMPF virtual offsets are direct indices or byte offsets
	 * into the directory.  If most entries have indices < entryCount, direct index
	 * mode works.  If most valid offsets are multiples of 4 and in range
	 * 0..entryCount*4, byte-offset mode works.
	 * <p>
	 * We default to direct index mode since it's the simpler mapping.
	 * Byte-offset mode is selected only if the entry count exceeds 0xFFFF / 4,
	 * which would make direct indexing impossible with 16-bit offsets.
	 */
	private boolean detectResolutionMode() {
		return entries.size() > 0x3FFF;
	}

	@Override
	public String toString() {
		return String.format("RTLinkFunctionDirectory[%d entries, mode=%s]",
			entries.size(), useByteOffset ? "BYTE_OFFSET" : "INDEX");
	}
}
