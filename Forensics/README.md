# 🔎 Forensics CTF Cheatsheet
## File Format Analysis

### 1. **Basic File Identification**
   - **`file`**: Identifies file type based on magic numbers.
     ```bash
     file <filename>
     ```

   - **`xxd`** / **`hexdump`**: View the raw bytes of a file in hexadecimal.
     ```bash
     xxd <filename>
     hexdump -C <filename>
     ```

   - **`strings`**: Extract human-readable strings from a file.
     ```bash
     strings <filename>
     ```

### 2. **Metadata Extraction**
   - **`exiftool`**: Extracts metadata from various file types (images, PDFs, etc.).
     ```bash
     exiftool <filename>
     ```

   - **`binwalk`**: Scans files for embedded data and file systems, can extract files.
     ```bash
     binwalk -e <filename>
     ```

   - **`foremost`**: Carve out hidden files based on headers and footers.
     ```bash
     foremost -i <filename> -o <output_directory>
     ```

### 3. **Compression and Archives**
   - **`tar`, `zip`, `unzip`, `7z`, `gzip`, etc.**: For working with compressed files and archives.
     - Example: `tar -xvf <file.tar>` to extract a `.tar` file.
     - Example: `unzip <file.zip>` to extract a `.zip` file.

   - **`binwalk`**: As mentioned, can identify and extract compressed archives embedded in binary files.

### 4. **PDF Files**
   - **`pdfinfo`**: Extracts metadata from PDFs.
     ```bash
     pdfinfo <filename.pdf>
     ```

   - **`pdfid`**: Scans PDF for potential exploits or JavaScript.
     ```bash
     python pdfid.py <filename.pdf>
     ```

   - **`pdf-parser`**: For deeper PDF structure analysis.
     ```bash
     python pdf-parser.py <filename.pdf>
     ```

### 5. **Images and Steganography**
   - **`steghide`**: Tool for hiding and extracting data from images/audio files.
     ```bash
     steghide extract -sf <image.jpg>
     ```

   - **`zsteg`**: Steganography detection for PNG and BMP images.
     ```bash
     zsteg <filename.png>
     ```

   - **`pngcheck`**: Verifies the integrity of PNG images and can show metadata.
     ```bash
     pngcheck -v <filename.png>
     ```

### 6. **Hex Editors**
   - **`hexedit`** / **`ghex`** / **`bless`**: Graphical and terminal-based hex editors for viewing and editing raw file bytes.
     ```bash
     hexedit <filename>
     ```

### 7. **Network and Packet Analysis**
   - **`Wireshark`**: Powerful GUI-based network protocol analyzer.
     - Open `.pcap` or `.pcapng` files for packet analysis.
   
   - **`tcpdump`**: Terminal-based network packet analyzer.
     ```bash
     tcpdump -r <capture.pcap>
     ```

   - **`tshark`**: Command-line version of Wireshark.
     ```bash
     tshark -r <capture.pcap>
     ```

### 8. **Miscellaneous File Format Analysis**
   - **`icat`**: Extract files from disk images.
     ```bash
     icat <image_file> <inode_number>
     ```

   - **`sleuthkit`**: Forensics tool for file system analysis.
     ```bash
     fls -r <disk_image>
     ```

   - **`bvi`**: Binary file editor with both binary and ASCII views.
     ```bash
     bvi <filename>
     ```

### 9. **Office Documents**
   - **`oletools`**: Analyze Microsoft Office documents for macros or hidden data.
     ```bash
     olevba <document.doc>
     ```

   - **`msoffcrypto-tool`**: For working with encrypted Office files.
     ```bash
     msoffcrypto-tool <encrypted.docx> --extract
     ```

### 10. **PE (Portable Executable) Files**
   - **`pefile`**: Python module for parsing and analyzing PE files.
     ```python
     import pefile
     pe = pefile.PE('malware.exe')
     ```

   - **`exiftool`**: Can also extract metadata from executable files.
     ```bash
     exiftool <filename.exe>
     ```

   - **`CFF Explorer`**: GUI tool for PE file analysis and reverse engineering (Windows).

### 11. **ELF (Executable and Linkable Format) Files**
   - **`readelf`**: Displays information about ELF files.
     ```bash
     readelf -a <filename>
     ```

   - **`objdump`**: Displays headers, sections, and disassembly of ELF files.
     ```bash
     objdump -d <filename>
     ```

---

### General Tips:
- Always check the **magic numbers** of a file as sometimes files may have their extension modified to mislead you.
- **Entropy analysis** can help detect encryption or compression (high entropy = likely compressed/encrypted).
- **Reverse engineering** tools like **Ghidra** or **IDA Pro** are useful for analyzing executable file formats, especially binaries.

---

This should cover most scenarios you’ll encounter in CTFs related to file format analysis.
