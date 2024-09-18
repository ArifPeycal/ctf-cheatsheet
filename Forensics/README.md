# 🔎 Forensics CTF Cheatsheet
## 📁File Format Analysis

### 1. **Basic File Identification**
**`file`**:
   - Identifies file type based on magic numbers. If you were given a binary file or file without extension, check using `file` first.
     
     ```bash
     file <filename>
     ```

**`xxd`** / **`hexdump`**:
   - View the raw bytes of a file in hexadecimal.

     ```bash
     xxd <filename>
     hexdump -C <filename>
     ```

**`strings`**:

   - Extract human-readable strings from a file. Combine with `grep` or `findstr` to get the flag directly.
     
     ```bash
     strings <filename> | grep <strings>
     ```

### 2. **Metadata Extraction**
**`exiftool`**:

   - Extracts metadata from various file types (images, PDFs, etc.).
     
     ```bash
     exiftool <filename>
     ```

### 3. **Compression and Archives**
**`tar`, `zip`, `unzip`, `7z`, `gzip`, etc.**:

   - For working with compressed files and archives.
     - Example: `tar -xvf <file.tar>` to extract a `.tar` file.
     - Example: `unzip <file.zip>` to extract a `.zip` file.

### 4. **PDF Files**
**`pdfinfo`**:
   - Extracts metadata from PDFs.
     
     ```bash
     pdfinfo <filename.pdf>
     ```

**`pdf-parser`**:
   - For deeper PDF structure analysis.
     
     ```bash
     python pdf-parser.py <filename.pdf>
     ```

### 5. **Image files**

**`pngcheck`**:
   - Verifies the integrity of PNG images and can show metadata.
     
     ```bash
     pngcheck -v <filename.png>
     ```

### 6. **ELF (Executable and Linkable Format) Files**
   - **`readelf`**: Displays information about ELF files.
     ```bash
     readelf -a <filename>
     ```

   - **`objdump`**: Displays headers, sections, and disassembly of ELF files.
     ```bash
     objdump -d <filename>
     ```

## 🖼️ Corrupted Image Recovery

### 1. **Automated Tools**
Due to CTF time constraints, it is recommended that players use tools to automate the process. 
   - [PCRT](https://github.com/sherlly/PCRT): A Python software that can auto-fix corrupted images.
     ```
      python PCRT.py -h
      usage: PCRT.py [-h] [-q] [-y] [-v] [-m] [-n NAME] [-p PAYLOAD] [-w WAY]
                     [-d DECOMPRESS] [-i INPUT] [-f] [-o OUTPUT]
      
      optional arguments:
        -h, --help            show this help message and exit
        -q, --quiet           don't show the banner infomation
        -y, --yes             auto choose yes
        -v, --verbose         use the safe way to recover
        -m, --message         show the image information
        -n NAME, --name NAME  payload name [Default: random]
        -p PAYLOAD, --payload PAYLOAD
                              payload to hide
        -w WAY, --way WAY     payload chunk: [1]: ancillary [2]: critical
                              [Default:1]
        -d DECOMPRESS, --decompress DECOMPRESS
                              decompress zlib data file name
        -i INPUT, --input INPUT
                              Input file name (*.png) [Select from terminal]
        -f, --file            Input file name (*.png) [Select from window]
        -o OUTPUT, --output OUTPUT
                              Output repaired file name [Default: output.png]     
      ```
   - [FotoForensics](https://fotoforensics.com/): Online image recovery tool.
     
     ![image](https://github.com/user-attachments/assets/07150792-eb4d-47f4-9d0c-6a0f4d2d29b6)

### 2. **Manually Patching JPEG Corrupted Headers**
There will be certain cases where tools can't recover the image file, then we need to manually fix the image file. An easy image recovery challenge only requires the CTF players to modify the magic bytes of an image file.  

   - **Magic Bytes**: Also can refer [here](https://en.wikipedia.org/wiki/List_of_file_signatures).
     1. `.jpg`: `FF D8 FF`
     2. `.png`: `89 50 4E 47 0D 0A 1A 0A`
     3. `.bmp`: `42 4D`
     4. `.gif`: `47 49 46 38 37 61`

   - **JPG File Header**:


| Offset (Hex) | Field        | Description                                                    | Example Values (Hex)  |
|--------------|--------------|----------------------------------------------------------------|-----------------------|
| 00h          | SOI          | Start of Image Marker                                          | FF D8                 |
| 02h          | APP0         | Application Use Marker                                         | FF E0                 |
| 04h          | Length       | Length of APP0 Field                                           | (varies)              |
| 06h          | Identifier   | "JFIF" (null-terminated string identifying JFIF format)        | 4A 46 49 46 00        |
| 07h          | Version      | JFIF Format Revision                                           | 01 02 / 01 00         |
| 09h          | Units        | Units used for resolution                                      | (varies)              |
| 0Ah          | Xdensity     | Horizontal resolution                                          | (varies)              |
| 0Ch          | Ydensity     | Vertical resolution                                            | (varies)              |
| 0Eh          | XThumbnail   | Horizontal pixel count for thumbnail                           | (varies)              |
| 0Fh          | YThumbnail   | Vertical pixel count for thumbnail                             | (varies)              |


   - **JPEG Header Patching**:
Open hexeditor to change the magic bytes, compare the bytes with any normal JPEG sample.

Corrupted file:

   ![image](https://github.com/user-attachments/assets/09d97b0d-7aae-480f-869b-fcf66b325141)

Repaired file:

![image](https://github.com/user-attachments/assets/25fb4338-5607-458f-b428-d8c306b3949a)


### 3. **Manually Patching PNG Corrupted Headers**


To manually patch the header, you need to have some basic understanding of PNG file format. The structure of a PNG file consists of a signature followed by a series of chunks. Each chunk holds specific data related to the image. 

1. **PNG Signature (8 bytes)**
   
The first part of the PNG file is a signature that helps identify the file as a PNG image. It consists of the following bytes:

| Values (Hex)    | Description                                                |
|-----------------|------------------------------------------------------------|
| 89              | High bit set to detect non-8-bit systems and prevent misinterpretation. |
| 50 4E 47        | "PNG" in ASCII for easy identification.                    |
| 0D 0A           | DOS-style line ending (CRLF) for DOS-Unix conversion.      |
| 1A              | End-of-file marker for DOS.                                |
| 0A              | Unix-style line ending (LF) for Unix-DOS conversion.       |

![image](https://github.com/user-attachments/assets/98ea06f0-e7e8-4c31-8e23-1d6ce3dccc9a)

2. **PNG Chunks**
   
The main content of a PNG file is stored in chunks. Each chunk has a specific purpose, and the PNG specification allows for both standard and custom chunks. Each chunk consists of four parts:

| Field         | Length      | Description                                                                         |
|---------------|-------------|-------------------------------------------------------------------------------------|
| Length        | 4 bytes     | The length of the chunk data in bytes.                                               |
| Chunk Type    | 4 bytes     | A 4-character ASCII code identifying the chunk type.                                 |
| Chunk Data    | Variable    | The data associated with the chunk (its length is specified in the Length field).    |
| CRC           | 4 bytes     | A 4-byte CRC (Cyclic Redundancy Check) to verify the integrity of the chunk.         |

#### **Critical Chunks (Required in every PNG file):**

1. `IHDR`(Image Header)

Hex Values: `49 48 44 52`

Purpose: Defines the image’s width, height, bit depth, color type, compression method, filter method, and interlace method.

| Field          | Length   | Description                                              |
|----------------|----------|----------------------------------------------------------|
| Width          | 4 bytes  | Image width in pixels.                                   |
| Height         | 4 bytes  | Image height in pixels.                                  |
| Bit Depth      | 1 byte   | Number of bits per channel (e.g., 8, 16).                |
| Color Type     | 1 byte   | Defines color scheme (e.g., grayscale, RGB).             |
| Compression    | 1 byte   | Compression method used (always 0 for PNG).              |
| Filter Method  | 1 byte   | Filter method used (always 0 for PNG).                   |
| Interlace      | 1 byte   | Interlace method (0 = no interlace, 1 = Adam7).          |

![image](https://github.com/user-attachments/assets/041fc901-9361-4430-893f-2d68da9f2dc5)

2. `PLTE` (Palette Table)

Purpose: Contains the color palette used in indexed-color images. It contains from 1 to 256 palette entries, each a three-byte series of the form. 

- Red 🔴: 1 byte (0 = black, 255 = red) - Green 🟢: 1 byte (0 = black, 255 = green) - Blue 🔵: 1 byte (0 = black, 255 = blue)

3. `IDAT` (Image Data)
   
Hex Values: `49 44 41 54`

Purpose: Contains the actual image data, which is compressed using the DEFLATE algorithm. Multiple IDAT chunks can be present and are concatenated to form the complete image data.

![image](https://github.com/user-attachments/assets/e2ff52dd-6419-4188-b55a-13a9ae62f8f8)

4. `IEND` (Image End)

Purpose: Marks the end of the PNG file. It contains no data but is necessary to signify the file’s end.

| Value (Hex)     | Description                                      |
|-----------------|--------------------------------------------------|
| 00 00 00 00     | The length of the IEND chunk is always 0 bytes.  |
| 49 45 4E 44     | The chunk type, "IEND", marks the end of the PNG file. |
| AE 42 60 82     | A fixed 4-byte CRC value for the IEND chunk.     |

![image](https://github.com/user-attachments/assets/d06c4adf-ba66-4105-ac9a-4fb5b53e109e)

#### Ancillary Chunks (Optional):

- tEXt / zTXt / iTXt (Textual Data): Store textual metadata. tEXt stores uncompressed text, zTXt stores compressed text, and iTXt stores international text.
- gAMA (Gamma Correction): Specifies the gamma correction to be applied to the image.
- cHRM (Chromaticity): Defines the chromaticity coordinates for the image’s primary colors.
- tIME (Modification Time): Stores the last modification time of the image.
- bKGD (Background Color): Suggests a background color for images without alpha transparency.
- pHYs (Physical Pixel Dimensions): Specifies the intended pixel size or aspect ratio.        
   
### 4. CTF Questions
1. **Incorrect PNG signature** -> `89 50 4E 47`
2. **Incorrect `IHDR`,`IDAT`, and `IEND` chunk** -> Change to correct hex values
3. **Incorrect data length** -> Calculate the number of bytes starting immediately after the chunk type and ending just before the current chunk's CRC. Use this [link](https://www.rapidtables.com/convert/number/hex-to-decimal.html) to convert from decimal to hexadecimals.
4. **Incorrect CRC** -> Use `pngcheck`
5. **Unknown width and length but known CRC** -> Bruteforce using Pyton script
   <details>
      
      <summary>Bruteforce solution</summary>
      
      ```py
      import struct
      import zlib

      known_crc = 0x932f8a6b
      
      # Fixed part of IHDR (bit depth, color type, etc.) after width and height
      fixed_data = b'\x08\x06\x00\x00\x00'      # Change according to PNG file

      chunk_type = b'IHDR'
      
      def brute_force_width_height():
          for width in range(1, 10000):  
              for height in range(1, 10000): 
                  ihdr_data = struct.pack(">II", width, height) + fixed_data

            calculated_crc = zlib.crc32(chunk_type + ihdr_data) & 0xffffffff

            if calculated_crc == known_crc:
                width_hex = f"{width:08X}"
                height_hex = f"{height:08X}"
                print(f"Found match! Width: {width} (0x{width_hex}), Height: {height} (0x{height_hex})")
                return width, height, width_hex, height_hex

    print("No match found.")
    return None

   brute_force_width_height()

   ```
      
   </details>

## 🕵️ Steganography

### 1. 🖼️ **Image Steganography**

**Tools**:

- **`steghide`**: Hides/Extracts data in images and audio.
  - *Extract data*:
    ```bash
    steghide extract -sf image.jpg
    ```
  - If there's a password:
    ```bash
    steghide extract -sf image.jpg -p "password"
    ```
- **`stegseek`**: Extract hidden files from password protected image using wordlist
  - Upgraded version of `steghide`, can use `steghide` command.
    ```bash
    stegseek [stegofile.jpg] [wordlist.txt]
    ```
- **`binwalk`**: Extracts hidden files or embedded data.
  - *Basic extraction*:
    ```bash
    binwalk -e image.png
    ```

- **`zsteg`**: Detects hidden data in PNG/BMP files.
  - *Scan for hidden data*:
    ```bash
    zsteg -a image.png
    ```
    
- **`stegsolve`**: GUI tool for analyzing image layers and color channels.
  - Use it to check image layers, LSB (Least Significant Bit), and filters for hidden data.
    ```bash
    java -jar stegsolve.jar
    ```
   ![image](https://github.com/user-attachments/assets/a57a2b1c-5cf5-4c16-8067-9d0104851ca7)


### 2. 🎵 **Audio Steganography**

**Tools**:

- **`DeepSound`**: Popular stegnography tool used to hide data inside audio tracks as well as decode it. Download [here](https://github.com/Jpinsoft/DeepSound).
    - If the challenge descriptions/hints stated "Deep", most probably need to use DeepSound. 

     ![image](https://github.com/user-attachments/assets/a74a6fb3-548a-4879-9d42-5b7138eadc00)

- **`Audacity / Sonic Visualiser `**: Audio editing tool for inspecting waveforms and spectrograms.
  - Use *spectrogram view* in Audacity to look for visual patterns.
    
   ![image](https://github.com/user-attachments/assets/0e63ea2e-0189-4ebb-a6b7-5e09e5e6d4a0)

- **`stegolsb`**: Extract hidden data in LSB of audio files.
  - *Extract from audio*:
    ```bash
    stegolsb wavsteg -r -i audio.wav -o output.txt -b 1
    ```
    
### 3. 📄 **Text Steganography**

**Tools**:

- **`stegsnow`**: Hides messages in whitespace at the end of lines in text files.
  
   ![image](https://github.com/user-attachments/assets/b855b02d-10b8-4743-a7d7-c3d873c60e44)

  - *Extract message*:
    ```bash
    stegsnow -C -p "password" textfile.txt
    ```
- **`Unicode Steganography with Zero-Width Characters`**: Zero-width characters is inserted within the words.
  - *https://330k.github.io/misc_tools/unicode_steganography.html*

   ![image](https://github.com/user-attachments/assets/cefd3d6d-397e-439b-90e7-d0629abbb056)


## 🗂️ Archives Cracking 

### 1. **Zip Known-Plaintext Attack (ZipCrypto Store)**

1. **Identify ZIP Encryption Type**:
   - Use tools like `zipinfo` or `file`. If the compression method is `store`, then, it is like to be vulnerable to `ZipCryto Known-Plaintext Attack`.
     
      ![image](https://github.com/user-attachments/assets/bfdb0671-9873-44af-a874-5134fe89f387)

2. **Find a Known Plaintext**:
   - You need to know at least `12 bytes` from a file from inside the ZIP archive.
   - Candidate files:
      1. SVG/XML: `<?xml version="1.0"?>`
      2. `networks` file in C:\Windows\System32\drivers\etc: `# Copyright (c) 1993-1999 Microsoft Corp`
3. **Run `bkcrack`**:
   
   - Install bkcrack from this [Github repo](https://github.com/kimci86/bkcrack).
   - Command:
     ```bash
     bkcrack -C encrypted.zip -c encrypted_file_in_zip -P known_plaintext_file -p known_plaintext
     ```
   - **Output**: `bkcrack` will generate the keys to decrypt the archive.
   
      ![image](https://github.com/user-attachments/assets/8e979b74-cc8a-44d2-bb8c-ace8ce4204f4)

4. **Decrypt the ZIP**:
   - Use the keys found in the previous step to decrypt the ZIP file:
     ```bash
     bkcrack -C secret.zip -k <key0> <key1> <key2> -U
     ```
      ![image](https://github.com/user-attachments/assets/d6b5e776-ac92-4ae8-9e6e-60f71208f35f)

### 2. **Cracking Archive Passwords with `John the Ripper`**

1. **Extract ZIP or RAR Hash**:
   - **For ZIP**:
     ```bash
     zip2john archive.zip > zip.hash
     ```
   - **For RAR**:
     ```bash
     rar2john archive.rar > rar.hash
     ```

2. **Crack the Password**:
   - Use John to crack the password using the hash:
     ```bash
     john --wordlist=/path/to/wordlist.txt zip.hash
     ```

3. **View Cracked Password**:
   - Once cracked, view the password with:
     ```bash
     john --show zip.hash
     ```

### 3. **Cracking ZIP and RAR Passwords with `Hashcat`**

#### 🖥️ **Hashcat Modes**:
- **ZIP mode**: `13600`
- **RAR3 mode**: `13000`
- **RAR5 mode**: `23700`


2. **Extract Hash**:
   - **For ZIP**:
     ```bash
     zip2john archive.zip > zip.hash
     ```
   - **For RAR**:
     ```bash
     rar2john archive.rar > rar.hash
     ```

3. **Run Hashcat**:
   - **ZIP** cracking example:
     ```bash
     hashcat -m 13600 zip.hash /path/to/wordlist.txt
     ```
   - **RAR3** cracking example:
     ```bash
     hashcat -m 13000 rar.hash /path/to/wordlist.txt
     ```

4. **Check Cracked Password**:
   - View the cracked password using:
     ```bash
     hashcat -m <mode> --show hashfile
     ```

## 4. **Analyzing and Cracking 7z Files**

1. **Convert 7z File to Hash Format**:
   ```bash
   7z2hashcat file.7z > 7z.hash
   ```

2. **Crack 7z Password with Hashcat**:
   ```bash
   hashcat -m 11600 7z.hash /path/to/wordlist.txt
   ```

3. **Check Cracked Password**:
   ```bash
   hashcat --show 7z.hash
   ```
