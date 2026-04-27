const ENTRIES = [
  // ==================== TRIAGE / QUICK WINS / FLAG SEARCH ====================
  {
    title: "CTF - Quick File Checks",
    description: "First things to try when you get an unknown file in a CTF",
    analysis: "If 'file' says 'data', the header is corrupted or the file is encrypted/compressed. Try fixing magic bytes.\nIf strings finds nothing, try Unicode strings (-el). Embedded files from binwalk = matryoshka challenge.\nHigh entropy (7.9+) = encrypted or compressed. Low entropy with no readable strings = custom encoding.\nAlways check exif comments and GPS — flags hide in metadata fields like Author, Comment, Description.",
    category: ["File Analysis"],
    phase: ["Triage"],
    os: ["Linux"],
    tools: ["file", "strings", "binwalk", "ExifTool"],
    commands: [
      { label: "1. File type", cmd: "file {FILE}" },
      { label: "2. Strings", cmd: "strings {FILE} | grep -iE 'flag|ctf|key|pass|secret'" },
      { label: "3. Hex header", cmd: "xxd {FILE} | head -5" },
      { label: "4. Binwalk", cmd: "binwalk {FILE}" },
      { label: "5. Exif", cmd: "exiftool {FILE}" },
      { label: "6. Entropy", cmd: "binwalk -E {FILE}" },
      { label: "7. Foremost", cmd: "foremost -i {FILE} -o carved/" }
    ]
  },
  {
    title: "Flag Grep - CTF Quick Search",
    description: "Search for flags across files, memory dumps, and PCAP using common CTF flag formats",
    analysis: "Run the common formats grep first — it covers most CTF platforms. If no hits, the flag may be encoded.\nBase64-encoded flags: look for strings matching ^[A-Za-z0-9+/=]{20,}$ then decode them.\nIn PCAPs, flags often hide in HTTP response bodies, DNS TXT records, or FTP data streams.\nIn memory dumps, grep both ASCII and Unicode. Flags sometimes span multiple lines or have null bytes between chars.",
    category: ["File Analysis"],
    phase: ["Triage"],
    os: ["Linux"],
    tools: ["grep", "tshark", "strings"],
    commands: [
      { label: "Generic flag", cmd: "grep -rEo 'flag\\{[^}]+\\}' ." },
      { label: "Common formats", cmd: "grep -rEoI '(flag|FLAG|ctf|CTF|picoCTF|HTB|CHTB|THM)\\{[^}]+\\}' ." },
      { label: "In PCAP", cmd: "tshark -r {PCAP} -Y 'frame contains \"flag{\"' -T fields -e data.text" },
      { label: "In memory", cmd: "strings {DUMP_FILE} | grep -oE 'flag\\{[^}]+\\}'" },
      { label: "Base64 flags", cmd: "strings {FILE} | while read l; do echo \"$l\" | base64 -d 2>/dev/null; done | grep -oE 'flag\\{[^}]+\\}'" }
    ]
  },

  // ==================== FILE ANALYSIS ====================
  {
    title: "file - Identify File Type",
    description: "Determine file type using magic bytes",
    analysis: "If output says 'data', the file header is damaged or non-standard — check hex header manually.\nMismatch between extension and detected type = renamed file (e.g., .jpg that is actually a ZIP).\nUse -k to see ALL matching signatures — some files have multiple valid headers (polyglots).",
    category: ["File Analysis"],
    phase: ["Triage"],
    os: ["Linux", "macOS"],
    tools: ["file"],
    commands: [
      { label: "Identify", cmd: "file {FILE}" },
      { label: "MIME type", cmd: "file --mime-type {FILE}" },
      { label: "All matches", cmd: "file -k {FILE}" }
    ]
  },
  {
    title: "strings - Extract Readable Text",
    description: "Extract printable strings from binary files",
    analysis: "Look for: URLs, IP addresses, file paths, error messages, base64 blobs, flag formats.\nLong random-looking strings = possible encoded data or keys.\nReferences to temp directories, /dev/shm, or AppData = suspicious.\nFunction names like 'encrypt', 'decode', 'connect', 'exec' reveal program behavior.",
    category: ["File Analysis"],
    phase: ["Analysis"],
    os: ["Linux", "macOS"],
    tools: ["strings"],
    commands: [
      { label: "ASCII strings", cmd: "strings {FILE}" },
      { label: "Unicode (LE)", cmd: "strings -el {FILE}" },
      { label: "Min length 10", cmd: "strings -n 10 {FILE}" },
      { label: "With offsets", cmd: "strings -t x {FILE}" },
      { label: "Grep for flags", cmd: "strings {FILE} | grep -iE 'flag|ctf|key|pass|secret'" }
    ]
  },
  {
    title: "xxd / hexdump - Hex Analysis",
    description: "View raw hex content of files for header analysis",
    analysis: "Compare first 4-8 bytes against known magic bytes to identify true file type.\nLook for readable ASCII in the right column — hidden messages, URLs, paths.\n00 00 00 runs = null padding or zeroed-out sections. FF FF FF runs = erased flash memory.\nSearch for 'PK' (504b) to find embedded ZIPs, or '89 50 4E 47' for embedded PNGs within binary blobs.",
    category: ["File Analysis"],
    phase: ["Analysis"],
    os: ["Linux", "macOS"],
    tools: ["xxd"],
    commands: [
      { label: "Hex dump", cmd: "xxd {FILE} | head -20" },
      { label: "First 64 bytes", cmd: "xxd -l 64 {FILE}" },
      { label: "Search hex", cmd: "xxd {FILE} | grep -i '504b0304'" },
      { label: "Binary view", cmd: "xxd -b {FILE} | head -20" },
      { label: "Reverse (hex to bin)", cmd: "xxd -r -p hex_input.txt output.bin" }
    ]
  },
  {
    title: "binwalk - Firmware / Embedded File Analysis",
    description: "Scan for embedded files, file systems, and compressed data",
    analysis: "Multiple file headers found = embedded files (extract with -e). Entropy near 8.0 = encrypted or compressed. Entropy drops/spikes at specific offsets = hidden data boundaries.\nZlib/gzip compressed sections inside images = appended data after image footer.\nIf -e fails, use dd with the offset binwalk reports to manually carve. False positives are common — verify extracted files with 'file'.",
    category: ["File Analysis", "Stego"],
    phase: ["Analysis", "Carving"],
    os: ["Linux"],
    tools: ["binwalk"],
    commands: [
      { label: "Scan", cmd: "binwalk {FILE}" },
      { label: "Extract", cmd: "binwalk -e {FILE}" },
      { label: "Deep extract", cmd: "binwalk --dd='.*' {FILE}" },
      { label: "Entropy", cmd: "binwalk -E {FILE}" },
      { label: "Raw extract at offset", cmd: "dd if={FILE} bs=1 skip={OFFSET} count={SIZE} of=extracted.bin" }
    ]
  },
  {
    title: "Entropy Analysis",
    description: "Check file entropy to detect encryption or compression",
    analysis: "Entropy 0-1: very structured/repetitive data (empty file, repeated pattern).\nEntropy 3-5: normal text, code, documents.\nEntropy 6-7: compressed data (ZIP, gzip) or packed executables.\nEntropy 7.5-8.0: encrypted data or high-quality compression. Truly random data = exactly 8.0.\nSudden entropy changes at specific offsets indicate boundaries between different content types — possible hidden or appended data.",
    category: ["File Analysis"],
    phase: ["Triage"],
    os: ["Linux"],
    tools: ["ent", "binwalk"],
    commands: [
      { label: "ent", cmd: "ent {FILE}" },
      { label: "binwalk entropy", cmd: "binwalk -E {FILE}" },
      { label: "Python entropy", cmd: "python3 -c \"import math, collections; d=open('{FILE}','rb').read(); f=collections.Counter(d); e=-sum(c/len(d)*math.log2(c/len(d)) for c in f.values()); print(f'Entropy: {e:.4f}/8.0')\"" }
    ]
  },
  {
    title: "Magic Bytes Reference",
    description: "Common file signatures (magic bytes) for identification and header repair",
    category: ["File Analysis"],
    phase: ["Triage"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["xxd"],
    commands: [
      { label: "PNG", cmd: "# 89 50 4E 47 0D 0A 1A 0A  (.PNG....)" },
      { label: "JPEG", cmd: "# FF D8 FF E0  (JFIF) or FF D8 FF E1 (Exif)" },
      { label: "PDF", cmd: "# 25 50 44 46  (%PDF)" },
      { label: "ZIP / DOCX / JAR", cmd: "# 50 4B 03 04  (PK..)" },
      { label: "GIF", cmd: "# 47 49 46 38  (GIF8)" },
      { label: "ELF", cmd: "# 7F 45 4C 46  (.ELF)" },
      { label: "PE / EXE", cmd: "# 4D 5A  (MZ)" },
      { label: "7z", cmd: "# 37 7A BC AF 27 1C  (7z...)" },
      { label: "RAR", cmd: "# 52 61 72 21  (Rar!)" },
      { label: "PCAP", cmd: "# D4 C3 B2 A1 (little-endian) or A1 B2 C3 D4 (big-endian)" },
      { label: "PCAPNG", cmd: "# 0A 0D 0D 0A" },
      { label: "GZIP", cmd: "# 1F 8B 08" },
      { label: "BZ2", cmd: "# 42 5A 68  (BZh)" },
      { label: "XZ", cmd: "# FD 37 7A 58 5A 00" },
      { label: "SQLite", cmd: "# 53 51 4C 69 74 65 20 66 6F 72 6D 61 74  (SQLite format)" },
      { label: "OGG", cmd: "# 4F 67 67 53  (OggS)" },
      { label: "MP3 (ID3)", cmd: "# 49 44 33  (ID3)" },
      { label: "FLAC", cmd: "# 66 4C 61 43  (fLaC)" },
      { label: "WAV", cmd: "# 52 49 46 46 xx xx xx xx 57 41 56 45  (RIFF....WAVE)" },
      { label: "AVI", cmd: "# 52 49 46 46 xx xx xx xx 41 56 49 20  (RIFF....AVI )" },
      { label: "TAR", cmd: "# 75 73 74 61 72  at offset 0x101 (ustar)" },
      { label: "Java class", cmd: "# CA FE BA BE" },
      { label: "Mach-O (macOS)", cmd: "# FE ED FA CE (32-bit) / FE ED FA CF (64-bit)" },
      { label: "Fix header (example)", cmd: "printf '\\x89\\x50\\x4e\\x47\\x0d\\x0a\\x1a\\x0a' | dd of={FILE} bs=1 count=8 conv=notrunc" }
    ]
  },
  {
    title: "File Carving",
    description: "Carve and recover files from disk images, memory dumps, and binary blobs using header/footer signatures",
    analysis: "foremost is fastest for quick carving; photorec recovers more file types and handles fragmented files better.\nCheck carved output with 'file' — false positives are common. Tiny carved files (< 100 bytes) are usually false hits.\nIf foremost misses files, try scalpel with custom config for specific signatures. Edit scalpel.conf to enable types.\nphotorec can recover from formatted drives — it ignores the filesystem and scans raw data.\nblkls + foremost combo focuses on unallocated space only, reducing noise from existing files.",
    category: ["File Analysis", "Disk"],
    phase: ["Carving", "Recovery"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["foremost", "scalpel", "photorec", "Sleuth Kit"],
    commands: [
      { label: "foremost (all types)", cmd: "foremost -i {FILE} -o output/" },
      { label: "foremost (specific)", cmd: "foremost -t jpg,png,pdf -i {FILE} -o output/" },
      { label: "foremost (verbose)", cmd: "foremost -v -i {IMAGE} -o output/" },
      { label: "scalpel", cmd: "scalpel -c /etc/scalpel/scalpel.conf -o output/ {IMAGE}" },
      { label: "photorec (interactive)", cmd: "photorec {IMAGE}" },
      { label: "photorec (CLI)", cmd: "photorec /d output/ /cmd {IMAGE} partition_none,options,mode_ext2,fileopt,everything,enable,search" },
      { label: "photorec (specific types)", cmd: "photorec /d output/ /cmd {IMAGE} partition_none,fileopt,everything,disable,jpg,enable,search" },
      { label: "blkls (unallocated)", cmd: "blkls -o {OFFSET} {IMAGE} > unalloc.bin && foremost -i unalloc.bin -o carved/" }
    ],
    references: ["https://www.cgsecurity.org/wiki/PhotoRec"]
  },
  {
    title: "ExifTool - Metadata Extraction",
    description: "Extract and analyze metadata from images, documents, and media",
    analysis: "CTF flags commonly hide in: Comment, UserComment, ImageDescription, Author, XPComment, Subject fields.\nGPS coordinates in photos can reveal locations — paste into Google Maps. Check Make/Model for camera identification.\nCreation vs Modification date mismatch = file was edited. Software field reveals what tool created/edited the file.\nThumbnail images may differ from main image (old content preserved in thumbnail after editing).",
    category: ["Metadata"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["ExifTool"],
    commands: [
      { label: "All metadata", cmd: "exiftool {FILE}" },
      { label: "GPS coordinates", cmd: "exiftool -gpslatitude -gpslongitude {FILE}" },
      { label: "Creation date", cmd: "exiftool -CreateDate -ModifyDate {FILE}" },
      { label: "Recursive", cmd: "exiftool -r /path/to/files/" },
      { label: "Remove all metadata", cmd: "exiftool -all= {FILE}" },
      { label: "Compare files", cmd: "exiftool -a -G1 {FILE}" }
    ],
    references: ["https://exiftool.org/"]
  },
  {
    title: "pdfinfo / pdftotext - PDF Analysis",
    description: "Extract metadata and text from PDF files",
    analysis: "Check for hidden text layers — some PDFs have invisible/white text overlaid on images.\npdftotext may reveal text that is not visible when viewing the PDF (hidden behind images or white-on-white).\nEmbedded JavaScript in PDFs = potential malicious payload. Check PDF structure for /JS or /JavaScript entries.\nImages extracted with pdfimages may contain steganographic data — run them through stego tools.",
    category: ["Metadata", "File Analysis"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["poppler-utils"],
    commands: [
      { label: "PDF info", cmd: "pdfinfo {FILE}" },
      { label: "Extract text", cmd: "pdftotext {FILE} -" },
      { label: "Extract images", cmd: "pdfimages -all {FILE} output/" },
      { label: "PDF structure", cmd: "pdftohtml -xml {FILE}" }
    ]
  },
  {
    title: "File Hashing & Verification",
    description: "Generate and verify file hashes for integrity checking",
    analysis: "Compare hashes against VirusTotal (search by hash). Known-good hash databases: NSRL, HashSets.\nDifferent hash from original = file tampered. Same hash as known malware = confirmed malicious.\nAlways hash evidence BEFORE and AFTER analysis to prove integrity. Document hash values in your notes.\nMD5 is vulnerable to collisions — use SHA-256 for forensic integrity. MD5 is fine for quick lookups on VT.",
    category: ["File Analysis"],
    phase: ["Acquisition", "Triage"],
    os: ["Linux", "macOS", "Windows"],
    tools: ["sha256sum", "md5sum"],
    commands: [
      { label: "SHA-256", cmd: "sha256sum {FILE}" },
      { label: "MD5", cmd: "md5sum {FILE}" },
      { label: "SHA-1", cmd: "sha1sum {FILE}" },
      { label: "Verify hash", cmd: "echo '{HASH}  {FILE}' | sha256sum -c" },
      { label: "Hash all files", cmd: "find . -type f -exec sha256sum {} \\; > hashes.txt" },
      { label: "macOS SHA-256", cmd: "shasum -a 256 {FILE}" }
    ]
  },
  {
    title: "CTF - ZIP / Archive Tricks",
    description: "Common CTF tricks with ZIP and archive files",
    analysis: "If fcrackzip/john fail, the password might not be in rockyou — try challenge-related words, title, description.\nZIP with 'stored' (no compression) method = known plaintext attack possible with pkcrack.\nNested ZIPs (zip inside zip) are common CTF patterns — automate extraction with a loop.\nCorrupt ZIP? Try 'zip -FF broken.zip --out fixed.zip' to repair. Check if it is actually a different format renamed to .zip.",
    category: ["File Analysis", "Crypto/Encoding"],
    phase: ["Analysis", "Recovery"],
    os: ["Linux"],
    tools: ["zip", "fcrackzip", "John the Ripper"],
    commands: [
      { label: "List contents", cmd: "unzip -l {FILE}" },
      { label: "Crack password", cmd: "fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u {FILE}" },
      { label: "John zip2john", cmd: "zip2john {FILE} > zip_hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt" },
      { label: "Known plaintext", cmd: "pkcrack -C encrypted.zip -c known.txt -P plain.zip -p known.txt -d decrypted.zip" },
      { label: "Nested ZIPs", cmd: "while file *.zip 2>/dev/null | grep -q Zip; do unzip -o *.zip && rm *.zip; done" }
    ]
  },
  {
    title: "pdfcrack - PDF Password Cracking",
    description: "Brute force or dictionary attack on password-protected PDF files",
    analysis: "PDF owner password (print/copy restriction) is trivial to remove — use qpdf or online tools. User password (open) requires cracking.\npdfcrack is slow — for large wordlists, use pdf2john + hashcat (GPU-accelerated) instead.\nTry empty password first, then common passwords: password, 123456, the challenge name.\nOlder PDF encryption (40-bit RC4) is very weak and cracks in seconds. Check PDF version with pdfinfo.",
    category: ["File Analysis", "Crypto/Encoding"],
    phase: ["Recovery"],
    os: ["Linux"],
    tools: ["pdfcrack"],
    commands: [
      { label: "Dictionary attack", cmd: "pdfcrack -f {FILE} -w /usr/share/wordlists/rockyou.txt" },
      { label: "Brute force (4 chars)", cmd: "pdfcrack -f {FILE} -n 4 -m 4" },
      { label: "Charset brute force", cmd: "pdfcrack -f {FILE} -c abcdefghijklmnopqrstuvwxyz0123456789" },
      { label: "pdf2john alternative", cmd: "pdf2john.pl {FILE} > pdf_hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt pdf_hash.txt" }
    ]
  },

  // ==================== DISK FORENSICS ====================
  {
    title: "dd - Create Disk Image",
    description: "Create a raw bit-for-bit copy of a disk or partition",
    analysis: "Always hash the source device BEFORE imaging and compare with the image hash AFTER.\nUse bs=4M or bs=64K for performance — bs=512 is forensically correct but extremely slow.\nIf source has bad sectors, use 'dcfldd' or 'dc3dd' instead — dd halts on errors by default.\nAdd conv=noerror,sync to skip bad sectors and pad with zeros (but prefer dc3dd for this).",
    category: ["Disk"],
    phase: ["Acquisition"],
    os: ["Linux"],
    tools: ["dd"],
    commands: [
      { label: "Basic image", cmd: "dd if=/dev/sda of={IMAGE} bs=4M status=progress" },
      { label: "With hash", cmd: "dd if=/dev/sda bs=4M status=progress | tee {IMAGE} | sha256sum > image.sha256" },
      { label: "Compressed", cmd: "dd if=/dev/sda bs=4M status=progress | gzip > {IMAGE}.gz" }
    ]
  },
  {
    title: "dc3dd - Forensic Imaging",
    description: "Forensically-sound imaging with built-in hashing",
    analysis: "dc3dd is preferred over dd for forensics — built-in hashing, error handling, and logging.\nThe log file documents the acquisition process for chain of custody. Always save it.\nSplit images are easier to transport and store on FAT32 media (4GB limit per file).\nVerify the hash in the log matches a separate hash of the output image.",
    category: ["Disk"],
    phase: ["Acquisition"],
    os: ["Linux"],
    tools: ["dc3dd"],
    commands: [
      { label: "Image + hash", cmd: "dc3dd if=/dev/sda of={IMAGE} hash=sha256 log=imaging.log" },
      { label: "Split image", cmd: "dc3dd if=/dev/sda ofs={IMAGE}.split ofsz=2G hash=sha256" }
    ]
  },
  {
    title: "dcfldd - Forensic Imaging (Enhanced dd)",
    description: "Enhanced dd with built-in hashing, progress, and verification",
    analysis: "dcfldd hashes on-the-fly during imaging — no need for separate hash step, saves time.\nUse the verify option to confirm the image matches the source in a single pass.\nThe hashlog is your chain of custody documentation — preserve it with the image.\nFor wiping: the wipe command with hash verification proves the drive was zeroed (for decommissioning).",
    category: ["Disk"],
    phase: ["Acquisition"],
    os: ["Linux"],
    tools: ["dcfldd"],
    commands: [
      { label: "Image + MD5", cmd: "dcfldd if=/dev/sda of={IMAGE} hash=md5 hashlog=hash.log" },
      { label: "Image + SHA256", cmd: "dcfldd if=/dev/sda of={IMAGE} hash=sha256 hashlog=hash.log" },
      { label: "Split output", cmd: "dcfldd if=/dev/sda of={IMAGE}.split splitformat=000 split=2G hash=sha256" },
      { label: "Verify image", cmd: "dcfldd if=/dev/sda vf={IMAGE} verifylog=verify.log" },
      { label: "Wipe drive", cmd: "dcfldd if=/dev/zero of=/dev/sda hash=sha256 hashlog=wipe_verify.log" }
    ]
  },
  {
    title: "Mount Forensic Images",
    description: "Mount forensic disk images (raw, E01, VMDK) for analysis in read-only mode",
    analysis: "ALWAYS mount read-only (ro) to preserve evidence integrity. Never mount without ro flag.\nThe offset for raw images = sector size (usually 512) x partition start sector. Get start sector from mmls or fdisk -l.\nE01 images must be mounted via ewfmount first (creates a raw device), then loop-mount the raw device.\nIf mount fails with wrong fs type, try specifying -t ntfs, -t ext4, etc. Use 'file' on the image to detect filesystem.",
    category: ["Disk"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["mount", "ewfmount", "qemu-nbd", "guestmount"],
    commands: [
      { label: "Raw image", cmd: "mount -o ro,loop,offset=$((512*{SECTOR})) {IMAGE} /mnt/evidence" },
      { label: "EWF (E01)", cmd: "ewfmount {IMAGE} /mnt/ewf && mount -o ro,loop /mnt/ewf/ewf1 /mnt/evidence" },
      { label: "VMDK (qemu-nbd)", cmd: "modprobe nbd max_part=8 && qemu-nbd --read-only -c /dev/nbd0 {IMAGE} && mount -o ro /dev/nbd0p1 /mnt/evidence" },
      { label: "VMDK (guestmount)", cmd: "guestmount -a {IMAGE} -m /dev/sda1 --ro /mnt/evidence" },
      { label: "VMDK note", cmd: "# Plain VMDK cannot be loop-mounted directly; use qemu-nbd, guestmount, or convert with qemu-img convert -f vmdk -O raw image.raw" },
      { label: "Unmount (raw/E01)", cmd: "umount /mnt/evidence" },
      { label: "Unmount (qemu-nbd)", cmd: "umount /mnt/evidence && qemu-nbd -d /dev/nbd0" }
    ]
  },
  {
    title: "Sleuth Kit - File System Analysis",
    description: "Analyze file systems, list files, view metadata",
    analysis: "mmls shows partition layout — note the Start offset for each partition (use as -o value in other commands).\nfls -d shows ONLY deleted files — these are your recovery targets. Note the inode number for extraction with icat.\nDeleted file with intact inode = recoverable with icat. Overwritten inode = need file carving instead.\nistat shows MAC timestamps (Modified/Accessed/Changed) — compare against incident timeline. Look for timestamp anomalies (timestomping).",
    category: ["Disk"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["Sleuth Kit"],
    commands: [
      { label: "Image info", cmd: "mmls {IMAGE}" },
      { label: "File system info", cmd: "fsstat -o {OFFSET} {IMAGE}" },
      { label: "List files", cmd: "fls -r -o {OFFSET} {IMAGE}" },
      { label: "List deleted files", cmd: "fls -r -d -o {OFFSET} {IMAGE}" },
      { label: "View file content", cmd: "icat -o {OFFSET} {IMAGE} {INODE}" },
      { label: "File metadata", cmd: "istat -o {OFFSET} {IMAGE} {INODE}" }
    ]
  },
  {
    title: "Windows MFT Analysis",
    description: "Parse NTFS Master File Table for file metadata, timestamps, and timeline analysis",
    analysis: "MFT has two sets of timestamps: $STANDARD_INFORMATION (easily modified by timestomping tools) and $FILE_NAME (harder to fake).\nIf $SI timestamps differ significantly from $FN timestamps, timestomping has occurred — a strong indicator of anti-forensics.\nLook for files with $SI Created > $SI Modified (impossible normally) = timestomping.\nSort by creation date during the incident window to find attacker-dropped files. Small files in System32 or temp folders are suspicious.",
    category: ["Disk"],
    phase: ["Analysis", "Timeline"],
    os: ["Windows", "Linux"],
    tools: ["MFTECmd", "analyzeMFT"],
    commands: [
      { label: "MFTECmd", cmd: "MFTECmd.exe -f \\$MFT --csv output/" },
      { label: "analyzeMFT", cmd: "analyzeMFT.py -f \\$MFT -o mft_output.csv" },
      { label: "Extract MFT (Linux)", cmd: "icat -o {OFFSET} {IMAGE} 0 > extracted_MFT" }
    ]
  },
  {
    title: "NTFS Alternate Data Streams (ADS)",
    description: "Detect and extract hidden data in NTFS Alternate Data Streams",
    analysis: "ADS is a classic data hiding technique — malware and CTF challenges use it to hide payloads in innocent-looking files.\nFiles with ADS have a normal size in Explorer but extra data attached via ':streamname' syntax.\nZone.Identifier ADS is normal (tracks download origin). Any other stream name is suspicious.\nLook for executable content in ADS — attackers hide scripts/PE files this way. Check with 'more < file:stream' or PowerShell.",
    category: ["Disk"],
    phase: ["Analysis"],
    os: ["Windows", "Linux"],
    tools: ["Sleuth Kit", "streams"],
    commands: [
      { label: "List ADS (Windows)", cmd: "dir /r C:\\path\\to\\file" },
      { label: "Read ADS (Windows)", cmd: "more < file.txt:hidden_stream" },
      { label: "PowerShell list ADS", cmd: "Get-Item file.txt -Stream * | Format-Table Stream, Length" },
      { label: "PowerShell read ADS", cmd: "Get-Content file.txt -Stream hidden_stream" },
      { label: "Sysinternals streams", cmd: "streams.exe -s C:\\path\\" },
      { label: "Sleuth Kit (Linux)", cmd: "fls -r -o {OFFSET} {IMAGE} | grep -i 'ads'" },
      { label: "icat extract ADS", cmd: "icat -o {OFFSET} {IMAGE} {INODE}:{ADS_NAME} > extracted_ads" }
    ]
  },
  {
    title: "Windows Recycle Bin",
    description: "Recover and analyze files from the Windows Recycle Bin",
    analysis: "$I files contain metadata: original path, deletion timestamp, file size. $R files contain the actual deleted data.\nMatch $I and $R files by their suffix (e.g., $IABCDEF and $RABCDEF are a pair).\nThe SID folder name under $Recycle.Bin identifies which user deleted the file.\nRecycle Bin emptied? The $I/$R files may still be recoverable from unallocated space with file carving.",
    category: ["Disk"],
    phase: ["Recovery"],
    os: ["Windows"],
    tools: ["RBCmd"],
    commands: [
      { label: "Parse $I files", cmd: "RBCmd.exe -d \"C:\\$Recycle.Bin\" --csv output/" },
      { label: "Manual (Linux)", cmd: "find /mnt/evidence/\\$Recycle.Bin -name '\\$I*' -exec xxd {} \\;" }
    ]
  },

  // ==================== MEMORY FORENSICS ====================
  {
    title: "Volatility3 - Memory Forensics",
    description: "Comprehensive memory analysis framework — process listing, network connections, registry, malware detection, credential extraction, file carving, and timeline generation",
    analysis: "Processes: svchost.exe must be child of services.exe and in System32. cmd.exe/powershell spawned by Office apps = macro exploit. Multiple lsass.exe = credential dumping.\nNetwork: connections to external IPs from svchost/explorer = C2. Unusual ports (4444, 8080, 1337). Connections from dead processes = injected code.\nMalfind: MZ headers in RWX memory regions = injected PE. VAD tag VadS with execute permissions = code injection.\nRegistry: Run keys pointing to temp/appdata = persistence. Check timestamps against incident timeline.\nCredentials: hashdump gives SAM hashes (crack with hashcat -m 1000). lsadump may reveal cleartext passwords.",
    category: ["Memory", "Network", "Registry", "Malware"],
    phase: ["Triage", "Analysis", "Recovery", "Carving", "Timeline"],
    os: ["Windows", "Linux", "macOS"],
    tools: ["Volatility3", "strings"],
    commands: [
      { label: "Image info (Win)", cmd: "vol -f {DUMP_FILE} windows.info" },
      { label: "Image info (Linux)", cmd: "vol -f {DUMP_FILE} linux.info" },
      { label: "Image info (macOS)", cmd: "vol -f {DUMP_FILE} mac.info" },
      { label: "Process list", cmd: "vol -f {DUMP_FILE} windows.pslist" },
      { label: "Process tree", cmd: "vol -f {DUMP_FILE} windows.pstree" },
      { label: "Process list (Linux)", cmd: "vol -f {DUMP_FILE} linux.pslist" },
      { label: "Hidden processes", cmd: "vol -f {DUMP_FILE} windows.psscan" },
      { label: "Network (netscan)", cmd: "vol -f {DUMP_FILE} windows.netscan" },
      { label: "Network (netstat)", cmd: "vol -f {DUMP_FILE} windows.netstat" },
      { label: "Network (Linux)", cmd: "vol -f {DUMP_FILE} linux.sockstat" },
      { label: "Command line args", cmd: "vol -f {DUMP_FILE} windows.cmdline" },
      { label: "DLL list", cmd: "vol -f {DUMP_FILE} windows.dlllist" },
      { label: "DLL list (PID)", cmd: "vol -f {DUMP_FILE} windows.dlllist --pid {PID}" },
      { label: "Dump process (Win)", cmd: "vol -f {DUMP_FILE} windows.memmap --dump --pid {PID}" },
      { label: "Dump files (Win)", cmd: "vol -f {DUMP_FILE} windows.dumpfiles --pid {PID}" },
      { label: "Dump process (Linux)", cmd: "vol -f {DUMP_FILE} linux.proc.maps --dump --pid {PID}" },
      { label: "Registry hives", cmd: "vol -f {DUMP_FILE} windows.registry.hivelist" },
      { label: "Registry key", cmd: "vol -f {DUMP_FILE} windows.registry.printkey --key \"Software\\Microsoft\\Windows\\CurrentVersion\\Run\"" },
      { label: "Dump hive", cmd: "vol -f {DUMP_FILE} windows.registry.hivelist --dump" },
      { label: "Malfind (all)", cmd: "vol -f {DUMP_FILE} windows.malfind" },
      { label: "Malfind (PID)", cmd: "vol -f {DUMP_FILE} windows.malfind --pid {PID}" },
      { label: "Handles (all)", cmd: "vol -f {DUMP_FILE} windows.handles" },
      { label: "Handles (PID)", cmd: "vol -f {DUMP_FILE} windows.handles --pid {PID}" },
      { label: "SSDT hooks", cmd: "vol -f {DUMP_FILE} windows.ssdt" },
      { label: "Extract strings", cmd: "strings -a -t d {DUMP_FILE} > strings.txt" },
      { label: "Unicode strings", cmd: "strings -a -t d -el {DUMP_FILE} >> strings.txt" },
      { label: "Map strings to PIDs", cmd: "vol -f {DUMP_FILE} windows.strings --strings-file strings.txt" },
      { label: "Hashdump", cmd: "vol -f {DUMP_FILE} windows.hashdump" },
      { label: "LSA dump", cmd: "vol -f {DUMP_FILE} windows.lsadump" },
      { label: "Cached creds", cmd: "vol -f {DUMP_FILE} windows.cachedump" },
      { label: "Filescan", cmd: "vol -f {DUMP_FILE} windows.filescan" },
      { label: "Filescan (filter)", cmd: "vol -f {DUMP_FILE} windows.filescan | grep -i 'secret'" },
      { label: "Dump file by addr", cmd: "vol -f {DUMP_FILE} windows.dumpfiles --virtaddr {OFFSET}" },
      { label: "Timeline", cmd: "vol -f {DUMP_FILE} timeliner.Timeliner" }
    ],
    references: ["https://volatility3.readthedocs.io"]
  },
  {
    title: "Volatility2 - Memory Forensics (Legacy)",
    description: "Legacy memory analysis framework — requires profile detection first. Note: connections/sockets plugins are XP/2003 only, use netscan for Vista+",
    analysis: "Run imageinfo first — try ALL suggested profiles if one does not work. kdbgscan is more reliable for profile detection.\nSet VOLATILITY_PROFILE and VOLATILITY_LOCATION env vars to avoid retyping on every command.\npsscan finds processes that pslist misses — compare both outputs. Processes only in psscan = hidden/unlinked (rootkit behavior).\nmalprocfind checks for common process anomalies automatically — good quick triage step.\nFor hibernation files: convert hiberfil.sys to raw first, then analyze normally.",
    category: ["Memory", "Network", "Malware"],
    phase: ["Triage", "Analysis", "Recovery"],
    os: ["Windows", "Linux"],
    tools: ["Volatility2"],
    commands: [
      { label: "Image info", cmd: "volatility -f {DUMP_FILE} imageinfo" },
      { label: "Kernel debugger scan", cmd: "volatility -f {DUMP_FILE} kdbgscan" },
      { label: "Set env vars", cmd: "export VOLATILITY_PROFILE=Win7SP1x64 && export VOLATILITY_LOCATION=file://{DUMP_FILE}" },
      { label: "Netscan (Vista+)", cmd: "volatility -f {DUMP_FILE} --profile={PROFILE} netscan" },
      { label: "Psscan", cmd: "volatility -f {DUMP_FILE} --profile={PROFILE} psscan" },
      { label: "Pstree", cmd: "volatility -f {DUMP_FILE} --profile={PROFILE} pstree" },
      { label: "Malprocfind", cmd: "volatility -f {DUMP_FILE} --profile={PROFILE} malprocfind" },
      { label: "DLL list (PID)", cmd: "volatility -f {DUMP_FILE} --profile={PROFILE} dlllist -p {PID}" },
      { label: "Handles (PID)", cmd: "volatility -f {DUMP_FILE} --profile={PROFILE} handles -p {PID}" },
      { label: "Handles - keys", cmd: "volatility -f {DUMP_FILE} --profile={PROFILE} handles -p {PID} -t Key" },
      { label: "Handles - files", cmd: "volatility -f {DUMP_FILE} --profile={PROFILE} handles -p {PID} -t File" },
      { label: "Get SIDs", cmd: "volatility -f {DUMP_FILE} --profile={PROFILE} getsids -p {PID}" },
      { label: "Filescan", cmd: "volatility -f {DUMP_FILE} --profile={PROFILE} filescan" },
      { label: "Dump file by name", cmd: "volatility -f {DUMP_FILE} --profile={PROFILE} dumpfiles -n -r {FILE} --dump-dir=./" },
      { label: "Hibernation convert", cmd: "volatility -f hiberfile.sys --profile={PROFILE} imagecopy -O hibermemory.raw" }
    ]
  },

  // ==================== NETWORK FORENSICS ====================
  {
    title: "tcpdump - Packet Capture",
    description: "Capture and filter network traffic from the command line",
    analysis: "Use -nn to disable name resolution for faster output and to see raw IPs/ports.\nASCII dump (-A) is great for spotting HTTP credentials, cookies, and plaintext protocols.\nLarge PCAPs? Filter during capture (host, port, net) to keep file size manageable.\nCapture on 'any' interface if unsure which interface carries the traffic. Use -c to limit packet count.",
    category: ["Network"],
    phase: ["Acquisition"],
    os: ["Linux", "macOS"],
    tools: ["tcpdump"],
    commands: [
      { label: "Capture all", cmd: "tcpdump -i eth0 -w {PCAP}" },
      { label: "Filter host", cmd: "tcpdump -i eth0 host {TARGET_IP} -w {PCAP}" },
      { label: "Filter port", cmd: "tcpdump -i eth0 port 80 -w {PCAP}" },
      { label: "Read pcap", cmd: "tcpdump -r {PCAP} -nn" },
      { label: "ASCII dump", cmd: "tcpdump -r {PCAP} -A | head -200" }
    ]
  },
  {
    title: "Wireshark - Display Filters",
    description: "Common Wireshark display filters for traffic analysis",
    analysis: "Start with Statistics > Conversations and Statistics > Protocol Hierarchy to get a big-picture view.\nFollow TCP Stream (right-click > Follow) to read full conversations — HTTP requests, FTP sessions, SMTP emails.\nTLS handshake type 1 (Client Hello) reveals SNI hostname even in encrypted traffic.\nFTP credentials are plaintext — filter for USER/PASS. HTTP POST bodies contain form submissions including login credentials.\nLook for DNS queries to unusual TLDs or very long subdomains = possible DNS exfiltration/C2.",
    category: ["Network"],
    phase: ["Analysis"],
    os: ["Windows", "Linux", "macOS"],
    tools: ["Wireshark"],
    commands: [
      { label: "Filter by IP", cmd: "ip.addr == {TARGET_IP}" },
      { label: "HTTP requests", cmd: "http.request" },
      { label: "DNS queries", cmd: "dns.qry.name contains \"example\"" },
      { label: "TCP SYN only", cmd: "tcp.flags.syn == 1 && tcp.flags.ack == 0" },
      { label: "Follow TCP stream", cmd: "tcp.stream eq {STREAM_NUM}" },
      { label: "Exclude noise", cmd: "!(arp || icmp || dns || stp)" },
      { label: "HTTP POST data", cmd: "http.request.method == POST" },
      { label: "TLS handshake", cmd: "tls.handshake.type == 1" },
      { label: "FTP credentials", cmd: "ftp.request.command == USER || ftp.request.command == PASS" }
    ]
  },
  {
    title: "tshark - CLI Packet Analysis",
    description: "Command-line Wireshark for scripting and automation",
    analysis: "Use -T fields -e to extract specific fields — much easier to parse than full packet output.\nExport objects (--export-objects) recovers transferred files from HTTP, SMB, DICOM, IMF, TFTP protocols.\nConversations (-z conv,tcp) reveals who talked to whom and how much data was transferred — spot large transfers or unusual pairs.\nPipe tshark output to sort/uniq/awk for quick statistics. DNS unique queries reveal domains the host contacted.",
    category: ["Network"],
    phase: ["Analysis"],
    os: ["Linux", "macOS"],
    tools: ["tshark"],
    commands: [
      { label: "Read pcap", cmd: "tshark -r {PCAP}" },
      { label: "Filter + fields", cmd: "tshark -r {PCAP} -Y 'http.request' -T fields -e http.host -e http.request.uri" },
      { label: "DNS queries", cmd: "tshark -r {PCAP} -Y 'dns.qry.name' -T fields -e dns.qry.name | sort -u" },
      { label: "Extract files", cmd: "tshark -r {PCAP} --export-objects http,exported_files/" },
      { label: "Conversations", cmd: "tshark -r {PCAP} -z conv,tcp -q" },
      { label: "Statistics", cmd: "tshark -r {PCAP} -z io,stat,1 -q" }
    ]
  },
  {
    title: "tcpflow - TCP Stream Reconstruction",
    description: "Reconstruct TCP sessions and extract transferred files from PCAP",
    analysis: "tcpflow creates one file per TCP stream — each file is the raw data transferred in one direction.\nLook at output filenames: they contain IP:port pairs showing source and destination.\nRun 'file' on each output file to identify transferred content (images, archives, executables).\nHTTP mode (-e http) separates HTTP headers from body content, making file extraction easier.",
    category: ["Network"],
    phase: ["Analysis", "Carving"],
    os: ["Linux"],
    tools: ["tcpflow"],
    commands: [
      { label: "Extract all streams", cmd: "tcpflow -r {PCAP} -o output/" },
      { label: "Filter by host", cmd: "tcpflow -r {PCAP} -o output/ host {TARGET_IP}" },
      { label: "Filter by port", cmd: "tcpflow -r {PCAP} -o output/ port 80" },
      { label: "Verbose + timestamps", cmd: "tcpflow -r {PCAP} -o output/ -T'%Y-%m-%dT%H:%M:%S'" },
      { label: "Color console output", cmd: "tcpflow -r {PCAP} -c -e http" }
    ]
  },
  {
    title: "editcap / mergecap - PCAP Manipulation",
    description: "Convert, split, merge, and manipulate PCAP/PCAPNG files",
    analysis: "Convert PCAPNG to PCAP if older tools do not support PCAPNG format.\nTime slicing isolates traffic during an incident window — reduces noise significantly.\nDuplicate removal (-d) is useful when captures overlap from multiple sensors.\nSplit large PCAPs by packet count for parallel analysis across team members.",
    category: ["Network"],
    phase: ["Analysis"],
    os: ["Linux", "macOS"],
    tools: ["editcap", "mergecap"],
    commands: [
      { label: "PCAPNG to PCAP", cmd: "editcap -F pcap {PCAP} output.pcap" },
      { label: "PCAP to PCAPNG", cmd: "editcap -F pcapng {PCAP} output.pcapng" },
      { label: "Time slice", cmd: "editcap -A '2024-01-01 00:00:00' -B '2024-01-02 00:00:00' {PCAP} sliced.pcap" },
      { label: "Split by count", cmd: "editcap -c 10000 {PCAP} split.pcap" },
      { label: "Merge PCAPs", cmd: "mergecap -w merged.pcap file1.pcap file2.pcap" },
      { label: "Remove duplicates", cmd: "editcap -d {PCAP} deduped.pcap" }
    ]
  },
  {
    title: "USB Keystroke Extraction from PCAP",
    description: "Extract keystrokes from USB HID keyboard captures (very common CTF challenge)",
    analysis: "USB HID data is 8 bytes: byte[0]=modifier (shift/ctrl/alt), byte[2]=keycode. Byte[2]==0 means no key pressed (skip).\nIf usb.capdata gives no results, try usbhid.data instead — different Wireshark/tshark versions use different field names.\nModifier byte 0x02 or 0x20 = Shift held (uppercase letter). 0x01 or 0x10 = Ctrl held.\nThe decode script may miss special characters — check the USB HID usage table for keys not in the mapping (backspace=0x2a, tab=0x2b, enter=0x28).",
    category: ["Network"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["tshark", "Python"],
    commands: [
      { label: "Extract HID data", cmd: "tshark -r {PCAP} -T fields -e usb.capdata -Y 'usb.capdata && usb.data_len == 8' > keystrokes.txt" },
      { label: "Alt: usbhid.data", cmd: "tshark -r {PCAP} -T fields -e usbhid.data -Y 'usbhid.data && usb.data_len == 8' > keystrokes.txt" },
      { label: "Decode script", cmd: "python3 -c \"\nUSB_KEYS = {4:'a',5:'b',6:'c',7:'d',8:'e',9:'f',10:'g',11:'h',12:'i',13:'j',14:'k',15:'l',16:'m',17:'n',18:'o',19:'p',20:'q',21:'r',22:'s',23:'t',24:'u',25:'v',26:'w',27:'x',28:'y',29:'z',30:'1',31:'2',32:'3',33:'4',34:'5',35:'6',36:'7',37:'8',38:'9',39:'0',40:'\\\\n',44:' ',45:'-',46:'=',47:'[',48:']'}\nwith open('keystrokes.txt') as f:\n  for line in f:\n    bytez = bytes.fromhex(line.strip().replace(':',''))\n    if bytez[2] != 0:\n      key = USB_KEYS.get(bytez[2], '?')\n      if bytez[0] & 0x22: key = key.upper()  # shift\n      print(key, end='')\"" }
    ]
  },
  {
    title: "Wireshark - TLS Decryption",
    description: "Decrypt TLS/HTTPS traffic in Wireshark using pre-master secret log or private key",
    analysis: "SSLKEYLOGFILE method works with any cipher suite including ECDHE (which private key method cannot decrypt).\nPrivate key method ONLY works with RSA key exchange (no PFS). Most modern traffic uses ECDHE, so this often fails.\nIn CTF: if you get a .pem/.key file with a PCAP, check if the traffic uses RSA key exchange. If ECDHE, look for a keylog file.\nAfter loading keys, filter 'http' to see the decrypted HTTP traffic inside what was TLS.",
    category: ["Network"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["Wireshark", "tshark"],
    commands: [
      { label: "With SSLKEYLOG", cmd: "# Set env: SSLKEYLOGFILE=/tmp/keys.log then browse. In Wireshark: Edit > Preferences > Protocols > TLS > Pre-Master-Secret log: /tmp/keys.log" },
      { label: "tshark with keylog", cmd: "tshark -r {PCAP} -o tls.keylog_file:/tmp/keys.log -Y http" },
      { label: "With private key", cmd: "# Edit > Preferences > Protocols > TLS > RSA keys list: IP,port,protocol,keyfile.pem" }
    ]
  },

  // ==================== STEGANOGRAPHY ====================
  {
    title: "Stego Workflow - Image Analysis Order",
    description: "Recommended order for analyzing images in CTF stego challenges",
    analysis: "Follow this order strictly — do not jump to brute force before checking basics. Most CTF stego flags are found in steps 1-6.\nIf pngcheck shows CRC errors, the image dimensions may be wrong — common CTF trick. Fix width/height and re-render.\nzsteg is PNG/BMP only. steghide is JPEG/BMP only. Do not mix them up.\nIf all tools fail, try aperisolve.fr — it runs multiple tools and shows results in one page.\nLook at the image visually — sometimes the flag is literally written in the image but hard to see (low contrast, tiny font).",
    category: ["Stego"],
    phase: ["Triage"],
    os: ["Linux"],
    tools: ["file", "exiftool", "strings", "binwalk", "pngcheck", "zsteg", "steghide", "stegsolve", "stegcracker"],
    commands: [
      { label: "1. File type", cmd: "file {FILE}" },
      { label: "2. Metadata", cmd: "exiftool {FILE}" },
      { label: "3. Strings", cmd: "strings {FILE} | grep -iE 'flag|ctf|key|pass'" },
      { label: "4. Embedded files", cmd: "binwalk {FILE}" },
      { label: "5. PNG check", cmd: "pngcheck -v {FILE}" },
      { label: "6. LSB (PNG/BMP)", cmd: "zsteg {FILE}" },
      { label: "7. JPEG stego", cmd: "steghide info {FILE}" },
      { label: "8. Visual analysis", cmd: "java -jar stegsolve.jar" },
      { label: "9. Brute force", cmd: "stegcracker {FILE} /usr/share/wordlists/rockyou.txt" },
      { label: "10. Online", cmd: "# https://aperisolve.fr" }
    ]
  },
  {
    title: "steghide - JPEG/BMP Stego",
    description: "Embed or extract hidden data in JPEG and BMP images",
    analysis: "If 'steghide info' shows embedded data but no passphrase works, try empty passphrase first. Common CTF passwords: password, secret, hidden, the challenge name/title.\nFile size much larger than visual content suggests = hidden data. Compare file size to similar resolution clean JPEG.\nsteghide only works with JPEG and BMP — it will fail silently on PNG. Use zsteg for PNG.\nIf extraction gives binary data, check it with 'file' — it could be another image, ZIP, or encoded text.",
    category: ["Stego"],
    phase: ["Analysis", "Recovery"],
    os: ["Linux"],
    tools: ["steghide"],
    commands: [
      { label: "Extract (with pass)", cmd: "steghide extract -sf {FILE} -p {PASSWORD}" },
      { label: "Extract (no pass)", cmd: "steghide extract -sf {FILE}" },
      { label: "Info", cmd: "steghide info {FILE}" },
      { label: "Embed", cmd: "steghide embed -cf cover.jpg -ef secret.txt -p {PASSWORD}" }
    ]
  },
  {
    title: "zsteg - PNG/BMP LSB Stego",
    description: "Detect LSB steganography in PNG and BMP files",
    analysis: "Run 'zsteg' first (default) — it checks the most common LSB configurations. Use -a for exhaustive check.\nLook for 'text' or 'file' results in the output — those indicate detected hidden data.\nCommon LSB hiding: b1,rgb,lsb (1 bit, RGB channels, least significant bit) is the default for most stego tools.\nIf zsteg finds partial text, try different bit/channel combinations. 'b1,r,lsb' = red channel only, 'b2,rgb,lsb' = 2nd bit.",
    category: ["Stego"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["zsteg"],
    commands: [
      { label: "Auto detect", cmd: "zsteg {FILE}" },
      { label: "All channels", cmd: "zsteg -a {FILE}" },
      { label: "Specific bits", cmd: "zsteg -b 1 {FILE}" },
      { label: "Extract", cmd: "zsteg -E \"b1,rgb,lsb\" {FILE} > extracted.bin" }
    ]
  },
  {
    title: "pngcheck - PNG Integrity",
    description: "Check PNG file integrity, detect corrupted headers, wrong CRC, and modified dimensions",
    analysis: "CRC FAILED = image dimensions were modified. This is a classic CTF trick — the real image is taller/wider but the header says otherwise.\nTo fix: calculate correct CRC for IHDR chunk, or brute-force width/height until CRC matches.\nIf the image looks cut off or has a colored bar at the bottom, the height was reduced — increase it to reveal hidden content.\nOther errors (invalid chunk, bad deflate) may indicate appended data after IEND or corrupted structure.",
    category: ["Stego", "File Analysis"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["pngcheck", "Python"],
    commands: [
      { label: "Validate", cmd: "pngcheck -v {FILE}" },
      { label: "Fix CRC (Python)", cmd: "python3 -c \"import struct,zlib;d=open('{FILE}','rb').read();print('CRC check:',hex(zlib.crc32(d[12:29])))\"" }
    ]
  },
  {
    title: "stegcracker - Brute Force Stego Passwords",
    description: "Brute force steghide passphrases using a wordlist",
    analysis: "stegcracker uses steghide under the hood — it only works on JPEG and BMP files.\nrockyou.txt has 14 million passwords. If it fails, try smaller targeted wordlists based on challenge context.\nVery slow compared to hashcat — there is no GPU acceleration for steghide. Consider limiting wordlist size.\nIf stegcracker finds nothing, the data may not be steghide-embedded — try jsteg, openstego, or outguess instead.",
    category: ["Stego"],
    phase: ["Recovery"],
    os: ["Linux"],
    tools: ["stegcracker"],
    commands: [
      { label: "Brute force", cmd: "stegcracker {FILE} /usr/share/wordlists/rockyou.txt" }
    ]
  },
  {
    title: "Least Significant Bit (LSB) Manual",
    description: "Manually extract LSB data using Python",
    analysis: "This script reads the LSB of the red channel only. Modify px[x,y][0] to [1] for green or [2] for blue.\nOutput will contain garbage after the hidden message — look for readable text at the start.\nSome challenges use MSB (most significant bit) instead of LSB, or use multiple bits per pixel.\nIf output is binary data, try converting groups of 8 bits to bytes and check with 'file'.\nRow-first vs column-first extraction order matters — try both if one gives garbage.",
    category: ["Stego"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["Python"],
    commands: [
      { label: "Python script", cmd: "python3 -c \"\nfrom PIL import Image\nim = Image.open('{FILE}')\npx = im.load()\nbits = ''\nfor y in range(im.height):\n  for x in range(im.width):\n    bits += str(px[x,y][0] & 1)\nprint(''.join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits),8)))\"" }
    ]
  },
  {
    title: "Sonic Visualiser - Audio Stego",
    description: "Analyze audio files visually for hidden spectrograms or data",
    analysis: "Add a spectrogram layer (Layer > Add Spectrogram) and look for visible text/images in the frequency domain.\nAdjust the color scheme and scale to make hidden spectrograms more visible. Try logarithmic vs linear scale.\nCommon CTF trick: flag is written as text visible in the spectrogram at certain frequencies.\nCheck multiple frequency ranges — hidden data may be above 16kHz (inaudible to humans but visible in spectrogram).\nAlso try: SSTV (slow-scan TV), morse code, DTMF tones — these require different decoders.",
    category: ["Stego"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["Sonic Visualiser"],
    commands: [
      { label: "Open file", cmd: "sonic-visualiser {FILE}" },
      { label: "Spectrogram (CLI)", cmd: "sox {FILE} -n spectrogram -o spectrogram.png" }
    ]
  },
  {
    title: "jsteg - JPEG Steganography",
    description: "Hide and reveal data in JPEG files using DCT coefficients (not detectable by steghide)",
    analysis: "jsteg uses a different algorithm than steghide — if steghide finds nothing, always try jsteg.\njsteg does NOT use a passphrase — data is either there or not. No brute forcing needed.\nOutput may be raw bytes — pipe through 'file' or 'strings' to identify content.\nDetection: jsteg modifies DCT coefficients, which is not visible to steghide's detection. Use stegdetect for statistical analysis.",
    category: ["Stego"],
    phase: ["Analysis", "Recovery"],
    os: ["Linux", "macOS"],
    tools: ["jsteg"],
    commands: [
      { label: "Reveal hidden data", cmd: "jsteg reveal {FILE} output.txt" },
      { label: "Hide data", cmd: "jsteg hide cover.jpg secret.txt stego.jpg" }
    ],
    references: ["https://github.com/lukechampine/jsteg"]
  },
  {
    title: "openstego - Image Steganography",
    description: "Java-based tool for embedding and extracting hidden data in images",
    analysis: "openstego uses its own algorithm — not compatible with steghide, zsteg, or jsteg. Try it if other tools fail.\nSupports PNG images (unlike steghide). Can also do digital watermarking.\nThe extract command needs no password by default, but embedding can use a password.\nIf you suspect openstego was used, the embedded data is typically in the LSB of the image with a custom header.",
    category: ["Stego"],
    phase: ["Analysis", "Recovery"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["openstego"],
    commands: [
      { label: "Extract data", cmd: "openstego extract -sf {FILE} -xd output/" },
      { label: "Embed data", cmd: "openstego embed -mf secret.txt -cf cover.png -sf stego.png" },
      { label: "GUI mode", cmd: "java -jar openstego.jar" }
    ],
    references: ["https://www.openstego.com/"]
  },
  {
    title: "zbarimg - QR Code / Barcode Scanner",
    description: "Decode QR codes and barcodes from image files (common in CTFs)",
    analysis: "If zbarimg fails, the QR code may be inverted (white on black instead of black on white) — invert colors first.\nPartially damaged QR codes can sometimes still be decoded due to error correction. Try different scanning tools.\nMultiple QR codes in one image? zbarimg will decode all of them. Check each result.\nQR code content may be a URL, base64, hex, or another encoding — decode further if it does not look like a flag directly.",
    category: ["Stego", "File Analysis"],
    phase: ["Analysis"],
    os: ["Linux", "macOS"],
    tools: ["zbar"],
    commands: [
      { label: "Decode QR/barcode", cmd: "zbarimg {FILE}" },
      { label: "Quiet (data only)", cmd: "zbarimg -q --raw {FILE}" },
      { label: "From screenshot", cmd: "zbarimg screenshot.png" },
      { label: "Python alternative", cmd: "python3 -c \"from pyzbar.pyzbar import decode; from PIL import Image; print(decode(Image.open('{FILE}')))\"" }
    ]
  },
  {
    title: "DTMF Tone Detection - Audio Forensics",
    description: "Decode DTMF (phone keypad) tones from audio files",
    analysis: "DTMF digits map to phone keypad: 0-9, *, #. The decoded digits might be a phone number, PIN, or encoded text.\nFor text encoding: use phone keypad mapping (2=ABC, 3=DEF, etc). Multiple presses select different letters.\nIf multimon-ng gives no results, the audio sample rate may be wrong — convert to 22050 Hz mono WAV first.\nLook for patterns: repeated digits = possible T9 encoding. Digits followed by pauses = phone number.",
    category: ["Stego"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["multimon-ng"],
    commands: [
      { label: "Decode DTMF", cmd: "multimon-ng -t wav -a DTMF {FILE}" },
      { label: "Convert to WAV first", cmd: "sox {FILE} -r 22050 -c 1 -t wav output.wav && multimon-ng -t wav -a DTMF output.wav" },
      { label: "Online tool", cmd: "# http://dialabc.com/sound/detect/" }
    ]
  },
  {
    title: "hipshot - Video Frame Steganography",
    description: "Extract hidden images from video files by compositing frames",
    analysis: "Extract all frames first, then examine individual frames — flags may appear in a single frame only.\nCompare consecutive frames: if only a few pixels differ between frames, those pixels may encode hidden data.\nCheck for steganography within individual extracted frames using image stego tools.\nSingle-frame extraction at specific timestamps is useful if you know when the hidden content appears.",
    category: ["Stego"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["hipshot", "ffmpeg"],
    commands: [
      { label: "Extract frames", cmd: "ffmpeg -i {FILE} -r 1 frames/frame_%04d.png" },
      { label: "hipshot composite", cmd: "hipshot {FILE}" },
      { label: "All frames fast", cmd: "ffmpeg -i {FILE} frames/frame_%04d.png" },
      { label: "Single frame", cmd: "ffmpeg -i {FILE} -ss 00:00:05 -frames:v 1 frame.png" }
    ]
  },

  // ==================== LOG ANALYSIS ====================
  {
    title: "Linux Auth Log Analysis",
    description: "Analyze authentication logs for suspicious activity",
    analysis: "Same IP with many 'Failed password' then 'Accepted' = successful brute force. sudo from unexpected user or for unusual commands.\nAccepted publickey for root from unknown IP = compromised SSH key. New cron jobs or authorized_keys during incident window.\nLook for failed logins for non-existent users = credential spraying. 'Invalid user' prefix indicates unknown username.\nMany failures from one IP in seconds = automated attack. Scattered failures across IPs = botnet or distributed brute force.",
    category: ["Logs"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["grep", "awk"],
    commands: [
      { label: "Failed logins", cmd: "grep 'Failed password' /var/log/auth.log | tail -20" },
      { label: "Successful logins", cmd: "grep 'Accepted' /var/log/auth.log | tail -20" },
      { label: "Failed by IP", cmd: "grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn" },
      { label: "SSH brute force", cmd: "grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head" },
      { label: "Sudo usage", cmd: "grep 'sudo' /var/log/auth.log" }
    ]
  },
  {
    title: "Windows Event Logs",
    description: "Parse, analyze, and search Windows Event Logs (.evtx) with key Event IDs for security investigations",
    analysis: "4624 Type 10 from unexpected IPs = RDP lateral movement. 4688 with encoded PowerShell (-enc base64) = malicious script execution.\n7045 new service from temp/appdata directory = persistence mechanism. 4720 followed by 4732 = attacker created and elevated account.\n1102 (audit log cleared) during incident window = anti-forensics. Gaps in event IDs = possible log tampering.\nCorrelate event timestamps across Security, System, and PowerShell logs to build a complete attack timeline.\nRDP session events (4778/4779) track reconnections — useful for tracking lateral movement sessions.",
    category: ["Logs"],
    phase: ["Analysis"],
    os: ["Windows", "Linux"],
    tools: ["evtx_dump", "python-evtx", "EvtxECmd"],
    commands: [
      { label: "Dump to XML", cmd: "evtx_dump.py Security.evtx > security.xml" },
      { label: "Logon events (4624)", cmd: "evtx_dump.py Security.evtx | grep -A 20 '<EventID>4624</EventID>'" },
      { label: "Failed logons (4625)", cmd: "evtx_dump.py Security.evtx | grep -A 20 '<EventID>4625</EventID>'" },
      { label: "New service (7045)", cmd: "evtx_dump.py System.evtx | grep -A 20 '<EventID>7045</EventID>'" },
      { label: "PowerShell (4104)", cmd: "evtx_dump.py 'Microsoft-Windows-PowerShell%4Operational.evtx' | grep -A 30 '<EventID>4104</EventID>'" },
      { label: "EvtxECmd (Zimmerman)", cmd: "EvtxECmd.exe -d C:\\Windows\\System32\\winevt\\Logs --csv output/" },
      { label: "RDP logons", cmd: "evtx_dump.py Security.evtx | grep -A 20 '<EventID>4624</EventID>' | grep -B5 -A15 'LogonType\">10'" },
      { label: "RDP session events", cmd: "# Event IDs: 4778 (session reconnected), 4779 (session disconnected)\nevtx_dump.py Security.evtx | grep -E '<EventID>(4778|4779)</EventID>'" },
      { label: "Network share access", cmd: "# Event ID 5140: Network share accessed\nevtx_dump.py Security.evtx | grep -A 20 '<EventID>5140</EventID>'" }
    ]
  },
  {
    title: "Apache/Nginx Access Log Analysis",
    description: "Analyze web server access logs for attacks and anomalies",
    analysis: "One IP with thousands of requests in minutes = scanner/bot. Check top IPs first for volume anomalies.\nSQLi indicators: UNION SELECT, OR 1=1, single quotes, hex encoding (0x), CONCAT, information_schema.\nXSS indicators: <script>, javascript:, onerror=, document.cookie in request URIs.\n404 bursts from one IP = directory brute forcing (gobuster/dirbuster). Check which paths they found (200 responses).\nLook for POST requests to unusual paths (webshells: /uploads/cmd.php, /wp-content/shell.php).\nStatus 500 errors may indicate successful exploitation attempts (server crashed processing malicious input).",
    category: ["Logs"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["grep", "awk"],
    commands: [
      { label: "Top IPs", cmd: "awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20" },
      { label: "Top URLs", cmd: "awk '{print $7}' access.log | sort | uniq -c | sort -rn | head -20" },
      { label: "SQLi attempts", cmd: "grep -iE \"(union|select|insert|update|delete|drop|exec|concat|0x)\" access.log" },
      { label: "XSS attempts", cmd: "grep -iE \"(<script|onerror|onload|alert\\(|document\\.cookie)\" access.log" },
      { label: "Status codes", cmd: "awk '{print $9}' access.log | sort | uniq -c | sort -rn" },
      { label: "404 scanning", cmd: "awk '$9 == 404 {print $7}' access.log | sort | uniq -c | sort -rn | head -20" }
    ]
  },
  {
    title: "plaso / log2timeline - Super Timeline",
    description: "Create a comprehensive forensic timeline from multiple sources using plaso/log2timeline",
    analysis: "Super timelines can be huge (millions of events). Always filter by date range and parser to reduce noise.\nFocus on the incident window: filter events from 1 hour before first indicator to 1 hour after last activity.\nKey parsers for Windows: winevtx, prefetch, mft, registry. These cover most IR needs.\nUse psort to exclude noisy parsers (filestat, pe) that generate many low-value events.\nTimeline CSV can be loaded into Timeline Explorer (Zimmerman) or Excel for pivoting and filtering.",
    category: ["Logs"],
    phase: ["Timeline"],
    os: ["Linux"],
    tools: ["plaso"],
    commands: [
      { label: "Create timeline", cmd: "log2timeline.py timeline.plaso {IMAGE}" },
      { label: "Docker run", cmd: "docker run --rm -v $(pwd):/data log2timeline/plaso log2timeline /data/timeline.plaso /data/{IMAGE}" },
      { label: "Filter & output CSV", cmd: "psort.py -o l2tcsv timeline.plaso > timeline.csv" },
      { label: "Date filter", cmd: "psort.py -o l2tcsv timeline.plaso \"date > '2024-01-01' AND date < '2024-02-01'\" > filtered.csv" },
      { label: "Filter parser", cmd: "log2timeline.py --parsers 'winevtx,prefetch,mft' timeline.plaso {IMAGE}" },
      { label: "Reduce noise", cmd: "psort.py -o l2tcsv timeline.plaso \"parser not in 'filestat,pe'\" > clean.csv" }
    ],
    references: ["https://plaso.readthedocs.io/"]
  },

  // ==================== WINDOWS FORENSICS ====================
  {
    title: "Windows Prefetch Analysis",
    description: "Analyze prefetch files to determine executed programs and timestamps",
    analysis: "Prefetch proves a program was executed. The filename includes an 8-character hash of the file path.\nLast execution time and run count show when and how often a program ran. Up to 8 last execution times on Win8+.\nFiles referenced by the prefetch entry reveal what the program accessed — DLLs, data files, config files.\nLook for: cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe, certutil.exe, bitsadmin.exe — common attacker LOLBins.\nAbsence of prefetch for a program that should have run = prefetch was deleted (anti-forensics).",
    category: ["Disk", "File Analysis"],
    phase: ["Analysis"],
    os: ["Windows"],
    tools: ["PECmd"],
    commands: [
      { label: "Parse single", cmd: "PECmd.exe -f C:\\Windows\\Prefetch\\CMD.EXE-*.pf" },
      { label: "Parse all", cmd: "PECmd.exe -d C:\\Windows\\Prefetch --csv output/" },
      { label: "Linux (python)", cmd: "python3 prefetch.py {FILE}" }
    ]
  },
  {
    title: "Registry Analysis Tools",
    description: "Extract forensic artifacts from offline Windows registry hives using RegRipper, RECmd, and regipy",
    analysis: "SAM hive: user accounts, login counts, last login timestamps, password hints. Parse with samparse plugin.\nSYSTEM hive: computer name, timezone, mounted devices, services (persistence). Critical for context.\nSOFTWARE hive: installed programs, OS version, network profiles. Check for unusual or recently installed software.\nNTUSER.DAT: per-user artifacts — Run keys, UserAssist (executed GUI apps with ROT13 names), RecentDocs, TypedPaths.\nRECmd with batch files processes all hives at once — much faster for initial triage than individual RegRipper plugins.",
    category: ["Registry"],
    phase: ["Analysis"],
    os: ["Windows", "Linux"],
    tools: ["RegRipper", "RECmd", "regipy"],
    commands: [
      { label: "RegRipper (SAM)", cmd: "regripper -r SAM -p samparse" },
      { label: "RegRipper (SYSTEM)", cmd: "regripper -r SYSTEM -p compname" },
      { label: "RegRipper (SOFTWARE)", cmd: "regripper -r SOFTWARE -p winver" },
      { label: "RegRipper (NTUSER)", cmd: "regripper -r NTUSER.DAT -p userassist" },
      { label: "RECmd (search)", cmd: "RECmd.exe -d C:\\path\\to\\hives --bn BatchExamples\\RECmd_Batch_MC.reb --csv output/" },
      { label: "RECmd (key lookup)", cmd: "RECmd.exe --hive NTUSER.DAT --kn \"Software\\Microsoft\\Windows\\CurrentVersion\\Run\"" },
      { label: "regipy", cmd: "registry-parse-header {FILE}" }
    ]
  },
  {
    title: "ShimCache / AppCompatCache",
    description: "Extract program execution evidence from ShimCache",
    analysis: "ShimCache records file path and last modified timestamp for executables that were LOOKED UP (not necessarily executed).\nHowever, presence in ShimCache is strong evidence of execution, especially combined with prefetch data.\nEntries are written on shutdown — recent activity may not appear until next reboot/shutdown.\nLook for executables in unusual locations: temp folders, user Downloads, Recycle Bin paths = suspicious.\nCorrelate ShimCache entries with prefetch and MFT timestamps for stronger execution evidence.",
    category: ["Registry"],
    phase: ["Analysis"],
    os: ["Windows"],
    tools: ["AppCompatCacheParser"],
    commands: [
      { label: "Parse", cmd: "AppCompatCacheParser.exe -f SYSTEM --csv output/" },
      { label: "From reg export", cmd: "AppCompatCacheParser.exe --csv output/" }
    ]
  },
  {
    title: "Windows - Key Forensic File Paths",
    description: "Important file locations for Windows forensic investigations",
    category: ["Disk", "Registry", "References"],
    phase: ["Analysis"],
    os: ["Windows"],
    tools: [],
    commands: [
      { label: "Registry Hives", cmd: "C:\\Windows\\System32\\config\\SAM\nC:\\Windows\\System32\\config\\SYSTEM\nC:\\Windows\\System32\\config\\SOFTWARE\nC:\\Windows\\System32\\config\\SECURITY\nC:\\Windows\\System32\\config\\DEFAULT" },
      { label: "User Registry", cmd: "C:\\Users\\<user>\\NTUSER.DAT\nC:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat" },
      { label: "Event Logs", cmd: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx\nC:\\Windows\\System32\\winevt\\Logs\\System.evtx\nC:\\Windows\\System32\\winevt\\Logs\\Application.evtx\nC:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx\nC:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx" },
      { label: "Prefetch", cmd: "C:\\Windows\\Prefetch\\*.pf" },
      { label: "Amcache", cmd: "C:\\Windows\\AppCompat\\Programs\\Amcache.hve" },
      { label: "Recent Files (LNK)", cmd: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\" },
      { label: "Jump Lists", cmd: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\\nC:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\" },
      { label: "Shellbags", cmd: "NTUSER.DAT: HKCU\\Software\\Microsoft\\Windows\\Shell\\\nUsrClass.dat: HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\" },
      { label: "Browser Data (Chrome)", cmd: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History\nC:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\nC:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies" },
      { label: "Browser Data (Firefox)", cmd: "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default\\places.sqlite\nC:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default\\logins.json" },
      { label: "Recycle Bin", cmd: "C:\\$Recycle.Bin\\<SID>\\$I*  (metadata)\nC:\\$Recycle.Bin\\<SID>\\$R*  (original file)" },
      { label: "SRUM", cmd: "C:\\Windows\\System32\\sru\\SRUDB.dat" },
      { label: "Startup Folders", cmd: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\\nC:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" },
      { label: "Scheduled Tasks", cmd: "C:\\Windows\\System32\\Tasks\\" },
      { label: "PowerShell History", cmd: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt" },
      { label: "RDP Cache", cmd: "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\" },
      { label: "Windows.old", cmd: "C:\\Windows.old\\  (previous OS installation)" },
      { label: "Pagefile / Hiberfil", cmd: "C:\\pagefile.sys\nC:\\hiberfil.sys\nC:\\swapfile.sys" },
      { label: "$MFT / $LogFile", cmd: "C:\\$MFT  (Master File Table)\nC:\\$LogFile  (NTFS journal)\nC:\\$UsnJrnl  (USN Change Journal at $Extend\\$UsnJrnl)" }
    ]
  },
  {
    title: "Windows - Important Event Log IDs",
    description: "Key Windows Event IDs for security investigations",
    category: ["Logs", "References"],
    phase: ["Analysis"],
    os: ["Windows"],
    tools: [],
    commands: [
      { label: "Logon/Logoff", cmd: "4624  Successful logon\n4625  Failed logon\n4634  Logoff\n4647  User-initiated logoff\n4648  Logon using explicit credentials (runas)\n4672  Special privileges assigned (admin logon)" },
      { label: "Account Management", cmd: "4720  User account created\n4722  User account enabled\n4724  Password reset attempt\n4725  User account disabled\n4726  User account deleted\n4732  Member added to security group\n4756  Member added to universal group" },
      { label: "Process / Service", cmd: "4688  New process created (requires audit policy)\n4689  Process exited\n7034  Service crashed unexpectedly\n7036  Service started or stopped\n7045  New service installed" },
      { label: "Object Access", cmd: "4663  Attempt to access object (file/reg)\n4656  Handle to object requested\n4658  Handle to object closed" },
      { label: "PowerShell", cmd: "4103  Module logging\n4104  Script block logging\n4105  Script started\n4106  Script completed" },
      { label: "Scheduled Tasks", cmd: "4698  Scheduled task created\n4699  Scheduled task deleted\n4702  Scheduled task updated" },
      { label: "Network / RDP", cmd: "4778  Session reconnected (RDP)\n4779  Session disconnected (RDP)\n5140  Network share accessed\n5156  Windows Firewall allowed connection" },
      { label: "Sysmon (if installed)", cmd: "1   Process creation\n3   Network connection\n7   Image loaded (DLL)\n8   CreateRemoteThread\n10  Process access\n11  File created\n13  Registry value set\n22  DNS query" }
    ]
  },
  {
    title: "Registry - Autostart / Persistence",
    description: "Registry keys commonly used for persistence and autostart programs",
    category: ["Registry", "Malware", "References"],
    phase: ["Analysis"],
    os: ["Windows"],
    tools: [],
    commands: [
      { label: "Run Keys", cmd: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nHKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\nHKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nHKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
      { label: "Run (WoW64)", cmd: "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\nHKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
      { label: "Services", cmd: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\" },
      { label: "Winlogon", cmd: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\nHKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" },
      { label: "Shell Extensions", cmd: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved\nHKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved" },
      { label: "AppInit_DLLs", cmd: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs" },
      { label: "Scheduled Tasks", cmd: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\\nHKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\" },
      { label: "Boot Execute", cmd: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute" },
      { label: "Image File Execution", cmd: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<exe>\\Debugger" }
    ]
  },
  {
    title: "Registry - User Activity & Evidence",
    description: "Registry keys that track user activity and application usage",
    category: ["Registry", "References"],
    phase: ["Analysis"],
    os: ["Windows"],
    tools: [],
    commands: [
      { label: "UserAssist (executed GUI apps)", cmd: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}\\Count\n(Values are ROT13 encoded)" },
      { label: "RecentDocs", cmd: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\" },
      { label: "TypedPaths (Explorer)", cmd: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths" },
      { label: "TypedURLs (IE/Edge)", cmd: "HKCU\\SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLs" },
      { label: "RunMRU (Run dialog)", cmd: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" },
      { label: "Last Visited MRU", cmd: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU" },
      { label: "Open/Save MRU", cmd: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU" },
      { label: "Mounted Devices", cmd: "HKLM\\SYSTEM\\MountedDevices" },
      { label: "USB Devices", cmd: "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\\nHKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB\\" },
      { label: "USB First/Last Connect", cmd: "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\<device>\\<serial>\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\\n  0064 = First Install\n  0066 = Last Connected\n  0067 = Last Removal" },
      { label: "Network Interfaces", cmd: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" },
      { label: "Network Profiles", cmd: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\\nHKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\" },
      { label: "BAM/DAM (execution)", cmd: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\<SID>\nHKLM\\SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings\\<SID>" }
    ]
  },
  {
    title: "Registry - System Information",
    description: "Registry keys for system configuration and identification",
    category: ["Registry", "References"],
    phase: ["Triage", "Analysis"],
    os: ["Windows"],
    tools: [],
    commands: [
      { label: "OS Version", cmd: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\n  ProductName, CurrentBuild, InstallDate" },
      { label: "Computer Name", cmd: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName" },
      { label: "Time Zone", cmd: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation" },
      { label: "Last Shutdown", cmd: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Windows\\ShutdownTime" },
      { label: "Installed Software", cmd: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\\nHKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" },
      { label: "User Profiles", cmd: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" },
      { label: "Current Control Set", cmd: "HKLM\\SYSTEM\\Select\n  Current, Default, LastKnownGood" }
    ]
  },

  // ==================== LINUX / macOS FORENSICS ====================
  {
    title: "Linux Forensics & IR",
    description: "Key forensic artifact locations, incident response commands, and persistence checks for Linux systems",
    analysis: "Bash history: look for wget/curl downloads, base64 decoding, nc/ncat reverse shells, chmod +x on downloaded files.\nCron jobs: check ALL locations (user crontabs, /etc/cron.d, /etc/crontab, cron.daily). Attackers use cron for persistence.\nSUID binaries: compare against a known-good list. Unexpected SUID on find, vim, python, nmap, etc. = privilege escalation.\nLD_PRELOAD and /etc/ld.so.preload = userland rootkit (hooking library calls). Any content here is highly suspicious.\nSystemd services: look for recently created .service files with ExecStart pointing to unusual binaries.",
    category: ["Logs", "Malware"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["grep", "cat", "find", "systemctl"],
    commands: [
      { label: "Bash history", cmd: "cat /home/*/.bash_history" },
      { label: "Cron jobs", cmd: "ls -la /etc/cron* /var/spool/cron/crontabs/" },
      { label: "Recent logins", cmd: "last -f /var/log/wtmp" },
      { label: "Failed logins", cmd: "lastb -f /var/log/btmp" },
      { label: "Installed packages", cmd: "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null" },
      { label: "Listening ports", cmd: "ss -tlnp" },
      { label: "Running processes", cmd: "ps auxf" },
      { label: "Authorized keys", cmd: "find / -name authorized_keys 2>/dev/null" },
      { label: "Crontabs (all)", cmd: "cat /etc/crontab && ls /etc/cron.d/ && crontab -l" },
      { label: "Systemd services", cmd: "systemctl list-unit-files --type=service | grep enabled" },
      { label: "Init scripts", cmd: "ls /etc/init.d/" },
      { label: "Profile scripts", cmd: "cat /etc/profile.d/*.sh" },
      { label: "LD_PRELOAD", cmd: "cat /etc/ld.so.preload 2>/dev/null; echo $LD_PRELOAD" },
      { label: "SUID binaries", cmd: "find / -perm -4000 -type f 2>/dev/null" },
      { label: "Firewall rules", cmd: "iptables -L -n -v 2>/dev/null || nft list ruleset 2>/dev/null" }
    ]
  },
  {
    title: "Linux - Key Forensic File Paths",
    description: "Important file locations for Linux forensic investigations",
    category: ["Disk", "Logs", "References"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: [],
    commands: [
      { label: "Auth & Login Logs", cmd: "/var/log/auth.log        (Debian/Ubuntu - authentication)\n/var/log/secure          (RHEL/CentOS - authentication)\n/var/log/wtmp            (successful logins - binary, use 'last')\n/var/log/btmp            (failed logins - binary, use 'lastb')\n/var/log/lastlog         (last login per user - use 'lastlog')\n/var/run/utmp            (currently logged in users)" },
      { label: "System Logs", cmd: "/var/log/syslog          (general system log)\n/var/log/messages        (RHEL/CentOS system log)\n/var/log/kern.log        (kernel messages)\n/var/log/dmesg           (boot messages)\n/var/log/boot.log        (boot services)" },
      { label: "User Artifacts", cmd: "/home/<user>/.bash_history\n/home/<user>/.zsh_history\n/home/<user>/.python_history\n/home/<user>/.mysql_history\n/home/<user>/.wget-hsts\n/home/<user>/.ssh/known_hosts\n/home/<user>/.ssh/authorized_keys\n/root/.bash_history" },
      { label: "Cron / Scheduled Tasks", cmd: "/etc/crontab\n/etc/cron.d/\n/etc/cron.daily/\n/etc/cron.hourly/\n/var/spool/cron/crontabs/<user>\n/var/spool/at/" },
      { label: "Persistence Locations", cmd: "/etc/rc.local\n/etc/init.d/\n/etc/systemd/system/\n/lib/systemd/system/\n/home/<user>/.config/autostart/\n/etc/profile.d/\n/home/<user>/.bashrc\n/home/<user>/.profile" },
      { label: "Network Configuration", cmd: "/etc/hosts\n/etc/hostname\n/etc/resolv.conf\n/etc/network/interfaces\n/etc/netplan/*.yaml\n/etc/iptables/rules.v4" },
      { label: "Users & Groups", cmd: "/etc/passwd\n/etc/shadow\n/etc/group\n/etc/sudoers\n/etc/sudoers.d/" },
      { label: "Web Server Logs", cmd: "/var/log/apache2/access.log\n/var/log/apache2/error.log\n/var/log/nginx/access.log\n/var/log/nginx/error.log\n/var/log/httpd/" },
      { label: "Package Logs", cmd: "/var/log/dpkg.log        (Debian/Ubuntu packages)\n/var/log/yum.log         (RHEL/CentOS packages)\n/var/log/apt/history.log  (APT history)" },
      { label: "Temp & Volatile", cmd: "/tmp/\n/var/tmp/\n/dev/shm/\n/proc/           (live process info)\n/sys/            (kernel info)" }
    ]
  },
  {
    title: "macOS - Key Forensic File Paths",
    description: "Important file locations for macOS forensic investigations",
    category: ["Disk", "Logs", "References"],
    phase: ["Analysis"],
    os: ["macOS"],
    tools: [],
    commands: [
      { label: "System Logs", cmd: "/var/log/system.log\n/var/log/install.log\n/private/var/log/asl/    (Apple System Log)\nUse: log show --predicate 'process == \"sshd\"' --last 1d" },
      { label: "User Artifacts", cmd: "/Users/<user>/.bash_history\n/Users/<user>/.zsh_history\n/Users/<user>/.bash_sessions/\n/Users/<user>/Library/Preferences/   (plist files)" },
      { label: "Launch Agents/Daemons", cmd: "/Library/LaunchAgents/\n/Library/LaunchDaemons/\n/System/Library/LaunchAgents/\n/System/Library/LaunchDaemons/\n/Users/<user>/Library/LaunchAgents/" },
      { label: "Login Items", cmd: "/Users/<user>/Library/Application Support/com.apple.backgroundtaskmanagementagent/" },
      { label: "Quarantine Events", cmd: "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2\n(SQLite database of downloaded files)" },
      { label: "Spotlight Metadata", cmd: "/.Spotlight-V100/\n(Indexed file metadata)" },
      { label: "FSEvents", cmd: "/.fseventsd/\n(File system change log)" },
      { label: "Keychain", cmd: "/Users/<user>/Library/Keychains/\n/Library/Keychains/System.keychain" },
      { label: "Browser (Safari)", cmd: "/Users/<user>/Library/Safari/History.db\n/Users/<user>/Library/Safari/Downloads.plist" },
      { label: "Trash", cmd: "/Users/<user>/.Trash/\n(Deleted files)" }
    ]
  },

  // ==================== CRYPTO / ENCODING ====================
  {
    title: "Base Encoding / Decoding",
    description: "Decode base64, base32, hex, and other common encodings",
    analysis: "Base64: charset A-Z, a-z, 0-9, +, / with = padding. Strings ending in = or == are almost certainly base64.\nBase32: charset A-Z, 2-7 with = padding. Longer than base64 for same data. Often uppercase-only strings.\nHex: only 0-9 and a-f characters. Even number of chars. Two hex chars = one byte.\nROT13: if text looks like English but is garbled, try ROT13 first. It is its own inverse (apply twice = original).\nMultiple layers of encoding are common in CTF — decode iteratively until readable text appears. CyberChef 'Magic' does this automatically.",
    category: ["Crypto/Encoding"],
    phase: ["Analysis"],
    os: ["Linux", "macOS"],
    tools: ["base64", "xxd", "Python"],
    commands: [
      { label: "Base64 decode", cmd: "echo '{ENCODED}' | base64 -d" },
      { label: "Base64 encode", cmd: "echo -n 'text' | base64" },
      { label: "Base32 decode", cmd: "python3 -c \"import base64; print(base64.b32decode('{ENCODED}').decode())\"" },
      { label: "Hex decode", cmd: "echo '{ENCODED}' | xxd -r -p" },
      { label: "URL decode", cmd: "python3 -c \"import urllib.parse; print(urllib.parse.unquote('{ENCODED}'))\"" },
      { label: "ROT13", cmd: "echo '{ENCODED}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'" }
    ]
  },
  {
    title: "Classic Ciphers Reference",
    description: "Common classical ciphers encountered in CTF challenges with solving tools",
    analysis: "Caesar/ROT: try all 25 shifts — one will be readable English. The Python one-liner does this automatically.\nVigenere: repeated patterns in ciphertext suggest Vigenere. Use Kasiski examination or online auto-solvers.\nSubstitution: frequency analysis — 'E' is most common letter in English. quipqiup.com auto-solves most substitution ciphers.\nRailfence: try 2-10 rails. If ciphertext length has a factor pattern, that may hint at the number of rails.\nIf unsure which cipher: paste into dcode.fr cipher identifier — it guesses the cipher type automatically.",
    category: ["Crypto/Encoding"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["dcode.fr"],
    commands: [
      { label: "Caesar / ROT", cmd: "python3 -c \"s='{ENCODED}'; [print(f'Shift {i}:', ''.join(chr((ord(c)-65+i)%26+65) if c.isupper() else chr((ord(c)-97+i)%26+97) if c.islower() else c for c in s)) for i in range(26)]\"" },
      { label: "Vigenere", cmd: "# https://guballa.de/vigenere-solver (auto-solve)\n# https://dcode.fr/vigenere-cipher\n# Python: pip install pycipher\npython3 -c \"from pycipher import Vigenere; print(Vigenere('{KEY}').decipher('{ENCODED}'))\"" },
      { label: "Beaufort", cmd: "# https://dcode.fr/beaufort-cipher" },
      { label: "Playfair", cmd: "# https://dcode.fr/playfair-cipher" },
      { label: "Railfence", cmd: "# https://dcode.fr/rail-fence-cipher\n# Try rails 2-10" },
      { label: "Substitution", cmd: "# https://quipqiup.com/ (auto-solve)\n# Frequency analysis: https://dcode.fr/substitution-cipher" },
      { label: "Atbash", cmd: "echo '{ENCODED}' | tr 'A-Za-z' 'Z-Az-a'" },
      { label: "Polybius Square", cmd: "# https://dcode.fr/polybius-cipher" },
      { label: "Enigma", cmd: "# https://enigma.louisedade.co.uk/enigma.html" }
    ]
  },
  {
    title: "XOR Analysis",
    description: "XOR brute force and decode for CTF challenges",
    analysis: "Single-byte XOR is most common in CTF. Key 0x00 = no encryption. Look for readable text in output.\nIf xortool suggests key length > 1, try the most probable key. Repeating patterns in hex dump suggest XOR with short key.\nXOR with a known plaintext: if you know part of the plaintext (e.g., 'flag{'), XOR ciphertext with known bytes to recover key.\nXOR is symmetric: encrypt = decrypt with same key. XOR with itself = all zeros.",
    category: ["Crypto/Encoding"],
    phase: ["Analysis"],
    os: ["Linux", "macOS"],
    tools: ["Python", "xortool"],
    commands: [
      { label: "xortool auto", cmd: "xortool {FILE}" },
      { label: "xortool known key", cmd: "xortool-xor -r '{KEY}' -f {FILE} > decoded.bin" },
      { label: "Python single-byte XOR", cmd: "python3 -c \"\ndata = open('{FILE}','rb').read()\nfor k in range(256):\n  d = bytes(b^k for b in data)\n  if b'flag' in d or b'CTF' in d:\n    print(f'Key: {k} -> {d[:100]}')\"" }
    ]
  },
  {
    title: "RSA Attacks - CTF",
    description: "Common RSA attack vectors for CTF crypto challenges",
    analysis: "Small e (e=3): if m^e < n, the ciphertext is just m^e without modular reduction — take the e-th root directly.\nFactorDB: always check if n is already factored. Many CTF challenges use known-factorable primes.\nWiener's attack: works when d (private exponent) is small relative to n. If e is very large, try Wiener's.\nFermat factorization: works when p and q are close together (|p-q| is small).\nCommon modulus attack: same n encrypted with two different public exponents = recoverable without factoring.\nRsaCtfTool tries all known attacks automatically — run it first before manual attempts.",
    category: ["Crypto/Encoding"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["Python", "RsaCtfTool"],
    commands: [
      { label: "RsaCtfTool (auto)", cmd: "python3 RsaCtfTool.py -n {N} -e {E} --uncipher {CIPHERTEXT}" },
      { label: "RsaCtfTool (key file)", cmd: "python3 RsaCtfTool.py --publickey pub.pem --uncipherfile flag.enc" },
      { label: "FactorDB lookup", cmd: "# https://factordb.com/\npython3 -c \"from factordb.factordb import FactorDB; f=FactorDB({N}); f.connect(); print(f.get_factor_list())\"" },
      { label: "Small e attack", cmd: "python3 -c \"\nimport gmpy2\ne = 3\nc = {CIPHERTEXT}\nm, exact = gmpy2.iroot(c, e)\nif exact: print(bytes.fromhex(hex(m)[2:]))\"" },
      { label: "Wiener's attack", cmd: "# pip install owiener\npython3 -c \"\nimport owiener\nd = owiener.attack({E}, {N})\nif d: print(f'Private key d = {d}')\"" },
      { label: "Common modulus", cmd: "python3 -c \"\nfrom Crypto.Util.number import *\nimport gmpy2\n# Same n, different e1/e2, ciphertexts c1/c2\n# Extended GCD to find plaintext\"" },
      { label: "Fermat factorization", cmd: "python3 -c \"\nimport gmpy2\nn = {N}\na = gmpy2.isqrt(n) + 1\nb2 = a*a - n\nwhile not gmpy2.is_square(b2):\n  a += 1; b2 = a*a - n\np = a + gmpy2.isqrt(b2)\nq = a - gmpy2.isqrt(b2)\nprint(f'p={p}\\nq={q}')\"" }
    ],
    references: ["https://github.com/RsaCtfTool/RsaCtfTool"]
  },
  {
    title: "openssl - Crypto Operations",
    description: "Encrypt, decrypt, generate keys, parse certificates",
    analysis: "AES decryption: if you get 'bad decrypt' error, the password or mode (CBC/ECB/CTR) may be wrong. Try different modes.\nRSA decrypt fails? Check if the key matches the ciphertext. Use 'openssl rsa -in key.pem -text' to inspect key details.\nCertificate analysis: check Subject, Issuer, validity dates, and SAN (Subject Alternative Names) for useful information.\nIn CTF: certificates sometimes contain flags in the Subject/Organization fields or in custom extensions.",
    category: ["Crypto/Encoding"],
    phase: ["Analysis"],
    os: ["Linux", "macOS"],
    tools: ["openssl"],
    commands: [
      { label: "AES decrypt", cmd: "openssl enc -d -aes-256-cbc -in {FILE} -out decrypted.bin -k {PASSWORD}" },
      { label: "RSA decrypt", cmd: "openssl rsautl -decrypt -inkey {KEY} -in {FILE} -out decrypted.txt" },
      { label: "Parse cert", cmd: "openssl x509 -in cert.pem -text -noout" },
      { label: "Generate RSA key", cmd: "openssl genrsa -out key.pem 2048" },
      { label: "Extract pubkey", cmd: "openssl rsa -in {KEY} -pubout -out pub.pem" },
      { label: "RSA decrypt (PKCS1)", cmd: "openssl pkcs8 -in {KEY} -nocrypt -out key_pkcs8.pem" }
    ]
  },
  {
    title: "Hash Identification & Cracking",
    description: "Identify hash types and crack them",
    analysis: "Hash length helps identify type: 32 hex chars = MD5, 40 = SHA-1, 64 = SHA-256, 128 = SHA-512.\nhashid sometimes gives too many possibilities — consider context (web app = likely MD5/bcrypt, Windows = NTLM).\nhashcat is much faster than john for GPU cracking. Use hashcat for large wordlists.\nIf wordlist fails, try rules: hashcat -r /usr/share/hashcat/rules/best64.rule adds common mutations (123, !, capitalization).\nOnline lookups: crackstation.net, hashes.org for quick checks before running cracking tools.",
    category: ["Crypto/Encoding"],
    phase: ["Analysis", "Recovery"],
    os: ["Linux"],
    tools: ["hashcat", "John the Ripper", "hashid"],
    commands: [
      { label: "Identify hash", cmd: "hashid '{HASH}'" },
      { label: "hashcat MD5", cmd: "hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt" },
      { label: "hashcat SHA256", cmd: "hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt" },
      { label: "hashcat NTLM", cmd: "hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt" },
      { label: "John auto", cmd: "john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt" },
      { label: "John show", cmd: "john --show hash.txt" }
    ]
  },
  {
    title: "John the Ripper - Hash Extractors (*2john)",
    description: "Extract crackable hashes from various file formats using *2john utilities",
    analysis: "Always extract the hash first with *2john, then crack with john or hashcat. Direct cracking without extraction will not work.\nFor hashcat: convert john-format hashes to hashcat format. Check hashcat wiki for the correct -m mode number.\nIf rockyou fails, try: common password lists, words from the challenge context, company names, usernames as passwords.\nKeePass databases: the master password protects everything. If cracked, you get all stored credentials.\nSSH keys: if the passphrase is cracked, you can use the key to authenticate. Check authorized_keys on target systems.",
    category: ["Crypto/Encoding"],
    phase: ["Recovery"],
    os: ["Linux"],
    tools: ["John the Ripper"],
    commands: [
      { label: "ZIP file", cmd: "zip2john {FILE} > hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt" },
      { label: "RAR file", cmd: "rar2john {FILE} > hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt" },
      { label: "7z file", cmd: "7z2john.pl {FILE} > hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt" },
      { label: "PDF file", cmd: "pdf2john.pl {FILE} > hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt" },
      { label: "SSH private key", cmd: "ssh2john.py {FILE} > hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt" },
      { label: "KeePass database", cmd: "keepass2john {FILE} > hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt" },
      { label: "Office document", cmd: "office2john.py {FILE} > hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt" },
      { label: "GPG private key", cmd: "gpg2john {FILE} > hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt" },
      { label: "Linux shadow", cmd: "unshadow /etc/passwd /etc/shadow > hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt" },
      { label: "Show cracked", cmd: "john --show hash.txt" }
    ]
  },
  {
    title: "ssdeep - Fuzzy Hashing",
    description: "Compare files by similarity using fuzzy hashing — find variants of malware or modified files",
    analysis: "Match score 0 = completely different, 100 = identical. Scores above 50 indicate significant similarity.\nUseful for finding malware variants: hash known samples, then match against unknown files.\nSmall changes (recompilation, packing, minor edits) still produce high similarity scores — unlike cryptographic hashes.\nCompare against a baseline of known-good files to identify modified system binaries (rootkit detection).",
    category: ["Crypto/Encoding", "File Analysis"],
    phase: ["Analysis"],
    os: ["Linux", "macOS"],
    tools: ["ssdeep"],
    commands: [
      { label: "Hash file", cmd: "ssdeep {FILE}" },
      { label: "Compare two", cmd: "ssdeep -p {FILE} file2.bin" },
      { label: "Match against set", cmd: "ssdeep -r /path/to/known/ > known.txt && ssdeep -m known.txt {FILE}" }
    ]
  },
  {
    title: "CyberChef - Swiss Army Knife",
    description: "Web-based tool for encoding, decoding, encryption, compression, and data analysis",
    analysis: "Use the 'Magic' operation first — it automatically detects and decodes multiple layers of encoding.\nChain operations by dragging them into the Recipe panel. Common chain: From Base64 > Gunzip > From Hex.\nThe 'Regular expression' operation with flag pattern extracts flags from large output.\nFor offline use or automation, use the CyberChef CLI (npm install). Recipes can be saved and shared as URLs.",
    category: ["Crypto/Encoding"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["CyberChef"],
    commands: [
      { label: "URL", cmd: "# https://gchq.github.io/CyberChef/" },
      { label: "Common recipes", cmd: "# From Base64 → To Hex\n# From Hex → XOR → To ASCII\n# Magic (auto-detect encoding)\n# From Base64 → Gunzip → Strings" },
      { label: "CLI alternative", cmd: "# Install: npm install -g cyberchef-cli\ncyberchef -r 'FromBase64' -i {FILE}" }
    ],
    references: ["https://gchq.github.io/CyberChef/"]
  },
  {
    title: "impacket-secretsdump - SAM Hash Extraction",
    description: "Extract password hashes from SAM/SYSTEM registry hives or remotely",
    analysis: "Offline extraction requires BOTH SAM and SYSTEM hives (SYSTEM contains the boot key to decrypt SAM).\nOutput format: username:RID:LM_hash:NT_hash. LM hash 'aad3b435b51404ee' = empty (LM hashing disabled).\nNT hashes can be cracked with hashcat -m 1000 or used directly for Pass-the-Hash attacks.\nNTDS.dit extraction gives ALL domain user hashes — this is the jackpot for domain compromise.\nRemote extraction requires admin credentials. Use -just-dc-ntlm flag to get only NT hashes (faster).",
    category: ["Memory", "Registry"],
    phase: ["Recovery"],
    os: ["Windows", "Linux"],
    tools: ["impacket"],
    commands: [
      { label: "From hive files", cmd: "impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL" },
      { label: "Remote extraction", cmd: "impacket-secretsdump {DOMAIN}/{USER}:{PASS}@{TARGET_IP}" },
      { label: "With hashes (PtH)", cmd: "impacket-secretsdump -hashes :{NTLM_HASH} {DOMAIN}/{USER}@{TARGET_IP}" },
      { label: "NTDS.dit extract", cmd: "impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL" }
    ],
    references: ["https://github.com/fortra/impacket"]
  },

  // ==================== MALWARE ANALYSIS ====================
  {
    title: "Static Malware Analysis",
    description: "Initial static analysis of suspicious executables",
    analysis: "Strings output: look for C2 URLs, IP addresses, registry paths, API calls (VirtualAlloc, CreateRemoteThread, WriteProcessMemory = injection).\nImported DLLs: ws2_32.dll = networking, crypt32.dll = encryption, advapi32.dll = registry/service manipulation.\nPacked binaries: very few strings, high entropy, small import table, UPX/ASPack section names. Unpack before analysis.\nSection names: .text/.code = normal. Unusual names (.upx, .aspack, .yoda) = packed. .rsrc with large size = embedded resources.\nCompare file hash against VirusTotal before deeper analysis — it may be known malware with existing reports.",
    category: ["Malware", "File Analysis"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["file", "strings", "objdump", "readelf"],
    commands: [
      { label: "File type", cmd: "file {FILE}" },
      { label: "Strings", cmd: "strings -n 8 {FILE} | head -50" },
      { label: "Sections (ELF)", cmd: "readelf -S {FILE}" },
      { label: "Imports (ELF)", cmd: "readelf -d {FILE}" },
      { label: "Sections (PE)", cmd: "objdump -x {FILE} | head -60" },
      { label: "PE imports", cmd: "python3 -c \"import pefile; pe=pefile.PE('{FILE}'); [print(e.dll.decode()) for e in pe.DIRECTORY_ENTRY_IMPORT]\"" },
      { label: "sigcheck (PE)", cmd: "sigcheck.exe -a {FILE}" }
    ]
  },
  {
    title: "Dynamic Malware Analysis",
    description: "Run and monitor suspicious files in a sandbox",
    analysis: "Run ONLY in an isolated VM/sandbox. Take a snapshot before execution.\nstrace: look for connect() calls (C2), open() of sensitive files (/etc/shadow, /etc/passwd), unlink() (self-deletion).\nltrace: library calls reveal high-level behavior. Look for encryption functions, DNS resolution, file operations.\nNetwork calls: DNS lookups reveal C2 domains. TCP connections to unusual ports = C2 or data exfiltration.\nFile access: writing to /tmp, /dev/shm, crontab, .bashrc = persistence attempts. Reading /proc/self/maps = anti-debug.",
    category: ["Malware"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["strace", "ltrace"],
    commands: [
      { label: "System calls", cmd: "strace -f -o trace.log ./{FILE}" },
      { label: "Library calls", cmd: "ltrace -f -o ltrace.log ./{FILE}" },
      { label: "Network calls", cmd: "strace -f -e trace=network ./{FILE}" },
      { label: "File access", cmd: "strace -f -e trace=open,read,write ./{FILE}" }
    ]
  },
  {
    title: "YARA - Pattern Matching",
    description: "Scan files for malware signatures using YARA rules",
    analysis: "YARA matches = potential malware, but verify with additional analysis. False positives occur with generic rules.\nUse community rules (Yara-Rules, Signature-Base) for quick scans against known malware families.\nWrite custom rules for specific IOCs found during investigation — hex patterns, strings, file properties.\nRecursive scan (-r) is useful for checking extracted files, carved data, or mounted disk images.\nCombine YARA with other tools: scan memory dumps, extracted process memory, or carved files.",
    category: ["File Analysis", "Malware"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["YARA"],
    commands: [
      { label: "Scan file", cmd: "yara rules.yar {FILE}" },
      { label: "Scan directory", cmd: "yara -r rules.yar /path/to/scan/" },
      { label: "Show matches", cmd: "yara -s rules.yar {FILE}" },
      { label: "Multiple rules", cmd: "yara -r /usr/share/yara-rules/ {FILE}" }
    ]
  },

  // ==================== REVERSE ENGINEERING ====================
  {
    title: "GDB - Binary Debugging",
    description: "Debug executables, inspect memory, set breakpoints for RE and exploit dev",
    analysis: "Set breakpoints on strcmp/memcmp to catch password checks — examine arguments to find the expected value.\nExamine the stack (x/20x $esp) before and after function calls to understand data flow.\ninfo proc mappings shows memory layout — useful for finding writable sections for exploit development.\npwndbg/peda extensions add visual context, heap analysis, and exploit helpers. Install one of them.\nFor anti-debug checks: binary may call ptrace(PTRACE_TRACEME) — bypass by setting a breakpoint on ptrace and forcing return 0.",
    category: ["Malware", "File Analysis"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["gdb", "pwndbg"],
    commands: [
      { label: "Start debugging", cmd: "gdb ./{FILE}" },
      { label: "With args", cmd: "gdb --args ./{FILE} arg1 arg2" },
      { label: "Set breakpoint", cmd: "b main\nb *0x08048456" },
      { label: "Run", cmd: "r" },
      { label: "Step / Next", cmd: "si    # step into\nni    # step over\nc     # continue" },
      { label: "Examine memory", cmd: "x/20x $esp   # 20 hex words at ESP\nx/s 0x804a000  # string at address\nx/10i $eip    # 10 instructions at EIP" },
      { label: "Info", cmd: "info registers\ninfo functions\ninfo proc mappings" },
      { label: "pwndbg (enhanced)", cmd: "# Install: git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh\n# Adds: vmmap, heap, checksec, cyclic, rop" }
    ]
  },
  {
    title: "Ghidra - Reverse Engineering",
    description: "NSA's open-source reverse engineering framework for binary analysis",
    analysis: "Start with the decompiler view (Window > Decompile) — C pseudocode is much easier to read than assembly.\nRename variables and functions as you understand them — Ghidra saves your annotations. Press 'L' to rename.\nLook for the main function first, then trace from string references (Search > For Strings) to find interesting code.\nCross-references (Ctrl+Shift+E) show where a function or variable is used — essential for understanding program flow.\nFor CTF RE: find the flag validation function, understand the algorithm, then reverse it to compute the flag.",
    category: ["Malware", "File Analysis"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["Ghidra"],
    commands: [
      { label: "Launch GUI", cmd: "ghidraRun" },
      { label: "Headless analysis", cmd: "analyzeHeadless /path/to/project ProjectName -import {FILE} -postScript script.py" },
      { label: "Decompile (headless)", cmd: "analyzeHeadless /path/to/project ProjectName -import {FILE} -postScript DecompileAll.py" },
      { label: "Tips", cmd: "# Key shortcuts:\n# G = Go to address\n# L = Rename\n# Ctrl+Shift+E = Show references\n# ; = Add comment\n# Window > Decompile = View C pseudocode" }
    ],
    references: ["https://ghidra-sre.org/"]
  },
  {
    title: "radare2 - Binary Analysis",
    description: "Quick binary analysis and reverse engineering from the command line",
    analysis: "Always run 'aaa' (or use -A flag) first for full analysis — without it, functions and references are not resolved.\n'afl' lists all detected functions — look for main, sym.check_password, sym.flag, or similar names.\n'iz' lists strings with their addresses — cross-reference with 'axt @addr' to find where they are used in code.\nVisual mode (V then p) cycles through views: hex, disasm, graph. Graph mode is best for understanding control flow.\nradare2 is faster than Ghidra for quick checks. Use Ghidra for deep analysis, r2 for quick triage.",
    category: ["Malware", "File Analysis"],
    phase: ["Analysis"],
    os: ["Linux", "macOS"],
    tools: ["radare2"],
    commands: [
      { label: "Analyze", cmd: "r2 -A {FILE}" },
      { label: "Functions", cmd: "afl" },
      { label: "Disassemble main", cmd: "s main && pdf" },
      { label: "Strings", cmd: "iz" },
      { label: "Cross-refs", cmd: "axt @ sym.main" },
      { label: "Hex dump", cmd: "px 64 @ 0x0" },
      { label: "Visual mode", cmd: "V then p to cycle views" },
      { label: "Decompile (with r2ghidra)", cmd: "pdg @ main" }
    ],
    references: ["https://rada.re/n/"]
  },
  {
    title: "pwntools - Exploit Development",
    description: "Python CTF framework for exploit development, binary interaction, and shellcode",
    analysis: "checksec output tells you what protections are enabled: NX (no shellcode on stack), PIE (ASLR for binary), canary (stack protection), RELRO.\nNo NX + no canary = classic buffer overflow with shellcode. NX + no PIE = ROP chain using fixed addresses.\nPattern create/find: send cyclic pattern, note the crash address, find the offset = exact buffer overflow length.\ncyclic_find takes the value from the crash register (EIP/RIP) and returns the exact offset to control it.\nFor remote challenges: switch process() to remote('host', port). Everything else stays the same.",
    category: ["Crypto/Encoding", "File Analysis"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["pwntools"],
    commands: [
      { label: "Install", cmd: "pip install pwntools" },
      { label: "Basic template", cmd: "python3 -c \"\nfrom pwn import *\np = process('./{FILE}')  # or remote('host', port)\np.sendline(b'payload')\np.interactive()\"" },
      { label: "Pattern create", cmd: "python3 -c \"from pwn import *; print(cyclic(200))\"" },
      { label: "Pattern offset", cmd: "python3 -c \"from pwn import *; print(cyclic_find(0x61616164))\"" },
      { label: "Shellcraft", cmd: "python3 -c \"from pwn import *; context.arch='amd64'; print(shellcraft.sh())\"" },
      { label: "ROP", cmd: "python3 -c \"\nfrom pwn import *\nelf = ELF('./{FILE}')\nrop = ROP(elf)\nprint(rop.dump())\"" },
      { label: "Checksec", cmd: "checksec ./{FILE}" }
    ],
    references: ["https://docs.pwntools.com/"]
  },

  // ==================== GUI FORENSIC TOOLS ====================
  {
    title: "GUI Forensic Tools",
    description: "Collection of graphical forensic tools for disk analysis, memory capture, network analysis, and steganography",
    category: ["Disk", "Memory", "Network", "Stego"],
    phase: ["Analysis", "Acquisition"],
    os: ["Windows", "Linux", "macOS"],
    tools: ["Autopsy", "FTK Imager", "NetworkMiner", "Stegsolve", "DumpIt", "EDD", "Wireshark", "Arsenal Image Mounter", "Event Log Explorer"],
    commands: [
      { label: "Autopsy", cmd: "# GUI forensic analysis platform built on Sleuth Kit, handles disk images, keyword search, timeline, hash filtering" },
      { label: "FTK Imager", cmd: "# Disk/memory acquisition and preview, create forensic images (E01/DD), mount images, RAM capture" },
      { label: "NetworkMiner", cmd: "# Passive network analysis, extracts files/images/credentials from PCAP, OS fingerprinting" },
      { label: "Stegsolve", cmd: "# Visual stego analysis, bit plane browsing, frame browsing, data extraction by color channel" },
      { label: "DumpIt", cmd: "# One-click Windows memory dump, creates raw memory image on double-click" },
      { label: "EDD", cmd: "# Encrypted Disk Detector, checks for BitLocker/TrueCrypt/PGP before imaging" },
      { label: "Wireshark", cmd: "# GUI packet analysis with powerful display filters (see Wireshark filters entry)" },
      { label: "Arsenal Image Mounter", cmd: "# Mount forensic images as drive letters in Windows with write-blocking" },
      { label: "Event Log Explorer", cmd: "# GUI Windows event log viewer with timeline and filtering" }
    ],
    references: [
      "https://www.autopsy.com/",
      "https://www.exterro.com/ftk-imager",
      "https://www.netresec.com/?page=NetworkMiner",
      "https://arsenalrecon.com/",
      "https://www.wireshark.org/"
    ]
  },

  // ==================== ADDITIONAL NEW TOOLS ====================
  {
    title: "Git Forensics",
    description: "Recover deleted data, secrets, and history from Git repositories — common CTF challenge type",
    analysis: "Secrets in git history: even if a file was deleted, every version exists in git objects forever. Use 'git log -p --all -S' to search.\nReflog shows ALL recent actions including 'deleted' branches and force-pushed changes — recoverable with git checkout.\nStash list often contains forgotten work-in-progress with sensitive data. Always check stashes.\nBranch -a shows remote tracking branches — check ALL branches, not just main/master.\nFor CTF: look at every commit diff for flags, check deleted files, examine stashes, and search blob objects directly.",
    category: ["File Analysis"],
    phase: ["Analysis", "Recovery"],
    os: ["Linux", "macOS", "Windows"],
    tools: ["git"],
    commands: [
      { label: "Full log", cmd: "git log --all --oneline --graph" },
      { label: "Reflog", cmd: "git reflog" },
      { label: "Show deleted", cmd: "git log --diff-filter=D --summary" },
      { label: "Search secrets", cmd: "git log -p --all -S 'password'" },
      { label: "Recover file", cmd: "git checkout HEAD~1 -- {FILE}" },
      { label: "Show all branches", cmd: "git branch -a" },
      { label: "Stash list", cmd: "git stash list && git stash show -p" },
      { label: "Diff commits", cmd: "git diff HEAD~5..HEAD" },
      { label: "Extract all blobs", cmd: "git rev-list --objects --all | git cat-file --batch-check" }
    ]
  },
  {
    title: "bulk_extractor - Automated Extraction",
    description: "Extract emails, URLs, credit card numbers, domains, and other artifacts from disk images and memory dumps without parsing file systems",
    analysis: "bulk_extractor works on raw data — no filesystem parsing needed. Works on partial images, corrupted disks, and memory dumps.\nOutput files: email.txt, url.txt, domain.txt, telephone.txt, ccn.txt (credit cards), exif.txt, etc.\nHistogram files (*_histogram.txt) show frequency counts — top entries are most likely relevant.\nWorks in parallel (multi-threaded) — much faster than grep for large images.\nGreat for quick triage: run on a memory dump to find all URLs, email addresses, and domains contacted.",
    category: ["Disk", "Memory"],
    phase: ["Analysis", "Carving"],
    os: ["Linux"],
    tools: ["bulk_extractor"],
    commands: [
      { label: "Basic scan", cmd: "bulk_extractor -o output/ {IMAGE}" },
      { label: "From memory", cmd: "bulk_extractor -o output/ {DUMP_FILE}" },
      { label: "Email/URLs only", cmd: "bulk_extractor -e email -e url -o output/ {IMAGE}" },
      { label: "View results", cmd: "ls output/*.txt && head output/email.txt" }
    ]
  },
  {
    title: "sqlite3 - Database Forensics",
    description: "Query SQLite databases — browser history, iOS backups, Android apps, chat logs",
    analysis: "Browser history timestamps: Chrome uses WebKit epoch (microseconds since 1601-01-01), Firefox uses Unix epoch in microseconds.\nThe conversion formulas in the commands handle these automatically. Verify dates make sense.\nDeleted records may still exist in SQLite 'free pages' — use undark or sqlite3 .recover to find them.\nCommon forensic SQLite databases: browser history/cookies, iOS SMS (sms.db), WhatsApp (msgstore.db), Android contacts.\nWAL files (*-wal) may contain more recent data not yet committed to the main database — always check for them.",
    category: ["Disk", "File Analysis"],
    phase: ["Analysis"],
    os: ["Linux", "macOS", "Windows"],
    tools: ["sqlite3"],
    commands: [
      { label: "List tables", cmd: "sqlite3 {FILE} \".tables\"" },
      { label: "Schema", cmd: "sqlite3 {FILE} \".schema\"" },
      { label: "Chrome history", cmd: "sqlite3 History \"SELECT url, title, datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 20\"" },
      { label: "Firefox history", cmd: "sqlite3 places.sqlite \"SELECT url, title, datetime(last_visit_date/1000000,'unixepoch') FROM moz_places ORDER BY last_visit_date DESC LIMIT 20\"" },
      { label: "Dump all", cmd: "sqlite3 {FILE} \".dump\"" }
    ]
  },
  {
    title: "dumpzilla - Browser Forensics",
    description: "Extract forensic data from Firefox/Thunderbird profiles (history, cookies, downloads, forms)",
    analysis: "dumpzilla extracts everything from a Firefox profile in one pass — much faster than manual SQLite queries.\nPasswords: Firefox stores encrypted passwords in logins.json (decrypted with key from key4.db). dumpzilla can extract if key is unprotected.\nCookies: look for session tokens, authentication cookies. Timestamps show when sites were visited.\nForms: autofill data may contain usernames, search queries, and other typed information.\nDownloads: shows what files were downloaded, from where, and when — key for tracking attacker tool downloads.",
    category: ["Disk"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["dumpzilla"],
    commands: [
      { label: "Full dump", cmd: "python3 dumpzilla.py /path/to/firefox/profile/" },
      { label: "Cookies", cmd: "python3 dumpzilla.py /path/to/profile/ --Cookies" },
      { label: "History", cmd: "python3 dumpzilla.py /path/to/profile/ --History" },
      { label: "Downloads", cmd: "python3 dumpzilla.py /path/to/profile/ --Downloads" },
      { label: "Forms", cmd: "python3 dumpzilla.py /path/to/profile/ --Forms" },
      { label: "Passwords", cmd: "python3 dumpzilla.py /path/to/profile/ --Passwords" },
      { label: "Manual SQLite", cmd: "sqlite3 places.sqlite \"SELECT url, title, datetime(last_visit_date/1000000,'unixepoch') FROM moz_places ORDER BY last_visit_date DESC LIMIT 50;\"" }
    ],
    references: ["https://github.com/pielco11/dumpzilla"]
  },

  // ==================== REFERENCE TABLES ====================
  {
    title: "Esoteric Languages - CTF Encoding",
    description: "Identify and decode esoteric programming languages commonly used in CTF challenges",
    category: ["Crypto/Encoding", "References"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: [],
    commands: [
      { label: "Brainfuck", cmd: "# Characters: + - < > [ ] . ,\n# Example: ++++++++++[>+++++++>++++++++++>+++>+<<<<-]>++.>+.+++++++..+++.\n# Interpreter: https://copy.sh/brainfuck/\n# Or: pip install brainfuck && brainfuck program.bf" },
      { label: "Ook!", cmd: "# Characters: Ook. Ook! Ook?\n# Variant of Brainfuck using Ook words\n# Decoder: https://dcode.fr/ook-language" },
      { label: "Malbolge", cmd: "# Extremely difficult esoteric language\n# Interpreter: http://malbolge.doleczek.pl/" },
      { label: "Piet", cmd: "# Programs are images (colored pixels)\n# Interpreter: https://www.bertnase.de/npiet/npiet-execute.php\n# npiet program.png" },
      { label: "Whitespace", cmd: "# Uses only spaces, tabs, newlines\n# Interpreter: https://vii5ard.github.io/whitespace/\n# Hint: if file looks empty but has content, try this" },
      { label: "JSFuck", cmd: "# JavaScript using only: []()!+\n# Just paste into browser console to execute\n# Decoder: https://enkhee-osiris.github.io/Decoder-JSFuck/" },
      { label: "Universal runner", cmd: "# https://tio.run — supports 600+ languages\n# Paste code, select language, run" }
    ]
  },
  {
    title: "Hexahue / Visual Ciphers",
    description: "Color-based and visual encoding schemes used in CTF challenges",
    category: ["Crypto/Encoding", "References"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: [],
    commands: [
      { label: "Hexahue", cmd: "# Each letter = 2x3 grid of colored cells\n# Decoder: https://www.dcode.fr/hexahue-cipher" },
      { label: "Braille", cmd: "# Unicode braille characters (⠁⠃⠉...)\n# Decoder: https://www.dcode.fr/braille-alphabet" },
      { label: "Morse Code", cmd: "# Dots and dashes: .- -... -.-.\n# Decoder: https://morsedecoder.com/\n# CLI: echo '.- -... -.-..' | morse -d" },
      { label: "Semaphore", cmd: "# Flag positions represent letters\n# Decoder: https://www.dcode.fr/semaphore-flag" },
      { label: "Pigpen Cipher", cmd: "# Geometric symbols based on grid position\n# Decoder: https://www.dcode.fr/pigpen-cipher" },
      { label: "Tap Code", cmd: "# Pairs of numbers (like Polybius but using taps)\n# Decoder: https://www.dcode.fr/tap-cipher" },
      { label: "Navy Flags", cmd: "# International maritime signal flags\n# Decoder: https://www.dcode.fr/maritime-signals-code" }
    ]
  },
  {
    title: "PHP Magic Hashes",
    description: "PHP type juggling — hashes starting with 0e are treated as zero in loose comparison",
    category: ["Crypto/Encoding", "References"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: [],
    commands: [
      { label: "MD5 magic strings", cmd: "# These strings produce MD5 hashes starting with 0e (scientific notation = 0)\n240610708  → 0e462097431906509019562988736854\nQNKCDZO    → 0e830400451993494058024219903391\naabg7XSs   → 0e087386482136013740957780965295\naabC9RqS   → 0e041022518165728065344349536255\ns878926199a → 0e545993274517709034328855841020\ns155964671a → 0e342768416822451524974117254469\ns214587387a → 0e848240448830537924465865611904" },
      { label: "SHA1 magic strings", cmd: "# SHA1 hashes starting with 0e:\naaroZmOk → 0e66507019969427134894567494305185566735\naaK1STfY → 0e76658526655756207688271159624026011393\naaO8zKZF → 0e89257456677279068558073954252716165668\naa3OFF9m → 0e36977786278517984959260394024281014729" },
      { label: "PHP comparison", cmd: "# In PHP loose comparison (==):\n# '0e12345' == '0e67890' → TRUE (both equal 0)\n# '0e12345' == 0 → TRUE\n# Always use === for strict comparison" },
      { label: "Exploit example", cmd: "# If PHP code does: if(md5($input) == '0') {...}\n# Send: 240610708\n# md5('240610708') = '0e462...' == 0 → TRUE" }
    ]
  }
];
