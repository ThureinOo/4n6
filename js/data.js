const ENTRIES = [
  // ==================== MEMORY FORENSICS ====================
  {
    title: "Volatility3 - Image Info",
    description: "Identify the OS and kernel version of a memory dump",
    category: ["Memory"],
    phase: ["Triage"],
    os: ["Windows", "Linux", "macOS"],
    tools: ["Volatility3"],
    commands: [
      { label: "Windows", cmd: "vol -f {DUMP_FILE} windows.info" },
      { label: "Linux", cmd: "vol -f {DUMP_FILE} linux.info" },
      { label: "macOS", cmd: "vol -f {DUMP_FILE} mac.info" }
    ],
    references: ["https://volatility3.readthedocs.io"]
  },
  {
    title: "Volatility3 - Process List",
    description: "List running processes from a memory dump",
    category: ["Memory"],
    phase: ["Analysis"],
    os: ["Windows", "Linux"],
    tools: ["Volatility3"],
    commands: [
      { label: "Windows", cmd: "vol -f {DUMP_FILE} windows.pslist" },
      { label: "Windows (tree)", cmd: "vol -f {DUMP_FILE} windows.pstree" },
      { label: "Linux", cmd: "vol -f {DUMP_FILE} linux.pslist" }
    ]
  },
  {
    title: "Volatility3 - Process Scan (hidden)",
    description: "Find hidden or unlinked processes via pool tag scanning",
    category: ["Memory"],
    phase: ["Analysis"],
    os: ["Windows"],
    tools: ["Volatility3"],
    commands: [
      { label: "psscan", cmd: "vol -f {DUMP_FILE} windows.psscan" }
    ]
  },
  {
    title: "Volatility3 - Network Connections",
    description: "List active and closed network connections",
    category: ["Memory", "Network"],
    phase: ["Analysis"],
    os: ["Windows", "Linux"],
    tools: ["Volatility3"],
    commands: [
      { label: "Windows", cmd: "vol -f {DUMP_FILE} windows.netscan" },
      { label: "Windows (netstat)", cmd: "vol -f {DUMP_FILE} windows.netstat" },
      { label: "Linux", cmd: "vol -f {DUMP_FILE} linux.sockstat" }
    ]
  },
  {
    title: "Volatility3 - Command Line Args",
    description: "Show command line arguments for each process",
    category: ["Memory"],
    phase: ["Analysis"],
    os: ["Windows"],
    tools: ["Volatility3"],
    commands: [
      { label: "cmdline", cmd: "vol -f {DUMP_FILE} windows.cmdline" }
    ]
  },
  {
    title: "Volatility3 - DLL List",
    description: "List loaded DLLs for processes",
    category: ["Memory"],
    phase: ["Analysis"],
    os: ["Windows"],
    tools: ["Volatility3"],
    commands: [
      { label: "All processes", cmd: "vol -f {DUMP_FILE} windows.dlllist" },
      { label: "Specific PID", cmd: "vol -f {DUMP_FILE} windows.dlllist --pid {PID}" }
    ]
  },
  {
    title: "Volatility3 - Dump Process Memory",
    description: "Dump the memory of a specific process to disk",
    category: ["Memory"],
    phase: ["Analysis", "Recovery"],
    os: ["Windows", "Linux"],
    tools: ["Volatility3"],
    commands: [
      { label: "Windows", cmd: "vol -f {DUMP_FILE} windows.memmap --dump --pid {PID}" },
      { label: "Windows (exe)", cmd: "vol -f {DUMP_FILE} windows.dumpfiles --pid {PID}" },
      { label: "Linux", cmd: "vol -f {DUMP_FILE} linux.proc.maps --dump --pid {PID}" }
    ]
  },
  {
    title: "Volatility3 - Registry Hives",
    description: "List and dump registry hives from memory",
    category: ["Memory", "Registry"],
    phase: ["Analysis"],
    os: ["Windows"],
    tools: ["Volatility3"],
    commands: [
      { label: "List hives", cmd: "vol -f {DUMP_FILE} windows.registry.hivelist" },
      { label: "Print key", cmd: "vol -f {DUMP_FILE} windows.registry.printkey --key \"Software\\Microsoft\\Windows\\CurrentVersion\\Run\"" },
      { label: "Dump hive", cmd: "vol -f {DUMP_FILE} windows.registry.hivelist --dump" }
    ]
  },
  {
    title: "Volatility3 - Malfind (Injected Code)",
    description: "Detect process injection and suspicious memory regions",
    category: ["Memory", "Malware"],
    phase: ["Analysis"],
    os: ["Windows"],
    tools: ["Volatility3"],
    commands: [
      { label: "All processes", cmd: "vol -f {DUMP_FILE} windows.malfind" },
      { label: "Specific PID", cmd: "vol -f {DUMP_FILE} windows.malfind --pid {PID}" }
    ]
  },
  {
    title: "Volatility3 - Handles",
    description: "List open handles (files, registry keys, mutexes) per process",
    category: ["Memory"],
    phase: ["Analysis"],
    os: ["Windows"],
    tools: ["Volatility3"],
    commands: [
      { label: "All", cmd: "vol -f {DUMP_FILE} windows.handles" },
      { label: "Specific PID", cmd: "vol -f {DUMP_FILE} windows.handles --pid {PID}" }
    ]
  },
  {
    title: "Volatility3 - SSDT Hooks",
    description: "Check for SSDT (System Service Descriptor Table) hooks — rootkit detection",
    category: ["Memory", "Malware"],
    phase: ["Analysis"],
    os: ["Windows"],
    tools: ["Volatility3"],
    commands: [
      { label: "SSDT", cmd: "vol -f {DUMP_FILE} windows.ssdt" }
    ]
  },
  {
    title: "Volatility3 - Strings + Process Mapping",
    description: "Extract strings from memory dump and map to processes",
    category: ["Memory"],
    phase: ["Analysis"],
    os: ["Windows", "Linux"],
    tools: ["Volatility3", "strings"],
    commands: [
      { label: "Extract strings", cmd: "strings -a -t d {DUMP_FILE} > strings.txt" },
      { label: "Unicode strings", cmd: "strings -a -t d -el {DUMP_FILE} >> strings.txt" },
      { label: "Map to PIDs", cmd: "vol -f {DUMP_FILE} windows.strings --strings-file strings.txt" }
    ]
  },
  {
    title: "Volatility2 - Profile Detection",
    description: "Determine the correct profile for Volatility 2",
    category: ["Memory"],
    phase: ["Triage"],
    os: ["Windows", "Linux"],
    tools: ["Volatility2"],
    commands: [
      { label: "imageinfo", cmd: "volatility -f {DUMP_FILE} imageinfo" },
      { label: "kdbgscan", cmd: "volatility -f {DUMP_FILE} kdbgscan" }
    ]
  },
  {
    title: "Volatility3 - Hashdump",
    description: "Extract password hashes from memory (SAM + SYSTEM)",
    category: ["Memory"],
    phase: ["Analysis", "Recovery"],
    os: ["Windows"],
    tools: ["Volatility3"],
    commands: [
      { label: "hashdump", cmd: "vol -f {DUMP_FILE} windows.hashdump" },
      { label: "lsadump", cmd: "vol -f {DUMP_FILE} windows.lsadump" },
      { label: "cachedump", cmd: "vol -f {DUMP_FILE} windows.cachedump" }
    ]
  },
  {
    title: "Volatility3 - Filescan & Dumpfiles",
    description: "Find and extract files from memory",
    category: ["Memory"],
    phase: ["Recovery", "Carving"],
    os: ["Windows"],
    tools: ["Volatility3"],
    commands: [
      { label: "Scan for files", cmd: "vol -f {DUMP_FILE} windows.filescan" },
      { label: "Filter by name", cmd: "vol -f {DUMP_FILE} windows.filescan | grep -i 'secret'" },
      { label: "Dump file", cmd: "vol -f {DUMP_FILE} windows.dumpfiles --virtaddr {OFFSET}" }
    ]
  },
  {
    title: "Volatility3 - Timeline",
    description: "Create a timeline of all timestamps in memory",
    category: ["Memory"],
    phase: ["Timeline"],
    os: ["Windows"],
    tools: ["Volatility3"],
    commands: [
      { label: "Timeliner", cmd: "vol -f {DUMP_FILE} timeliner.Timeliner" }
    ]
  },

  // ==================== DISK FORENSICS ====================
  {
    title: "dd - Create Disk Image",
    description: "Create a raw bit-for-bit copy of a disk or partition",
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
    title: "Sleuth Kit - File System Analysis",
    description: "Analyze file systems, list files, view metadata",
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
    title: "Autopsy - GUI Forensic Analysis",
    description: "GUI-based forensic analysis platform built on Sleuth Kit",
    category: ["Disk"],
    phase: ["Analysis"],
    os: ["Windows", "Linux", "macOS"],
    tools: ["Autopsy"],
    commands: [
      { label: "Launch", cmd: "autopsy" },
      { label: "CLI (Sleuth Kit)", cmd: "autopsy -d /path/to/case" }
    ],
    references: ["https://www.autopsy.com/"]
  },
  {
    title: "Mount Disk Image",
    description: "Mount a forensic disk image for analysis (read-only)",
    category: ["Disk"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["mount"],
    commands: [
      { label: "Raw image", cmd: "mount -o ro,loop,offset=$((512*{SECTOR})) {IMAGE} /mnt/evidence" },
      { label: "EWF (E01)", cmd: "ewfmount {IMAGE} /mnt/ewf && mount -o ro,loop /mnt/ewf/ewf1 /mnt/evidence" },
      { label: "Unmount", cmd: "umount /mnt/evidence" }
    ]
  },

  // ==================== NETWORK FORENSICS ====================
  {
    title: "Wireshark - Display Filters",
    description: "Common Wireshark display filters for traffic analysis",
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
    title: "tcpdump - Packet Capture",
    description: "Capture and filter network traffic from the command line",
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
    title: "NetworkMiner - PCAP Analysis",
    description: "Extract files, images, credentials from PCAP",
    category: ["Network"],
    phase: ["Analysis", "Carving"],
    os: ["Windows", "Linux"],
    tools: ["NetworkMiner"],
    commands: [
      { label: "Open pcap", cmd: "NetworkMiner {PCAP}" }
    ],
    references: ["https://www.netresec.com/?page=NetworkMiner"]
  },

  // ==================== STEGANOGRAPHY ====================
  {
    title: "steghide - JPEG/BMP Stego",
    description: "Embed or extract hidden data in JPEG and BMP images",
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
    title: "stegsolve - Image Analysis",
    description: "Visual steganography analysis with bit-plane browsing",
    category: ["Stego"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["stegsolve"],
    commands: [
      { label: "Launch", cmd: "java -jar stegsolve.jar" }
    ]
  },
  {
    title: "Sonic Visualiser - Audio Stego",
    description: "Analyze audio files visually for hidden spectrograms or data",
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
    title: "stegcracker - Brute Force Stego Passwords",
    description: "Brute force steghide passphrases using a wordlist",
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
    category: ["Stego"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["Python"],
    commands: [
      { label: "Python script", cmd: "python3 -c \"\nfrom PIL import Image\nim = Image.open('{FILE}')\npx = im.load()\nbits = ''\nfor y in range(im.height):\n  for x in range(im.width):\n    bits += str(px[x,y][0] & 1)\nprint(''.join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits),8)))\"" }
    ]
  },

  // ==================== FILE ANALYSIS ====================
  {
    title: "file - Identify File Type",
    description: "Determine file type using magic bytes",
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
    title: "binwalk - Firmware / Embedded File Analysis",
    description: "Scan for embedded files, file systems, and compressed data",
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
    title: "strings - Extract Readable Text",
    description: "Extract printable strings from binary files",
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
    title: "foremost - File Carving",
    description: "Carve files from disk images or binary blobs by headers/footers",
    category: ["File Analysis", "Disk"],
    phase: ["Carving"],
    os: ["Linux"],
    tools: ["foremost"],
    commands: [
      { label: "Carve all types", cmd: "foremost -i {FILE} -o output/" },
      { label: "Specific types", cmd: "foremost -t jpg,png,pdf -i {FILE} -o output/" },
      { label: "Verbose", cmd: "foremost -v -i {IMAGE} -o output/" }
    ]
  },
  {
    title: "scalpel - Advanced File Carving",
    description: "Carve files using header/footer signatures (faster than foremost)",
    category: ["File Analysis", "Disk"],
    phase: ["Carving"],
    os: ["Linux"],
    tools: ["scalpel"],
    commands: [
      { label: "Carve", cmd: "scalpel -c /etc/scalpel/scalpel.conf -o output/ {IMAGE}" }
    ]
  },
  {
    title: "YARA - Pattern Matching",
    description: "Scan files for malware signatures using YARA rules",
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
  {
    title: "Entropy Analysis",
    description: "Check file entropy to detect encryption or compression",
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

  // ==================== METADATA ====================
  {
    title: "ExifTool - Metadata Extraction",
    description: "Extract and analyze metadata from images, documents, and media",
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

  // ==================== LOG ANALYSIS ====================
  {
    title: "Linux Auth Log Analysis",
    description: "Analyze authentication logs for suspicious activity",
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
    title: "Windows Event Log Analysis",
    description: "Parse and analyze Windows Event Logs (.evtx)",
    category: ["Logs"],
    phase: ["Analysis"],
    os: ["Windows", "Linux"],
    tools: ["evtx_dump", "python-evtx"],
    commands: [
      { label: "Dump to XML", cmd: "evtx_dump.py Security.evtx > security.xml" },
      { label: "Logon events (4624)", cmd: "evtx_dump.py Security.evtx | grep -A 20 '<EventID>4624</EventID>'" },
      { label: "Failed logons (4625)", cmd: "evtx_dump.py Security.evtx | grep -A 20 '<EventID>4625</EventID>'" },
      { label: "New service (7045)", cmd: "evtx_dump.py System.evtx | grep -A 20 '<EventID>7045</EventID>'" },
      { label: "PowerShell (4104)", cmd: "evtx_dump.py 'Microsoft-Windows-PowerShell%4Operational.evtx' | grep -A 30 '<EventID>4104</EventID>'" }
    ]
  },
  {
    title: "Apache/Nginx Access Log Analysis",
    description: "Analyze web server access logs for attacks and anomalies",
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
    description: "Create a comprehensive forensic timeline from multiple sources",
    category: ["Logs"],
    phase: ["Timeline"],
    os: ["Linux"],
    tools: ["plaso"],
    commands: [
      { label: "Create timeline", cmd: "log2timeline.py timeline.plaso {IMAGE}" },
      { label: "Filter & output CSV", cmd: "psort.py -o l2tcsv timeline.plaso > timeline.csv" },
      { label: "Date filter", cmd: "psort.py -o l2tcsv timeline.plaso \"date > '2024-01-01' AND date < '2024-02-01'\" > filtered.csv" }
    ],
    references: ["https://plaso.readthedocs.io/"]
  },

  // ==================== WINDOWS FORENSICS ====================
  {
    title: "Windows Prefetch Analysis",
    description: "Analyze prefetch files to determine executed programs and timestamps",
    category: ["Registry"],
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
    title: "Windows Registry Forensics",
    description: "Extract forensic artifacts from offline registry hives",
    category: ["Registry"],
    phase: ["Analysis"],
    os: ["Windows", "Linux"],
    tools: ["RegRipper", "regipy"],
    commands: [
      { label: "RegRipper (SAM)", cmd: "regripper -r SAM -p samparse" },
      { label: "RegRipper (SYSTEM)", cmd: "regripper -r SYSTEM -p compname" },
      { label: "RegRipper (SOFTWARE)", cmd: "regripper -r SOFTWARE -p winver" },
      { label: "RegRipper (NTUSER)", cmd: "regripper -r NTUSER.DAT -p userassist" },
      { label: "regipy", cmd: "registry-parse-header {FILE}" }
    ]
  },
  {
    title: "Windows MFT Analysis",
    description: "Parse NTFS Master File Table for file metadata and timestamps",
    category: ["Disk", "Registry"],
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
    title: "ShimCache / AppCompatCache",
    description: "Extract program execution evidence from ShimCache",
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
    title: "Windows Recycle Bin",
    description: "Recover and analyze files from the Windows Recycle Bin",
    category: ["Disk"],
    phase: ["Recovery"],
    os: ["Windows"],
    tools: ["RBCmd"],
    commands: [
      { label: "Parse $I files", cmd: "RBCmd.exe -d \"C:\\$Recycle.Bin\" --csv output/" },
      { label: "Manual (Linux)", cmd: "find /mnt/evidence/\\$Recycle.Bin -name '\\$I*' -exec xxd {} \\;" }
    ]
  },

  // ==================== LINUX FORENSICS ====================
  {
    title: "Linux Forensic Artifact Collection",
    description: "Key locations for forensic artifacts on Linux systems",
    category: ["Logs"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["grep", "cat"],
    commands: [
      { label: "Bash history", cmd: "cat /home/*/.bash_history" },
      { label: "Cron jobs", cmd: "ls -la /etc/cron* /var/spool/cron/crontabs/" },
      { label: "Recent logins", cmd: "last -f /var/log/wtmp" },
      { label: "Failed logins", cmd: "lastb -f /var/log/btmp" },
      { label: "Installed packages", cmd: "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null" },
      { label: "Listening ports", cmd: "ss -tlnp" },
      { label: "Running processes", cmd: "ps auxf" },
      { label: "Authorized keys", cmd: "find / -name authorized_keys 2>/dev/null" }
    ]
  },
  {
    title: "Linux Persistence Checks",
    description: "Check common persistence mechanisms on Linux",
    category: ["Malware"],
    phase: ["Analysis"],
    os: ["Linux"],
    tools: ["find", "grep"],
    commands: [
      { label: "Crontabs", cmd: "cat /etc/crontab && ls /etc/cron.d/ && crontab -l" },
      { label: "Systemd services", cmd: "systemctl list-unit-files --type=service | grep enabled" },
      { label: "Init scripts", cmd: "ls /etc/init.d/" },
      { label: "Profile scripts", cmd: "cat /etc/profile.d/*.sh" },
      { label: "LD_PRELOAD", cmd: "cat /etc/ld.so.preload 2>/dev/null; echo $LD_PRELOAD" },
      { label: "SUID binaries", cmd: "find / -perm -4000 -type f 2>/dev/null" }
    ]
  },

  // ==================== CRYPTO / ENCODING ====================
  {
    title: "Base Encoding / Decoding",
    description: "Decode base64, base32, hex, and other common encodings",
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
    title: "Hash Identification & Cracking",
    description: "Identify hash types and crack them",
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
    title: "XOR Analysis",
    description: "XOR brute force and decode for CTF challenges",
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

  // ==================== HASHING & INTEGRITY ====================
  {
    title: "File Hashing & Verification",
    description: "Generate and verify file hashes for integrity checking",
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

  // ==================== MALWARE ANALYSIS ====================
  {
    title: "Static Malware Analysis",
    description: "Initial static analysis of suspicious executables",
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
      { label: "PE imports", cmd: "python3 -c \"import pefile; pe=pefile.PE('{FILE}'); [print(e.dll.decode()) for e in pe.DIRECTORY_ENTRY_IMPORT]\"" }
    ]
  },
  {
    title: "Dynamic Malware Analysis",
    description: "Run and monitor suspicious files in a sandbox",
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

  // ==================== CTF QUICK WINS ====================
  {
    title: "CTF - Quick File Checks",
    description: "First things to try when you get an unknown file in a CTF",
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
    title: "CTF - Common Magic Bytes",
    description: "Reference for common file signatures (magic bytes)",
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
      { label: "Fix header (example)", cmd: "printf '\\x89\\x50\\x4e\\x47\\x0d\\x0a\\x1a\\x0a' | dd of={FILE} bs=1 count=8 conv=notrunc" }
    ]
  },
  {
    title: "CTF - ZIP / Archive Tricks",
    description: "Common CTF tricks with ZIP and archive files",
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

  // ==================== WINDOWS FILE PATHS ====================
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

  // ==================== WINDOWS REGISTRY PATHS ====================
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

  // ==================== LINUX FILE PATHS ====================
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

  // ==================== ADDITIONAL STEGANOGRAPHY ====================
  {
    title: "jsteg - JPEG Steganography",
    description: "Hide and reveal data in JPEG files using DCT coefficients (not detectable by steghide)",
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

  // ==================== CRYPTOGRAPHY (CTF-HEAVY) ====================
  {
    title: "CyberChef - Swiss Army Knife",
    description: "Web-based tool for encoding, decoding, encryption, compression, and data analysis",
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
    title: "Classic Ciphers Reference",
    description: "Common classical ciphers encountered in CTF challenges with solving tools",
    category: ["Crypto/Encoding"],
    phase: ["Analysis"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["dcode.fr"],
    commands: [
      { label: "Caesar / ROT", cmd: "# Brute force all 25 shifts:\nfor i in $(seq 1 25); do echo \"Shift $i:\"; echo '{ENCODED}' | tr $(printf '%b' $(printf '\\\\x%02x' $(seq $((65+i)) $((90))) $(seq 65 $((64+i))) $(seq $((97+i)) $((122))) $(seq 97 $((96+i))))) 'A-Za-z'; done\n# Or use: https://dcode.fr/caesar-cipher" },
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
    title: "RSA Attacks - CTF",
    description: "Common RSA attack vectors for CTF crypto challenges",
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
  },

  // ==================== ADDITIONAL FORENSICS ====================
  {
    title: "pdfcrack - PDF Password Cracking",
    description: "Brute force or dictionary attack on password-protected PDF files",
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
  {
    title: "dumpzilla - Browser Forensics",
    description: "Extract forensic data from Firefox/Thunderbird profiles (history, cookies, downloads, forms)",
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
  {
    title: "tcpflow - TCP Stream Reconstruction",
    description: "Reconstruct TCP sessions and extract transferred files from PCAP",
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
    title: "USB Keystroke Extraction from PCAP",
    description: "Extract keystrokes from USB HID keyboard captures (very common CTF challenge)",
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
    title: "photorec - File Carving",
    description: "Recover deleted files from disk images, memory cards, and drives",
    category: ["Disk", "File Analysis"],
    phase: ["Carving", "Recovery"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["photorec"],
    commands: [
      { label: "Interactive mode", cmd: "photorec {IMAGE}" },
      { label: "CLI mode", cmd: "photorec /d output/ /cmd {IMAGE} partition_none,options,mode_ext2,fileopt,everything,enable,search" },
      { label: "Specific file types", cmd: "photorec /d output/ /cmd {IMAGE} partition_none,fileopt,everything,disable,jpg,enable,search" }
    ],
    references: ["https://www.cgsecurity.org/wiki/PhotoRec"]
  },
  {
    title: "NTFS Alternate Data Streams (ADS)",
    description: "Detect and extract hidden data in NTFS Alternate Data Streams",
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
    title: "dcfldd - Forensic Imaging (Enhanced dd)",
    description: "Enhanced dd with built-in hashing, progress, and verification",
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
    title: "CTF - Additional Magic Bytes",
    description: "More file signatures for identification and header repair",
    category: ["File Analysis"],
    phase: ["Triage"],
    os: ["Linux", "Windows", "macOS"],
    tools: ["xxd"],
    commands: [
      { label: "GZIP", cmd: "# 1F 8B 08" },
      { label: "BZ2", cmd: "# 42 5A 68  (BZh)" },
      { label: "XZ", cmd: "# FD 37 7A 58 5A 00" },
      { label: "PCAPNG", cmd: "# 0A 0D 0D 0A" },
      { label: "SQLite", cmd: "# 53 51 4C 69 74 65 20 66 6F 72 6D 61 74  (SQLite format)" },
      { label: "OGG", cmd: "# 4F 67 67 53  (OggS)" },
      { label: "MP3 (ID3)", cmd: "# 49 44 33  (ID3)" },
      { label: "FLAC", cmd: "# 66 4C 61 43  (fLaC)" },
      { label: "WAV", cmd: "# 52 49 46 46 xx xx xx xx 57 41 56 45  (RIFF....WAVE)" },
      { label: "AVI", cmd: "# 52 49 46 46 xx xx xx xx 41 56 49 20  (RIFF....AVI )" },
      { label: "TAR", cmd: "# 75 73 74 61 72  at offset 0x101 (ustar)" },
      { label: "Java class", cmd: "# CA FE BA BE" },
      { label: "Mach-O (macOS)", cmd: "# FE ED FA CE (32-bit) / FE ED FA CF (64-bit)" }
    ]
  },

  // ==================== PASSWORD CRACKING CONVERTERS ====================
  {
    title: "John the Ripper - Hash Extractors (*2john)",
    description: "Extract crackable hashes from various file formats using *2john utilities",
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
    title: "impacket-secretsdump - SAM Hash Extraction",
    description: "Extract password hashes from SAM/SYSTEM registry hives or remotely",
    category: ["Crypto/Encoding", "Registry"],
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

  // ==================== REVERSE ENGINEERING ====================
  {
    title: "Ghidra - Reverse Engineering",
    description: "NSA's open-source reverse engineering framework for binary analysis",
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
    title: "GDB - Binary Debugging",
    description: "Debug executables, inspect memory, set breakpoints for RE and exploit dev",
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
    title: "pwntools - Exploit Development",
    description: "Python CTF framework for exploit development, binary interaction, and shellcode",
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

  // ==================== ESOTERIC LANGUAGES ====================
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

  // ==================== PCAP TOOLS ====================
  {
    title: "editcap / mergecap - PCAP Manipulation",
    description: "Convert, split, merge, and manipulate PCAP/PCAPNG files",
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
  }
];
