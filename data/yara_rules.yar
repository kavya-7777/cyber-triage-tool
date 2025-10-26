//
// data/yara_rules.yar
// Refined YARA rule set for Cyber Triage Tool (demo)
// - Added meta.severity and meta.tlp where helpful
// - Auto-generated IOC rules include severity = "high"
// - Rules are still safe: many rules match ASCII fragments; stronger hash rules are included as comments
//

import "pe"
import "hash"

/////////////////////////////////////////////////////////////////////////
// Demo / handcrafted rules (with meta.severity)
/////////////////////////////////////////////////////////////////////////

rule CT_Ransomware_Generic
{
  meta:
    description = "Heuristic: strings/markers typical of generic ransomware families (demo)"
    author = "Cyber Triage Tool"
    severity = "critical"
    tlp = "TLP:WHITE"
    tags = "ransomware,critical"
  strings:
    $s1 = "ENCRYPTED_BY" ascii wide nocase
    $s2 = "YOUR FILES ARE ENCRYPTED" ascii wide nocase
  condition:
    any of ($s1, $s2)
}

rule CT_Suspicious_Filenames
{
  meta:
    description = "Matches common suspicious filenames (demo)"
    author = "Cyber Triage Tool"
    severity = "high"
    tags = "filename,suspicious"
  strings:
    $s1 = "evil.exe" ascii nocase
    $s2 = "triple_demo.exe" ascii nocase
    $s3 = "invoice.pdf.exe" ascii nocase
  condition:
    any of them
}

rule CT_Possible_Packed_File
{
  meta:
    description = "Heuristic: many consecutive non-printable bytes near start -> possible packer/encoded payload"
    author = "Cyber Triage Tool"
    severity = "medium"
    tags = "packer,heuristic"
  strings:
    // regex for a run of many non-printable bytes (tunable)
    $s = /[\x00-\x08\x0E-\x1F]{8,}/
  condition:
    $s
}

rule CT_Domain_or_IP_IoC
{
  meta:
    description = "Detect known bad domain or IP in file contents"
    author = "Cyber Triage Tool"
    severity = "high"
    tags = "ioc,domain,ip"
  strings:
    $domain = "bad.example.com" ascii nocase
    $ip = "192.0.2.1"
  condition:
    any of them
}

rule CT_Sample_SHA256_ASCII
{
  meta:
    description = "Match ASCII hex representation of sample SHA256 fragments (demo)"
    author = "Cyber Triage Tool"
    severity = "high"
    tags = "ioc,hash"
  strings:
    // these are ASCII hex fragments (safe, non-binary). Useful for matching textual dumps.
    $h1 = "00979047eff88ef31a3279dc91bc28f2bbf9ff7f4672a98916b08f06da88ca7a" ascii nocase
    $h2 = "59b924ce8d73ad4573acf8f8b3260477f3adffae05b59de50162e4cb0b1d5e88" ascii nocase
    $h3 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ascii nocase
  condition:
    any of them
}

/////////////////////////////////////////////////////////////////////////
// Auto-generated IOC rules (based on data/ioc.json) with meta.severity
// These are conservative (ASCII/text) matches for safe demo operation.
// If you want exact file-hash matching, enable the commented hash rules below
/////////////////////////////////////////////////////////////////////////

rule CT_IOC_Filenames
{
  meta:
    description = "IOCs: filenames (auto-generated)"
    author = "Cyber Triage Tool"
    severity = "high"
    tags = "ioc,filename"
  strings:
    $fn0 = "evil.exe" ascii nocase
    $fn1 = "triple_demo.exe" ascii nocase
    $fn2 = "invoice.pdf.exe" ascii nocase
  condition:
    any of them
}

rule CT_IOC_Domains_IPs
{
  meta:
    description = "IOCs: domains and IPs (auto-generated)"
    author = "Cyber Triage Tool"
    severity = "high"
    tags = "ioc,domain,ip"
  strings:
    $d0 = "bad.example.com" ascii nocase
    $d1 = "192.0.2.1"
  condition:
    any of them
}

rule CT_IOC_hash_00979047
{
  meta:
    description = "IOC: hash fragment (auto-generated)"
    author = "Cyber Triage Tool"
    severity = "high"
    tags = "ioc,hash"
  strings:
    $h = "00979047eff88ef31a3279dc91bc28f2bbf9ff7f4672a98916b08f06da88ca7a" ascii nocase
  condition:
    $h
}

/*
If you want exact SHA256 file matching and your YARA build supports the 'hash' module,
you can add a rule like below (commented out for portability):

rule CT_IOC_hash_exact_00979047
{
  meta:
    description = "Exact SHA256 match (requires 'hash' module)"
    author = "Cyber Triage Tool"
    severity = "critical"
    tags = "ioc,hash,critical"
  condition:
    hash.sha256(0, filesize) == "00979047eff88ef31a3279dc91bc28f2bbf9ff7f4672a98916b08f06da88ca7a"
}
*/

rule CT_IOC_hash_59b924ce
{
  meta:
    description = "IOC: hash fragment (auto-generated)"
    author = "Cyber Triage Tool"
    severity = "high"
    tags = "ioc,hash"
  strings:
    $h = "59b924ce8d73ad4573acf8f8b3260477f3adffae05b59de50162e4cb0b1d5e88" ascii nocase
  condition:
    $h
}

rule CT_IOC_hash_e3b0c442
{
  meta:
    description = "IOC: hash fragment (auto-generated) - benign empty-hash example"
    author = "Cyber Triage Tool"
    severity = "low"
    tags = "ioc,hash,benign"
  strings:
    $h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ascii nocase
  condition:
    $h
}

/////////////////////////////////////////////////////////////////////////
// End of rules
/////////////////////////////////////////////////////////////////////////