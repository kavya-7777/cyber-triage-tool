//
// data/yara_rules.yar
// Combined starter YARA rule set for Cyber Triage Tool
// - Human-readable demo rules (PE imports, sections, packing heuristics)
// - IOC-derived rules (filenames, domains, IPs, hash-fragments) auto-generated from data/ioc.json
// NOTE: rules using `pe` require yara-python built with PE support. If your runtime lacks the PE
// module, `pe`-based rules will simply not match but won't crash the scanner.
//

/**************************************************************************
 * Demo / handcrafted rules
 **************************************************************************/

import "pe"
import "hash"

rule CT_Suspicious_Filenames
{
  meta:
    description = "Matches common suspicious filenames (demo)"
    author = "Cyber Triage Tool"
  strings:
    $s1 = "evil.exe" ascii nocase
    $s2 = "triple_demo.exe" ascii nocase
    $s3 = "invoice.pdf.exe" ascii nocase
  condition:
    any of them
}

rule CT_Domain_or_IP_IoC
{
  meta:
    description = "Detect known bad domain or IP in file contents"
    author = "Cyber Triage Tool"
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
  strings:
    // these are ASCII hex fragments (safe, non-binary). Useful for matching textual dumps.
    $h1 = "00979047eff88ef31a3279dc91bc28f2bbf9ff7f4672a98916b08f06da88ca7a" ascii nocase
    $h2 = "59b924ce8d73ad4573acf8f8b3260477f3adffae05b59de50162e4cb0b1d5e88" ascii nocase
    $h3 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ascii nocase
  condition:
    any of them
}

rule CT_Possible_Packed_File
{
  meta:
    description = "Heuristic: many consecutive non-printable bytes near start -> possible packer/encoded payload"
    author = "Cyber Triage Tool"
  strings:
    // regex for a run of many non-printable bytes (tunable)
    $s = /[\x00-\x08\x0E-\x1F]{8,}/
  condition:
    $s
}

/**************************************************************************
 * Auto-generated IOC rules (based on data/ioc.json)
 *
 * These were created from your sample IOC file:
 *  filenames: evil.exe, triple_demo.exe
 *  domains: bad.example.com
 *  ips: 192.0.2.1
 *  hashes: three sha256 strings
 *
 * The rules below are conservative (ASCII/text matches) to be safe and easy
 * to understand during a demo. You can replace/add binary-hex matches later.
 **************************************************************************/

rule CT_IOC_Filenames
{
  meta:
    description = "IOCs: filenames (auto-generated)"
    author = "Cyber Triage Tool"
  strings:
    $fn0 = "evil.exe" ascii nocase
    $fn1 = "triple_demo.exe" ascii nocase
  condition:
    any of them
}

rule CT_IOC_Domains_IPs
{
  meta:
    description = "IOCs: domains and IPs (auto-generated)"
    author = "Cyber Triage Tool"
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
  strings:
    $h = "00979047eff88ef31a3279dc91bc28f2bbf9ff7f4672a98916b08f06da88ca7a" ascii nocase
  condition:
    $h
}

rule CT_IOC_hash_59b924ce
{
  meta:
    description = "IOC: hash fragment (auto-generated)"
    author = "Cyber Triage Tool"
  strings:
    $h = "59b924ce8d73ad4573acf8f8b3260477f3adffae05b59de50162e4cb0b1d5e88" ascii nocase
  condition:
    $h
}

rule CT_IOC_hash_e3b0c442
{
  meta:
    description = "IOC: hash fragment (auto-generated)"
    author = "Cyber Triage Tool"
  strings:
    $h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ascii nocase
  condition:
    $h
}

/**************************************************************************
 * End of rules
 **************************************************************************/
