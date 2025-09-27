"""
heuristics.py

Refined heuristic anomaly checks for Cyber Triage Tool.

Features:
 - Streaming Shannon entropy calculation for files (works on arbitrarily large files)
 - Printable-byte ratio and top byte frequency diagnostics
 - Suspicious filename & path heuristics (double extensions, random-looking names, temp/download paths, long hex sequences)
 - Best-effort "unsigned executable" check for PE files using `pefile` if available (falls back gracefully)
 - Tunable scoring function that returns both component scores and final suspicion_score (0..100)
 - analyze_file(path) -> dict with metrics, flags, reasons, breakdown and suspicion_score
 - CLI: scan single file or recursively scan directories and print JSON reports

Usage:
    from heuristics import analyze_file
    r = analyze_file("evidence/case001/artifacts/abcd__invoice.pdf.exe")
"""

from __future__ import annotations
import os
import math
import json
import re
import argparse
from collections import defaultdict, Counter
from typing import Tuple, Dict, Any, List, Optional

# ---------------------------
# Tunables & thresholds
# ---------------------------

# Entropy thresholds (bits per byte)
ENTROPY_THRESHOLD = 7.2
ENTROPY_WARNING_THRESHOLD = 6.5

# Filename heuristics
FILENAME_CHAR_ENTROPY_THRESHOLD = 3.8
MAX_FILENAME_LEN = 80
HEXSEQ_RE = re.compile(r'[0-9A-Fa-f]{6,}')

# Suspicious extensions / directory patterns
SUSPICIOUS_EXTENSIONS = {'.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar', '.ps1', '.dll', '.sys'}
SUSPICIOUS_DIR_PATTERNS = [
    r'\\temp\\', r'\\tmp\\', r'/tmp/', r'\\appdata\\', r'\\local\\temp',
    r'/var/tmp', r'/home/.*/Downloads', r'/home/.*/\.cache', r'\\windows\\temp\\',
]

DOUBLE_EXT_RE = re.compile(r'\.[a-zA-Z0-9]{1,6}\.[a-zA-Z0-9]{1,6}$')

# Byte diagnostics
TOP_N_BYTES = 5
PRINTABLE_RATIO_CHUNK = 65536  # used to compute printable ratio in streaming

# Scoring weights (tune these to favor IOC/YARA/heuristics in a scoring engine)
WEIGHTS = {
    "entropy": 0.45,       # entropy-based weight
    "filename": 0.30,      # filename/path related signals
    "pe_unsigned": 0.25    # unsigned PE signal
}
# The final suspicion_score is scaled to 0..100 after applying these weights.

# ---------------------------
# Core helpers
# ---------------------------

def shannon_entropy_from_counts(counts: List[int], length: int) -> float:
    if length <= 0:
        return 0.0
    ent = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / length
        ent -= p * math.log2(p)
    return ent

def compute_file_entropy(path: str, chunk_size: int = 65536) -> float:
    """Streaming Shannon entropy (bits per byte)."""
    counts = [0] * 256
    total = 0
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            total += len(chunk)
            for b in chunk:
                counts[b] += 1
    return shannon_entropy_from_counts(counts, total)

def printable_ratio_and_top_bytes(path: str, sample_bytes: int = PRINTABLE_RATIO_CHUNK) -> Dict[str, Any]:
    """
    Compute printable ratio (ASCII printable fraction) and top N frequent bytes
    using first `sample_bytes` bytes (or entire file if smaller).
    """
    total = 0
    printable = 0
    counts = Counter()
    try:
        with open(path, 'rb') as f:
            data = f.read(sample_bytes)
            total = len(data)
            if total == 0:
                return {"printable_ratio": 0.0, "top_bytes": []}
            for b in data:
                counts[b] += 1
                # ASCII printable approx: 32-126 (space..~)
                if 32 <= b <= 126:
                    printable += 1
    except Exception:
        return {"printable_ratio": 0.0, "top_bytes": []}
    ratio = (printable / total) if total > 0 else 0.0
    top = counts.most_common(TOP_N_BYTES)
    top_bytes = [{"byte": tb, "count": cnt} for tb, cnt in top]
    return {"printable_ratio": ratio, "top_bytes": top_bytes}

def char_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    length = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent

# ---------------------------
# Filename & path heuristics
# ---------------------------

def suspicious_filename(path_or_name: str) -> Tuple[bool, List[str]]:
    """
    Evaluate the basename for suspicious patterns.
    Returns (flag, reasons[]).
    """
    reasons: List[str] = []
    name = os.path.basename(path_or_name or "")
    lower = name.lower()

    # double extension (e.g. invoice.pdf.exe)
    if DOUBLE_EXT_RE.search(name):
        final_ext = os.path.splitext(name)[1].lower()
        if final_ext in SUSPICIOUS_EXTENSIONS:
            reasons.append(f'double extension with executable ({name})')

    # suspicious extension
    _, ext = os.path.splitext(name)
    if ext.lower() in SUSPICIOUS_EXTENSIONS:
        reasons.append(f'suspicious extension "{ext}"')

    # long filename
    if len(name) > MAX_FILENAME_LEN:
        reasons.append(f'very long filename ({len(name)} chars)')

    # hex-like sequences
    if HEXSEQ_RE.search(name):
        reasons.append('contains long hex/hex-like sequence')

    # high character entropy
    ch_ent = char_entropy(name)
    if ch_ent >= FILENAME_CHAR_ENTROPY_THRESHOLD:
        reasons.append(f'high filename entropy ({ch_ent:.2f})')

    return (len(reasons) > 0, reasons)

def suspicious_path(path: str) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if not path:
        return False, reasons
    lower = path.replace('/', '\\').lower()
    for pat in SUSPICIOUS_DIR_PATTERNS:
        try:
            if re.search(pat, lower):
                reasons.append(f'path matches suspicious pattern: {pat}')
        except re.error:
            continue
    if 'downloads' in lower or '\\downloads' in lower:
        reasons.append('file in Downloads directory')
    return (len(reasons) > 0, reasons)

# ---------------------------
# PE checks
# ---------------------------

def is_pe_file(path: str) -> bool:
    try:
        with open(path, 'rb') as f:
            hdr = f.read(2)
            return hdr == b'MZ'
    except Exception:
        return False

def check_pe_signed(path: str) -> Dict[str, Optional[Any]]:
    """
    Best-effort check: returns {'signed': True/False/None, 'reason': str}
    - None means unknown (pefile missing or parse error)
    """
    try:
        import pefile
    except Exception:
        return {'signed': None, 'reason': 'pefile not installed - pip install pefile to enable PE signing checks'}

    try:
        pe = pefile.PE(path, fast_load=True)
        # Look for certificate table in data directories
        data_dirs = getattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY', []) or []
        for dd in data_dirs:
            name = getattr(dd, 'name', None)
            if name and 'SECURITY' in name.upper():
                size = getattr(dd, 'Size', None) or getattr(dd, 'Size', 0)
                if size and size > 0:
                    return {'signed': True, 'reason': f'certificate table present (size={size})'}
                else:
                    return {'signed': False, 'reason': 'certificate table present but size 0 (unsigned)'}
        # fallback: no cert table found
        return {'signed': False, 'reason': 'no security data directory found; likely unsigned'}
    except Exception as e:
        return {'signed': None, 'reason': f'error parsing PE: {e}'}

# ---------------------------
# Scoring utilities
# ---------------------------

def _score_entropy(entropy: float) -> float:
    """
    Map entropy -> 0..100 (component). Strong signal if entropy >= ENTROPY_THRESHOLD.
    """
    if entropy >= ENTROPY_THRESHOLD:
        return 100.0
    if entropy <= ENTROPY_WARNING_THRESHOLD:
        # linear scaling from 0..warning_threshold
        return max(0.0, (entropy / ENTROPY_WARNING_THRESHOLD) * 40.0)  # low signal under warning
    # between warning and threshold -> scale 40..90
    span = ENTROPY_THRESHOLD - ENTROPY_WARNING_THRESHOLD
    frac = (entropy - ENTROPY_WARNING_THRESHOLD) / (span if span > 0 else 1.0)
    return 40.0 + frac * 50.0  # yields up to ~90; rest may be given by filename/pe_unsigned

def _score_filename_flags(fname_flag: bool, n_reasons: int) -> float:
    """
    0..100 where presence of several filename reasons increases signal.
    """
    if not fname_flag:
        return 0.0
    # base 40 + up to 60 depending on number of reasons (cap)
    return min(100.0, 40.0 + min(n_reasons, 4) * 15.0)

def _score_pe_unsigned(unsigned_flag: Optional[bool]) -> float:
    if unsigned_flag is True:
        return 100.0
    if unsigned_flag is False:
        return 0.0
    # None => unknown (pefile missing) -> moderate small signal
    return 20.0

def clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))

# ---------------------------
# Main analyzer
# ---------------------------

def analyze_file(path: str,
                 entropy_threshold: float = ENTROPY_THRESHOLD,
                 entropy_warning: float = ENTROPY_WARNING_THRESHOLD) -> Dict[str, Any]:
    """
    Analyze a file and return a structured report.

    Keys returned:
    - path, filename, size, entropy, entropy_level
    - printable_ratio (sample), top_bytes (sample)
    - filename_suspicious, filename_reasons
    - path_suspicious, path_reasons
    - is_pe, pe_signed_check, unsigned_executable (True/False/None)
    - component_scores: {entropy_component, filename_component, pe_component}
    - suspicion_score: final integer 0..100
    - reasons: list of human-readable reasons
    """
    report: Dict[str, Any] = {}
    report['path'] = path
    report['filename'] = os.path.basename(path)

    # stat
    try:
        size = os.path.getsize(path)
    except Exception as e:
        report['error'] = f'unable to stat file: {e}'
        return report
    report['size'] = size

    # entropy
    try:
        ent = compute_file_entropy(path)
    except Exception as e:
        report['error'] = f'error computing entropy: {e}'
        return report
    report['entropy'] = ent

    # entropy level
    ent_level = 'normal'
    if ent >= entropy_threshold:
        ent_level = 'high'
    elif ent >= entropy_warning:
        ent_level = 'warning'
    report['entropy_level'] = ent_level

    # printable ratio and top bytes (sample)
    pr = printable_ratio_and_top_bytes(path)
    report.update(pr)

    # filename/path heuristics
    fname_flag, fname_reasons = suspicious_filename(report['filename'])
    path_flag, path_reasons = suspicious_path(path)
    report['filename_suspicious'] = fname_flag
    report['filename_reasons'] = fname_reasons
    report['path_suspicious'] = path_flag
    report['path_reasons'] = path_reasons

    # PE checks
    pe = is_pe_file(path)
    report['is_pe'] = pe
    if pe:
        pe_info = check_pe_signed(path)
        unsigned_flag = None
        if pe_info.get('signed') is False:
            unsigned_flag = True
        elif pe_info.get('signed') is True:
            unsigned_flag = False
        else:
            unsigned_flag = None
    else:
        pe_info = {'signed': None, 'reason': 'not a PE/Windows executable'}
        unsigned_flag = False

    report['pe_signed_check'] = pe_info
    report['unsigned_executable'] = unsigned_flag

    # Build human reasons (dedupe while preserving order)
    reasons: List[str] = []
    def add_reason(r: str):
        if r not in reasons:
            reasons.append(r)

    # entropy-related reasons
    if ent_level == 'high':
        add_reason(f'high entropy ({ent:.2f})')
    elif ent_level == 'warning':
        add_reason(f'moderate entropy ({ent:.2f})')

    # filename/path reasons
    for r in fname_reasons:
        add_reason(r)
    for r in path_reasons:
        add_reason(r)

    # PE reasons
    if unsigned_flag is True:
        add_reason('PE file appears unsigned')
    elif unsigned_flag is None and pe:
        add_reason('PE signature check unknown (pefile missing or parse error)')

    # component scores
    entropy_comp = _score_entropy(ent)          # 0..100
    filename_comp = _score_filename_flags(fname_flag, len(fname_reasons))
    pe_comp = _score_pe_unsigned(unsigned_flag)

    report['component_scores'] = {
        'entropy_component': int(round(entropy_comp)),
        'filename_component': int(round(filename_comp)),
        'pe_component': int(round(pe_comp))
    }

    # combine with WEIGHTS into final 0..100
    try:
        w_ent = WEIGHTS.get("entropy", 0.45)
        w_fname = WEIGHTS.get("filename", 0.30)
        w_pe = WEIGHTS.get("pe_unsigned", 0.25)
        # normalize components to 0..1
        comp = (
            (entropy_comp / 100.0) * w_ent +
            (filename_comp / 100.0) * w_fname +
            (pe_comp / 100.0) * w_pe
        )
        final_score = int(round(comp * 100.0))
    except Exception:
        final_score = int(round((entropy_comp + filename_comp + pe_comp) / 3.0))

    # clamp
    final_score = max(0, min(100, final_score))

    report['reasons'] = reasons
    report['suspicion_score'] = final_score

    return report

# ---------------------------
# CLI support
# ---------------------------

def _scan_path(path: str, recursive: bool = False) -> List[Dict[str, Any]]:
    reports = []
    if os.path.isfile(path):
        reports.append(analyze_file(path))
        return reports
    for root, dirs, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            try:
                reports.append(analyze_file(fp))
            except Exception as e:
                reports.append({'path': fp, 'error': str(e)})
        if not recursive:
            break
    return reports

def main(argv=None):
    p = argparse.ArgumentParser(description='Heuristic anomaly checks (entropy, filename, path, unsigned PE)')
    p.add_argument('path', help='file or directory to analyze')
    p.add_argument('-r', '--recursive', action='store_true', help='recurse directories')
    p.add_argument('-o', '--output', help='output JSON file')
    args = p.parse_args(argv)

    reports = _scan_path(args.path, recursive=args.recursive)
    out = json.dumps(reports, indent=2)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as fh:
            fh.write(out)
        print(f'Written {len(reports)} reports to {args.output}')
    else:
        print(out)

if __name__ == '__main__':
    main()
