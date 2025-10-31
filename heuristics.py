# heuristics.py

from __future__ import annotations
import os
import math
import json
import re
import argparse
import logging
from collections import defaultdict, Counter
from typing import Tuple, Dict, Any, List, Optional

logger = logging.getLogger(__name__)

ENTROPY_THRESHOLD = 7.2
ENTROPY_WARNING_THRESHOLD = 6.5

FILENAME_CHAR_ENTROPY_THRESHOLD = 3.8
MAX_FILENAME_LEN = 80
HEXSEQ_RE = re.compile(r'[0-9A-Fa-f]{6,}')

# Use forward-slash forms in patterns for easier normalization
SUSPICIOUS_DIR_PATTERNS = [
    r'/temp/', r'/tmp/', r'/appdata/', r'/local/temp/',
    r'/var/tmp', r'/home/.*/downloads', r'/home/.*/\.cache', r'/windows/temp/',
]

# compile these once for speed
try:
    SUSPICIOUS_DIR_PATTERNS_COMPILED = [re.compile(p, flags=re.IGNORECASE) for p in SUSPICIOUS_DIR_PATTERNS]
except re.error:
    SUSPICIOUS_DIR_PATTERNS_COMPILED = []

DOUBLE_EXT_RE = re.compile(r'\.[a-zA-Z0-9]{1,6}\.[a-zA-Z0-9]{1,6}$')

TOP_N_BYTES = 5
PRINTABLE_RATIO_CHUNK = 65536  # sample bytes for printable ratio

WEIGHTS = {
    "entropy": 0.45,
    "filename": 0.30,
    "pe_unsigned": 0.25
}

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

def compute_entropy_and_printable(path: str,
                                  chunk_size: int = 65536,
                                  sample_bytes: int = PRINTABLE_RATIO_CHUNK,
                                  max_entropy_bytes: Optional[int] = None
                                  ) -> Dict[str, Any]:
    counts = [0] * 256
    total = 0
    printable_sample = 0
    read_for_sample = 0

    try:
        with open(path, 'rb') as fh:
            while True:
                if max_entropy_bytes is not None and total >= max_entropy_bytes:
                    break
                to_read = chunk_size
                if max_entropy_bytes is not None:
                    to_read = min(to_read, max_entropy_bytes - total)
                    if to_read <= 0:
                        break
                chunk = fh.read(to_read)
                if not chunk:
                    break
                for b in chunk:
                    counts[b] += 1
                prev_total = total
                total += len(chunk)
                if prev_total < sample_bytes:
                    to_take = min(sample_bytes - prev_total, len(chunk))
                    for b in chunk[:to_take]:
                        if 32 <= b <= 126:
                            printable_sample += 1
                    read_for_sample += to_take
    except Exception as e:
        logger.debug("compute_entropy_and_printable read error on %s: %s", path, e)
        return {"entropy": 0.0, "printable_ratio": 0.0, "top_bytes": [], "scanned_bytes": 0}

    entropy = shannon_entropy_from_counts(counts, total)
    top = sorted([(i, counts[i]) for i in range(256)], key=lambda x: -x[1])[:TOP_N_BYTES]
    top_bytes = [{"byte": b, "hex": f"0x{b:02x}", "count": cnt} for b, cnt in top if cnt > 0]
    printable_ratio = (printable_sample / read_for_sample) if read_for_sample > 0 else 0.0

    return {"entropy": entropy, "printable_ratio": printable_ratio, "top_bytes": top_bytes, "scanned_bytes": total}

def compute_file_entropy(path: str, chunk_size: int = 65536) -> float:
    res = compute_entropy_and_printable(path, chunk_size=chunk_size, sample_bytes=0, max_entropy_bytes=None)
    return float(res.get("entropy", 0.0))


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

def suspicious_filename(path_or_name: str) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    name = os.path.basename(path_or_name or "")
    lower = name.lower()

    if DOUBLE_EXT_RE.search(name):
        final_ext = os.path.splitext(name)[1].lower()
        if final_ext in {'.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar', '.ps1', '.dll', '.sys'}:
            reasons.append(f'double extension with executable ({name})')

    _, ext = os.path.splitext(name)
    if ext.lower() in {'.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar', '.ps1', '.dll', '.sys'}:
        reasons.append(f'suspicious extension "{ext}"')

    if len(name) > MAX_FILENAME_LEN:
        reasons.append(f'very long filename ({len(name)} chars)')

    if HEXSEQ_RE.search(name):
        reasons.append('contains long hex/hex-like sequence')

    ch_ent = char_entropy(name)
    if ch_ent >= FILENAME_CHAR_ENTROPY_THRESHOLD:
        reasons.append(f'high filename entropy ({ch_ent:.2f})')

    return (len(reasons) > 0, reasons)

def suspicious_path(path: str) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if not path:
        return False, reasons

    norm = path.replace('\\', '/').lower()

    # Use the precompiled patterns
    for pat in SUSPICIOUS_DIR_PATTERNS_COMPILED:
        try:
            if pat.search(norm):
                reasons.append(f'path matches suspicious pattern: {pat.pattern}')
        except Exception:
            continue

    if '/downloads' in norm:
        reasons.append('file in Downloads directory')

    return (len(reasons) > 0, reasons)

def is_pe_file(path: str) -> bool:
    try:
        with open(path, 'rb') as f:
            hdr = f.read(2)
            return hdr == b'MZ'
    except Exception:
        return False


def check_pe_signed(path: str) -> Dict[str, Optional[Any]]:
    try:
        import pefile
    except Exception:
        return {'signed': None, 'reason': 'pefile not installed - pip install pefile to enable PE signing checks'}

    pe = None
    try:
        pe = pefile.PE(path, fast_load=True)
        # some pefile versions expose DIRECTORY_ENTRY_SECURITY
        try:
            sec = getattr(pe, 'DIRECTORY_ENTRY_SECURITY', None)
            if sec:
                return {'signed': True, 'reason': 'certificate table present (DIRECTORY_ENTRY_SECURITY)'}
        except Exception:
            pass

        # inspect DATA_DIRECTORY entries (robust fallback)
        try:
            dd_list = getattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY', []) or []
            for dd in dd_list:
                name = getattr(dd, 'name', None)
                size = getattr(dd, 'Size', None) if hasattr(dd, 'Size') else (getattr(dd, 'size', None) if hasattr(dd, 'size') else None)
                if name and 'SECURITY' in str(name).upper():
                    if size and int(size) > 0:
                        return {'signed': True, 'reason': f'certificate table present (size={size})'}
                    else:
                        return {'signed': False, 'reason': 'certificate table present but size 0 (unsigned)'}
        except Exception:
            # fall through to "no security" case
            pass

        # fallback: no cert table found
        return {'signed': False, 'reason': 'no security data directory found; likely unsigned'}
    except Exception as e:
        logger.debug("pefile parsing failed for %s: %s", path, e)
        return {'signed': None, 'reason': f'error parsing PE: {e}'}
    finally:
        # try to clean up resources if available
        try:
            if pe is not None:
                pe.close()
        except Exception:
            pass

def _score_entropy(entropy: float) -> float:
    if entropy >= ENTROPY_THRESHOLD:
        return 100.0
    if entropy <= ENTROPY_WARNING_THRESHOLD:
        return max(0.0, (entropy / ENTROPY_WARNING_THRESHOLD) * 40.0)
    span = ENTROPY_THRESHOLD - ENTROPY_WARNING_THRESHOLD
    frac = (entropy - ENTROPY_WARNING_THRESHOLD) / (span if span > 0 else 1.0)
    return 40.0 + frac * 50.0

def _score_filename_flags(fname_flag: bool, n_reasons: int) -> float:
    if not fname_flag:
        return 0.0
    return min(100.0, 40.0 + min(n_reasons, 4) * 15.0)

def _score_pe_unsigned(unsigned_flag: Optional[bool]) -> float:
    if unsigned_flag is True:
        return 100.0
    if unsigned_flag is False:
        return 0.0
    return 20.0

def clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))

def analyze_file(path: str,
                 entropy_threshold: float = ENTROPY_THRESHOLD,
                 entropy_warning: float = ENTROPY_WARNING_THRESHOLD,
                 compute_entropy: bool = True,
                 max_entropy_bytes: Optional[int] = None
                 ) -> Dict[str, Any]:
    report: Dict[str, Any] = {}
    report['path'] = path
    report['filename'] = os.path.basename(path)

    try:
        size = os.path.getsize(path)
    except Exception as e:
        report['error'] = f'unable to stat file: {e}'
        logger.debug("analyze_file stat failed for %s: %s", path, e)
        return report
    report['size'] = size

    # entropy + printable/top-bytes - single pass when requested
    if compute_entropy:
        try:
            ep = compute_entropy_and_printable(path, sample_bytes=PRINTABLE_RATIO_CHUNK, max_entropy_bytes=max_entropy_bytes)
            ent = float(ep.get('entropy', 0.0))
            printable_ratio = float(ep.get('printable_ratio', 0.0))
            top_bytes = ep.get('top_bytes', [])
            report['scanned_bytes'] = ep.get('scanned_bytes', 0)
        except Exception as e:
            report['error'] = f'error computing entropy: {e}'
            logger.exception("error computing entropy for %s", path)
            return report
    else:
        # lightweight: sample for printable/top-bytes, entropy set to 0
        try:
            with open(path, 'rb') as fh:
                data = fh.read(PRINTABLE_RATIO_CHUNK)
            printable = sum(1 for b in data if 32 <= b <= 126)
            printable_ratio = (printable / len(data)) if data else 0.0
            counts = Counter(data)
            top = counts.most_common(TOP_N_BYTES)
            top_bytes = [{"byte": tb, "hex": f"0x{tb:02x}", "count": cnt} for tb, cnt in top]
            ent = 0.0
            report['scanned_bytes'] = len(data)
        except Exception as e:
            report['error'] = f'error sampling file: {e}'
            logger.debug("sampling failed for %s: %s", path, e)
            return report

    report['entropy'] = ent
    ent_level = 'normal'
    if ent >= entropy_threshold:
        ent_level = 'high'
    elif ent >= entropy_warning:
        ent_level = 'warning'
    report['entropy_level'] = ent_level

    report['printable_ratio'] = printable_ratio
    report['top_bytes'] = top_bytes

    fname_flag, fname_reasons = suspicious_filename(report['filename'])
    path_flag, path_reasons = suspicious_path(path)
    report['filename_suspicious'] = fname_flag
    report['filename_reasons'] = fname_reasons
    report['path_suspicious'] = path_flag
    report['path_reasons'] = path_reasons

    pe = is_pe_file(path)
    report['is_pe'] = pe
    if pe:
        pe_info = check_pe_signed(path)
        unsigned_flag = None
        if isinstance(pe_info.get('signed'), bool):
            unsigned_flag = (not pe_info.get('signed'))
        else:
            unsigned_flag = None
    else:
        pe_info = {'signed': None, 'reason': 'not a PE/Windows executable'}
        unsigned_flag = False

    report['pe_signed_check'] = pe_info
    report['unsigned_executable'] = unsigned_flag

    reasons: List[str] = []

    def add_reason(r: str):
        if r not in reasons:
            reasons.append(r)

    if ent_level == 'high':
        add_reason(f'high entropy ({ent:.2f})')
    elif ent_level == 'warning':
        add_reason(f'moderate entropy ({ent:.2f})')

    for r in fname_reasons:
        add_reason(r)
    for r in path_reasons:
        add_reason(r)

    if unsigned_flag is True:
        add_reason('PE file appears unsigned')
    elif unsigned_flag is None and pe:
        add_reason('PE signature check unknown (pefile missing or parse error)')

    entropy_comp = _score_entropy(ent)
    filename_comp = _score_filename_flags(fname_flag, len(fname_reasons))
    pe_comp = _score_pe_unsigned(unsigned_flag)

    report['component_scores'] = {
        'entropy_component': int(round(entropy_comp)),
        'filename_component': int(round(filename_comp)),
        'pe_component': int(round(pe_comp))
    }

    try:
        w_ent = WEIGHTS.get("entropy", 0.45)
        w_fname = WEIGHTS.get("filename", 0.30)
        w_pe = WEIGHTS.get("pe_unsigned", 0.25)
        comp = (
            (entropy_comp / 100.0) * w_ent +
            (filename_comp / 100.0) * w_fname +
            (pe_comp / 100.0) * w_pe
        )
        final_score = int(round(comp * 100.0))
    except Exception:
        final_score = int(round((entropy_comp + filename_comp + pe_comp) / 3.0))

    final_score = max(0, min(100, final_score))

    report['reasons'] = reasons
    report['suspicion_score'] = final_score

    return report

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
    p.add_argument('--fast', action='store_true', help='fast mode: skip full entropy computation')
    p.add_argument('--max-bytes', type=int, help='limit bytes used for entropy computation (fast approximate)')
    p.add_argument('-o', '--output', help='output JSON file')
    args = p.parse_args(argv)

    reports = []
    if args.recursive:
        reports = _scan_path(args.path, recursive=True)
    else:
        if os.path.isfile(args.path):
            reports = [analyze_file(args.path, compute_entropy=not args.fast, max_entropy_bytes=args.max_bytes)]
        else:
            reports = _scan_path(args.path, recursive=False)

    out = json.dumps(reports, indent=2)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as fh:
            fh.write(out)
        print(f'Written {len(reports)} reports to {args.output}')
    else:
        print(out)

if __name__ == '__main__':
    # Simple logging setup for CLI use
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    main()
