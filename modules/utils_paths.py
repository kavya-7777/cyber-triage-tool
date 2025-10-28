import os
import glob

def resolve_artifact_path(case_id, artifact_id):
    """
    Try to resolve the actual file path for an artifact.
    Handles both normal and ZIP-extracted artifacts.
    """
    base = os.path.join("evidence", case_id, "artifacts")

    # 1️⃣ Normal path
    direct_path = os.path.join(base, artifact_id)
    if os.path.exists(direct_path):
        return direct_path

    # 2️⃣ ZIP uploads: search inside uploads/zip_*
    pattern = os.path.join(base, "uploads", "zip_*", f"{artifact_id}*")
    matches = glob.glob(pattern)
    if matches:
        return matches[0]

    return None
