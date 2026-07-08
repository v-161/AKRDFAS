import hashlib
from pathlib import Path


class ModuleHasher:

    def __init__(self):
        pass

    def sha256(self, filepath):

        if filepath is None:
            return None

        path = Path(filepath)

        if not path.exists():
            return None

        sha = hashlib.sha256()

        try:

            with open(path, "rb") as f:

                while True:

                    data = f.read(65536)

                    if not data:
                        break

                    sha.update(data)

            return sha.hexdigest()

        except Exception:

            return None