import subprocess


class ModuleMetadata:

    def __init__(self):
        pass

    def get(self, module_name):

        metadata = {
            "path": None,
            "author": None,
            "license": None,
            "description": None,
            "version": None,
            "depends": None
        }

        try:

            result = subprocess.run(
                ["modinfo", module_name],
                capture_output=True,
                text=True,
                check=True
            )

            for line in result.stdout.splitlines():

                if ":" not in line:
                    continue

                key, value = line.split(":", 1)

                key = key.strip()
                value = value.strip()

                if key == "filename":
                    metadata["path"] = value

                elif key == "author":
                    metadata["author"] = value

                elif key == "license":
                    metadata["license"] = value

                elif key == "description":
                    metadata["description"] = value

                elif key == "version":
                    metadata["version"] = value

                elif key == "depends":
                    metadata["depends"] = value

        except Exception:
            pass

        return metadata