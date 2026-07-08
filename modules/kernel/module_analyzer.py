import subprocess


class ModuleAnalyzer:

    def __init__(self):

        pass

    def enumerate_modules(self):

        modules = []

        try:

            result = subprocess.run(
                ["lsmod"],
                capture_output=True,
                text=True,
                check=True
            )

            lines = result.stdout.splitlines()

            # Skip header
            for line in lines[1:]:

                parts = line.split()

                if len(parts) < 3:
                    continue

                name = parts[0]

                size = int(parts[1])

                used = int(parts[2])

                dependencies = []

                if len(parts) > 3:

                    if parts[3] != "-":

                        dependencies = [
                            x.strip()
                            for x in parts[3].split(",")
                            if x.strip()
                        ]

                modules.append({

                    "name": name,

                    "size": size,

                    "used_by": used,

                    "dependencies": dependencies

                })

        except Exception as e:

            print("Module Enumeration Error:", e)

        return modules