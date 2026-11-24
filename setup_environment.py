"""Create or reuse the shared environment and install both frameworks."""

import subprocess
import sys
import venv
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def setup(root: Path) -> None:
    environment = root / ".venv"
    python = (environment / "Scripts" / "python.exe" if sys.platform == "win32"
              else environment / "bin" / "python")
    if not environment.exists():
        print(f"Creating virtual environment: {environment}", flush=True)
        venv.create(environment, with_pip=True)
    elif not (environment / "pyvenv.cfg").is_file() or not python.is_file():
        raise RuntimeError(f"{environment} exists but is not a valid virtual environment; inspect it before proceeding.")
    else:
        print(f"Reusing virtual environment: {environment}", flush=True)

    version_check = (
        "import sys; "
        f"expected = {sys.version_info[:2]!r}; "
        "actual = sys.version_info[:2]; "
        "sys.stderr.write(f'Existing environment uses Python {actual[0]}.{actual[1]}; "
        "setup uses {expected[0]}.{expected[1]}. Use a matching Python or inspect "
        "the environment before replacing it.\\n') if actual != expected else None; "
        "sys.exit(actual != expected)"
    )
    subprocess.run([str(python), "-c", version_check], check=True)
    subprocess.run([str(python), "-m", "pip", "install", "-r", str(root / "requirements.txt")], check=True)
    subprocess.run([str(python), "-m", "pip", "check"], check=True)
    print("Environment ready.", flush=True)


def main() -> int:
    try:
        setup(ROOT)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Environment setup failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
