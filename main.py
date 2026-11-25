"""Inicia o menu em um ambiente virtual local do NetProbe."""

import hashlib
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path


RAIZ = Path(__file__).resolve().parent
AMBIENTE = RAIZ / ".venv"
REQUISITOS = RAIZ / "requirements.txt"
MARCADOR = AMBIENTE / ".netprobe-requirements"
CHECAR_PYTHON = "import sys; raise SystemExit(sys.version_info < (3, 10))"
CHECAR_DEPENDENCIAS = (
    "from importlib.util import find_spec; "
    "raise SystemExit(not all(find_spec(nome) for nome in ('scapy', 'rich', 'psutil', 'icmplib')))"
)


@contextmanager
def _bloquear_preparacao():
    """Impede duas instâncias de instalar no mesmo ambiente ao mesmo tempo."""
    AMBIENTE.mkdir(exist_ok=True)
    with (AMBIENTE / ".netprobe-setup.lock").open("a+b") as arquivo:
        arquivo.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(arquivo.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(arquivo, fcntl.LOCK_EX)
        yield


def _executar(python: Path, *args: str, silencioso: bool = False) -> int:
    saida = subprocess.DEVNULL if silencioso else None
    return subprocess.run(
        [str(python), "-E", "-X", "utf8", *args], cwd=RAIZ, stdout=saida, stderr=saida,
    ).returncode


def _preparar_ambiente() -> Path:
    python = AMBIENTE / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    assinatura = hashlib.sha256(REQUISITOS.read_bytes()).hexdigest().encode("ascii")

    with _bloquear_preparacao():
        if not python.is_file() or _executar(python, "-c", CHECAR_PYTHON, silencioso=True):
            try:
                import venv
            except ModuleNotFoundError as erro:
                raise RuntimeError("Instale o módulo venv do Python. No Linux, ele costuma vir no pacote python3-venv.") from erro

            print("Preparando o ambiente virtual local...", flush=True)
            venv.create(AMBIENTE, symlinks=os.name != "nt")

        if (
            MARCADOR.is_file()
            and MARCADOR.read_bytes() == assinatura
            and _executar(python, "-c", CHECAR_DEPENDENCIAS, silencioso=True) == 0
        ):
            return python

        print("Instalando as dependências do NetProbe...", flush=True)
        if _executar(python, "-m", "pip", "--version", silencioso=True) != 0:
            if _executar(python, "-m", "ensurepip", "--upgrade") != 0:
                raise RuntimeError("O Python precisa dos módulos venv e ensurepip. No Linux, instale o pacote python3-venv da sua distribuição.")

        if _executar(python, "-m", "pip", "install", "--disable-pip-version-check", "-r", str(REQUISITOS)) != 0:
            raise RuntimeError("A instalação das dependências falhou. Confira a conexão com o índice de pacotes e as mensagens acima.")
        if _executar(python, "-c", CHECAR_DEPENDENCIAS, silencioso=True) != 0:
            raise RuntimeError("O ambiente virtual não carregou todas as dependências após a instalação.")

        MARCADOR.write_bytes(assinatura)
    return python


def main() -> int:
    if sys.version_info < (3, 10):
        print("O NetProbe precisa do Python 3.10 ou superior.", file=sys.stderr)
        return 1

    try:
        python = _preparar_ambiente()
        return _executar(python, "-m", "src.interface.terminal")
    except (OSError, RuntimeError, subprocess.SubprocessError) as erro:
        print(f"Não foi possível iniciar o NetProbe. {erro}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
