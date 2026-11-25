"""Entrada de compatibilidade para a interface do NetProbe no terminal."""

if __package__:
    from .terminal import main
else:
    from terminal import main


if __name__ == "__main__":
    main()
