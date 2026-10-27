from setuptools import setup, find_packages

setup(
    name="flagmap",
    version="1.6.1",
    description="Scan CTF challenge source code for common web-exploitation vuln patterns, with suggested payloads.",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        # Structural (AST) matching engine for Python/JS/PHP — see
        # ast_engine.py and the README's "Architecture" section. Optional at
        # runtime in the sense that flagmap still works without them (it
        # falls back to the legacy regex engine for every language, same as
        # pre-1.0 behavior), but you want these installed to get the real
        # improvement this version is about.
        "tree-sitter>=0.21",
        "tree-sitter-python>=0.21",
        "tree-sitter-javascript>=0.21",
        "tree-sitter-php>=0.21",
        "tree-sitter-go>=0.21",
        "tree-sitter-java>=0.21",
        "tree-sitter-ruby>=0.21",
        "tree-sitter-lua>=0.2",
        "tree-sitter-rust>=0.21",
    ],
    entry_points={
        "console_scripts": [
            "flagmap=flagmap.cli:main",
        ],
    },
)
