"""
Cython build configuration for omnibioai-security-sdk IP protection.
Usage: python setup.py build_ext --inplace
"""
import os
from setuptools import setup, find_packages
from Cython.Build import cythonize
from Cython.Compiler import Options
from setuptools.extension import Extension

Options.annotate = False

EXTENSIONS = [
    "middleware/policy.py",
    "middleware/s2s.py",
    "auth/service.py",
    "policy/client.py",
    "iam/client.py",
    "iam/cache.py",
]


def make_extensions(paths):
    exts = []
    for p in paths:
        if not os.path.exists(p):
            print(f"WARNING: {p} not found, skipping")
            continue
        module = p.replace("/", ".").replace("\\", ".").removesuffix(".py")
        exts.append(Extension(module, [p]))
    return exts


setup(
    name="omnibioai-security-sdk",
    packages=find_packages(exclude=["tests*", "migrations*"]),
    ext_modules=cythonize(
        make_extensions(EXTENSIONS),
        compiler_directives={
            "language_level": "3",
            "boundscheck": False,
            "wraparound": False,
            "cdivision": True,
        },
        nthreads=os.cpu_count() or 4,
    ),
    zip_safe=False,
)
