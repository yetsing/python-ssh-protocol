from distutils.core import Extension, setup

module1 = Extension(
    "_umac",
    sources=[
        "_umacmodule.c",
        "rijndael.c",
        "umac.c",
        "umac128.c",
    ],
    include_dirs=["."],
)

setup(
    name="umac",
    version="1.0",
    description="This is a demo package",
    ext_modules=[module1],
)
