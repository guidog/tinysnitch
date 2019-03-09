import setuptools

setuptools.setup(
    version="0.0.1",
    name="opensnitch",
    packages=['opensnitch'],
    install_requires=[
                      ],
    entry_points={'console_scripts': ['opensnitchd = opensnitch:main']},
)
