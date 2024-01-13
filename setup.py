"""Setup script for torshammer"""

import setuptools


# Get version information without importing the package
SHORT_DESCRIPTION = "Tor's Hammer"
LONG_DESCRIPTION = open('README.md', 'rt').read()

CLASSIFIERS = [
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
    'Programming Language :: Python :: 3.11.4',
    'Programming Language :: Python :: Implementation :: PyPy',
    'Topic :: Software Development :: Build Tools',
]

setuptools.setup(
    name='torshammer',
    version='1.0.0',
    description=SHORT_DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    author='jayluxferro',
    author_email='securityteam@sperixlabs.org',
    url='https://github.com/jayluxferro/torshammer',
    packages=setuptools.find_packages(),
    license='GPLv3+',
    platforms=['any'],
    keywords='distutils setuptools egg pip requirements',
    classifiers=CLASSIFIERS,
    entry_points={
        'console_scripts': [
            'torshammer = src.__init__:run',
        ],
    },
)
