from setuptools import setup, find_packages

setup(
    name='threatrecon',
    author='Bart Otten',
    version='1.0',
    author_email='bartotten@gmail.com',
    description='Threat Recon',
    license='GPL',
    packages=find_packages('src'),
    package_dir={ '' : 'src' },
    zip_safe=False,
    package_data={
        '' : [ '*.gif', '*.png', '*.conf', '*.mtz', '*.machine' ] # list of resources
    },
    install_requires=[
        'canari',
        'requests',
        'python-whois'
    ],
    dependency_links=[
        # custom links for the install_requires
    ]
)
