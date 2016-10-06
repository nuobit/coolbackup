from distutils.core import setup

setup(name='coolbackup',
      version='0.1',
      author="NuoBiT Solutions, S.L., Eric Antones",
      author_email='eantones@nuobit.com',
      package_dir={'coolbackup': 'src'},
      packages=['coolbackup'],
      entry_points={
        'console_scripts': [
            'coolbackup=coolbackup.coolbackup:main',
        ],
      },
      install_requires=[
        'psutil',
        'pyyaml',
        'paramiko',
        'coolemail>=0.1',
        'imapbackup>=0.1',
        'attrdict',
      ],
      url='https://github.com/nuobit/coolbackup',
      # download_url = 'https://github.com/eantones/imapbackup/archive/0.1.tar.gz',
      keywords=['imap', 'files', 'backup', 'incremental'],
      license='AGPLv3+',
      platform='Linux',
      description='Incremental backup',
      long_description='Backs up from diferent sources',
      classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Operating System :: POSIX :: Linux',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.5',
        'Topic :: System :: Archiving :: Backup',
        'Topic :: System :: Filesystems',
        'Topic :: Communications :: Email',
      ]
      #data_files=[('config.samples', ['config.samples/servers.conf.d/01sample1.conf', 'config.samples/logger.conf']),
      #          ],
      #package_data={'coolbackup': ['config.samples/servers.conf.d/01sample1.conf', 'config.samples/logger.conf']},

)
