from setuptools import setup

setup(name='sysmon-bypass-finder',
      version='0.1',
      description='Find possible bypasses in sysmon policy',
      url='https://github.com/mkorman90/sysmon-config-bypass-finder',
      author='Martin Korman',
      author_email='martin@centauri.co.il',
      install_requires=['lxml', 'tabulate', 'click'],
      zip_safe=False,
      entry_points={
            'console_scripts': ['analyze-sysmon-config=sysmon_bypass_finder.main:analyze_config']
        }
      )
