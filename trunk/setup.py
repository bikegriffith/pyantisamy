from setuptools import setup, find_packages

setup(
    name='pyantisamy',
    version='0.1alpha',
    description="OWASP AntiSamy XSS Prevention",
    long_description="""The OWASP AntiSamy project is an API for safely allowing users to supply their own HTML and CSS without exposure to XSS vulnerabilities.""",
    author="Mike Griffith",
    author_email="mike@mike-griffith.com",
    url="http://www.mike-griffith.com",
    
    # package up all .py's under here, as well as all .xml's and .cfg's
    packages=find_packages(),
    package_data={'': ['*.xml', '*.xsd', '*.cfg']},
    
    # make sure user has lxml and cssutils
    install_requires=['lxml>=2.0', 'cssutils>=0.9'],
)

#
# Execute the following to create the egg
# $ python setup.py bdist_egg
# See more about setuptools at http://ianbicking.org/docs/setuptools-presentation/
#
