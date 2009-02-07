""" Main entry point for AntiSamy XSS scanning. """

from owasp.antisamy.scanexception import ScanException
from owasp.antisamy.scanresult import ScanResult

def scan(input, policy):
    """ Scan the given input using the given policy and return a resultset
        which can be analyzed.
        @param input
        @param policy
        @return ScanResult
        @raises ScanException
        @raises PolicyException
    """
    pass

