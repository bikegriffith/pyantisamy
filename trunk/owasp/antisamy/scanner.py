""" Main entry point for AntiSamy XSS scanning. """

from owasp.antisamy.scanexception import ScanException
from owasp.antisamy.scanresult import ScanResult

DEFAULT_ENCODING = "utf-8"

def scan(input, policy, input_encoding=DEFAULT_ENCODING,
        output_encoding=DEFAULT_ENCODING):
    """ Scan the given input using the given policy and return a resultset
        which can be analyzed.
        @param input Untrusted HTML which may contain malicious code.
        @param policy The Policy object which determines rules for scanning.
        @param input_encoding The encoding of the input.
        @param output_encoding The desired encoding of the output.
        @return A CleanResults object which contains information about the scan (including the results).
        @raises ScanException When there is a problem encountered while scanning the HTML.
        @raises PolicyException When there is a problem reading the policy file.
    """
    pass

