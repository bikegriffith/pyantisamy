import os
from nose import tools as NT
from owasp.antisamy import policy


class TestPolicyObject(object):

    def test_constructor(self):
        self.policy = policy.Policy()
        assert True


class TestPolicyParser(object):

    def setup(self):
        self.filename = os.path.join(os.path.dirname(__file__),
                "../data/antisamy.xml")
        self.parser = policy.PolicyParser(self.filename)

    def test_constructor(self):
        assert self.parser

    def test_objectifies_policy_file(self):
        assert self.parser.policy_obj

    def test_parses_common_regular_expressions(self):
        policy = self.parser.parse()
        assert policy.regexps
        NT.assert_equals(len(policy.regexps), 34)


