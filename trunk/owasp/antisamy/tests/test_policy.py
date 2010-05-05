import os
from nose import tools as NT
from owasp.antisamy import policy


class TestPolicyObject(object):

    def test_constructor(self):
        self.policy = policy.Policy()
        assert True


class TestPolicyParserForCoreAntisamyXml(object):

    def setup(self):
        self.filename = os.path.join(os.path.dirname(__file__),
                "../data/antisamy.xml")
        self.parser = policy.PolicyParser(self.filename)
        self.policy = self.parser.parse()

    def test_constructor(self):
        assert self.parser is not None

    def test_objectifies_policy_file(self):
        assert self.parser.xml is not None

    def test_parses_common_regular_expressions(self):
        assert self.policy.regexps
        NT.assert_equals(len(self.policy.regexps), 34)

    def test_parses_directives(self):
        assert self.policy.directives
        NT.assert_equals(len(self.policy.directives), 8)
        NT.assert_equals(self.policy.directives["omitXmlDeclaration"], True)
        NT.assert_equals(self.policy.directives["maxInputSize"], 200000)
        NT.assert_equals(self.policy.directives["embedStyleSheets"], False)

