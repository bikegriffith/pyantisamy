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

    def test_parses_all_common_regular_expressions(self):
        assert self.policy.regexps
        NT.assert_equals(len(self.policy.regexps), 34)

    def test_parses_all_directives(self):
        assert self.policy.directives
        NT.assert_equals(len(self.policy.directives), 8)

    def test_guesses_correct_type_on_directives(self):
        NT.assert_equals(self.policy.directives["omitXmlDeclaration"], True)
        NT.assert_equals(self.policy.directives["maxInputSize"], 200000)
        NT.assert_equals(self.policy.directives["embedStyleSheets"], False)

    def test_parses_global_tag_attribute_names(self):
        assert self.policy.global_attributes
        NT.assert_equals(len(self.policy.global_attributes), 5)
        NT.assert_equals(self.policy.global_attributes,
                ["id", "style", "title", "class", "lang"])

    def test_parses_all_attributes(self):
        assert self.policy.attributes
        NT.assert_equals(len(self.policy.attributes), 42)

    def test_parsed_attributes_should_have_regular_expression_validators(self):
        NT.assert_equals(self.policy.attributes["class"].valid_regexps,
                ["htmlClass"])

    def test_parsed_attributes_should_have_a_list_of_valid_literals(self):
        NT.assert_equals(self.policy.attributes["media"].valid_literals,
                ["screen", "tty", "tv", "projection", "handheld", "print",
                        "braille", "aural", "all"])

    def test_parsed_attributes_should_have_both_regexp_and_literal_validators(self):
        attribute = self.policy.attributes["href"]
        NT.assert_equals(attribute.valid_regexps,
                ["onsiteURL", "offsiteURL"])
        NT.assert_equals(attribute.valid_literals,
                ["javascript:history.go(0)",
                 "javascript:history.go(-1)",
                 "javascript:void(0)",
                 "javascript:location.reload()"])

