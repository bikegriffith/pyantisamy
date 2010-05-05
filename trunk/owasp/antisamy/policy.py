""" This file holds the model and parsing logic for our policy engine.  Policy
    files are stored in xml documents.  Some sample ones are included in the
    data module in this package.
"""

import re
from lxml import objectify

def from_file(filename):
    """ generate a policy object from the given file """
    return PolicyParser(filename).parse()


DEFAULT_POLICY_URI = "data/antisamy.xml"
DEFAULT_ONINVALID = "removeAttribute"
DEFAULT_MAX_INPUT_SIZE = 100000
DEFAULT_MAX_STYLESHEET_IMPORTS = 1
OMIT_XML_DECLARATION = "omitXmlDeclaration"
OMIT_DOCTYPE_DECLARATION = "omitDoctypeDeclaration"
MAX_INPUT_SIZE = "maxInputSize"
USE_XHTML = "useXHTML"
FORMAT_OUTPUT = "formatOutput"
EMBED_STYLESHEETS = "embedStyleSheets"
CONNECTION_TIMEOUT = "connectionTimeout"
REGEXP_BEGIN = '^'
REGEXP_END = '$'


class Policy(object):
    """ Policy and rules engine for XSS scanning. """

    tag_names = ()

    def __init__(self, regexps=None, attributes=None, tag_rules=None,
            css_rules=None, directives=None, global_attributes=None):
        self.regexps = regexps
        self.attributes = attributes
        self.tag_rules = tag_rules
        self.css_rules = css_rules
        self.directives = directives
        self.global_attributes = global_attributes


class Attribute(object):
    """ an html attribute and its rules """

    def __init__(self, name, description=None, valid_regexps=None,
            valid_literals=None):
        self.name = name
        self.description = description
        self.valid_regexps = valid_regexps
        self.valid_literals = valid_literals


class Tag(object):
    """ an html element and its rules """

    def __init__(self, name, action, attributes=None):
        self.name = name
        self.action = action
        self.attributes = attributes


class PolicyParser(object):

    def __init__(self, policy_file):
        self.xml = objectify.parse(policy_file).getroot()
        self._regexps = None
        self._attributes = None

    def parse(self):
        """ Parse all of the top-level elements in the specified config file.
            @return Policy
        """
        self._regexps = self.parse_regexps()
        self._attributes = self.parse_attributes()
        return Policy(regexps=self._regexps,
                      attributes=self._attributes,
                      tag_rules=self.parse_tag_rules(),
                      css_rules=self.parse_css_rules(),
                      directives=self.parse_directives(),
                      global_attributes=self.parse_global_attributes())

    def parse_regexps(self):
        """ Parse the <common-regexps> section of the config file. """
        regexps = getattr(self.xml, "common-regexps").findall("regexp")
        parsed = {}
        for regexp in regexps:
            name = regexp.get("name")
            parsed[name] = self._to_regexp(regexp.get("value"))
        return parsed

    def _to_regexp(self, value):
        try:
            return re.compile(value)
        except Exception, ex:
            raise ValueError("Invalid regular expression ({0}): {1}"
                    .format(ex, value))

    def parse_directives(self):
        """ Parse the <directives> section of the config file. """
        directives = getattr(self.xml, "directives").findall("directive")
        parsed = {}
        for directive in directives:
            name = directive.get("name")
            value = directive.get("value")
            parsed[name] = self._guess_type(value)
        return parsed

    def parse_attributes(self):
        """ Parse the <common-attributes> section of the config file. """
        attributes = getattr(self.xml,
                "common-attributes").findall("attribute")
        parsed = {}
        for attribute in attributes:
            parsed[attribute.get("name")] = self._get_attribute(attribute)
        return parsed

    def _get_attribute(self, attribute):
        name = attribute.get("name")
        description = attribute.get("description")
        regexps = getattr(attribute, "regexp-list", None)
        literals = getattr(attribute, "literal-list", None)
        if regexps is not None:
            compiled_regexps = []
            for r in regexps.findall("regexp"):
                if r.get("name") is not None:
                    compiled_regexps.append(self._regexps[r.get("name")])
                else:
                    compiled_regexps.append(self._to_regexp(r.get("value")))
            regexps = compiled_regexps
        if literals is not None:
            literals = [l.get("value") for l in literals.findall("literal")]
        return Attribute(name, description=description,
                valid_regexps=regexps, valid_literals=literals)

    def parse_global_attributes(self):
        """ Parse the <global-tag-attributes> (id, style, etc.) section of the
            config file.
        """
        attributes = getattr(self.xml,
                "global-tag-attributes").findall("attribute")
        return [self._attributes[attribute.get("name")]
                    for attribute in attributes]

    def parse_tag_rules(self):
        """ Parse the <tag-rules> (restrictions) section of the config file.
        """
        tags = getattr(self.xml, "tag-rules").findall("tag")
        parsed = {}
        for tag in tags:
            name = tag.get("name")
            action = tag.get("action")
            attributes = []
            for attribute in tag.findall("attribute"):
                if attribute.get("name") in self._attributes:
                    attributes.append(self._attributes[attribute.get("name")])
                else:
                    attributes.append(self._get_attribute(attribute))
            parsed[name] = Tag(name, action, attributes)
        return parsed

    def parse_css_rules(self):
        """ Parse the <css-rules> section of the config file. """
        return {}

    def _guess_type(self, value):
        if value.isdigit():
            return int(value)
        if value == "true":
            return True
        if value == "false":
            return False
        return value

