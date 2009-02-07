""" This file holds the model and parsing logic for our policy engine.  Policy
    files are stored in xml documents.  Some sample ones are included in the
    data module in this package.
"""

DEFAULT_POLICY_URI = "data/antisamy.xml";
DEFAULT_ONINVALID = "removeAttribute";
DEFAULT_MAX_INPUT_SIZE = 100000;
DEFAULT_MAX_STYLESHEET_IMPORTS = 1;
OMIT_XML_DECLARATION = "omitXmlDeclaration";
OMIT_DOCTYPE_DECLARATION = "omitDoctypeDeclaration";
MAX_INPUT_SIZE = "maxInputSize";
USE_XHTML = "useXHTML";
FORMAT_OUTPUT = "formatOutput";
EMBED_STYLESHEETS = "embedStyleSheets";
CONNECTION_TIMEOUT = "connectionTimeout";
REGEXP_BEGIN = '^';
REGEXP_END = '$';


class Policy:
    """ Policy and rules engine for XSS scanning. """
	
	common_regexps = {}; 
	common_attributes = {};
	tag_rules = {};
	css_rules = {};
	directives = {};
	global_attributes = {};
	tag_names = [];

    def __init__(self):
        pass
    
    def parse(self):
        """ Parse all of the top-level elements in the specified config file. """
        top_level_parsers = [self.parse_common_regexps, self.parse_directives,
                self.parse_common_attributes, self.parse_global_tag_attributes,
                self.parse_tag_rules, self.parse_css_rules]
        for parser in top_level_parsers:
            parser()
    
    def parse_common_regexps(self):
        """ Parse the <common-regexps> section of the config file. """
        # List of <regexp name="" value="" /> need to map to dict of compiled regexps
        pass
    
    def parse_directives(self):
        """ Parse the <directives> section of the config file. """
        # List of <directive name="" value="" /> need to map to dict
        pass
    
    def parse_common_attributes(self):
        """ Parse the <common-attributes> section of the config file. """
        # WEE BIT TRICKIER.. refer to java implementation.. stuff going on with invalid, etc attributes
        pass
    
    def parse_global_tag_attributes(self):
        """ Parse the <global-tag-attributes> (id, style, etc.) section of the config file. """
        # requires that parse_common_attributes has already been called.  loop through the list of <attribute name="" /> nodes and pull the actual attribute from the common_attributes list and stick it here
        pass
    
    def parse_tag_rules(self):
        """ Parse the <tag-rules> (restrictions) section of the config file. """
        pass
    
    def parse_css_rules(self):
        """ Parse the <css-rules> section of the config file. """
		pass
