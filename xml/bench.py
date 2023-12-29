
##
## https://gist.github.com/immerrr/6cbdcae303683203ddb44a0c1c18731e
##

import timeit

"""
Looking at New York Times homepage:

Common classes:
[
('story', 147),
('story-heading', 145),
('theme-summary', 64),
('column', 58),
('collection', 50),
('section-heading', 49),
('story-link', 39),
('icon', 38),
('thumb', 35),
('ad', 33)
]

Many
<article class="story" ...
or
<article class="story theme-summary ...
"""

SETUP = '''
import lxml.etree
import lxml.html

CLASS_EXPR = "contains(concat(' ', normalize-space(@class), ' '), ' {} ')"

def has_class_old(context, *classes):
    """
    This lxml extension allows to select by CSS class more easily
    >>> ns = etree.FunctionNamespace(None)
    >>> ns['has-class'] = has_class
    """
    expressions = ' and '.join([CLASS_EXPR.format(c) for c in classes])
    xpath = 'self::*[@class and {}]'.format(expressions)
    return bool(context.context_node.xpath(xpath))

def has_class_set(context, *classes):
    class_attr = context.context_node.get("class")
    if class_attr:
        return set(classes).issubset(class_attr.split())

def has_one_class(context, cls):
    return cls in context.context_node.get("class", "").split()

def has_class_plain(context, *classes):
    node_cls = context.context_node.get('class')
    if node_cls is None:
        return False
    node_cls = ' ' + node_cls + ' '
    for cls in classes:
        if ' ' + cls + ' ' not in node_cls:
            return False
    return True


ns = lxml.etree.FunctionNamespace(None)
ns['has-class-old'] = has_class_old
ns['has-class-set'] = has_class_set
ns['has-one-class'] = has_one_class
ns['has-class-plain'] = has_class_plain

body = open('nytimes.html', 'rb').read().decode('utf-8')

from parsel import Selector

sel = Selector(body)

'''

N = 1000


def _t(stmt, setup=SETUP, number=N, ref=None):
    v = timeit.timeit(stmt, setup, number=number)
    rel = 1.0 if ref is None else (v / ref)
    print '%-70s %6.3f %6.3f' % (stmt, v, rel)
    return v


ref = _t('sel.css(".story")')
#_t('sel.xpath("//*[has-class-old(\'story\')]")', ref=ref)
_t('sel.xpath("//*[has-class-set(\'story\')]")', ref=ref)
_t('sel.xpath("//*[has-one-class(\'story\')]")', ref=ref)
_t('sel.xpath("//*[has-class-plain(\'story\')]")', ref=ref)
print("\n")

ref = _t('sel.css("article.story")')
#_t('sel.xpath("//article[has-class-old(\'story\')]")', ref=ref)
_t('sel.xpath("//article[has-class-set(\'story\')]")', ref=ref)
_t('sel.xpath("//article[has-one-class(\'story\')]")', ref=ref)
_t('sel.xpath("//article[has-class-plain(\'story\')]")', ref=ref)
print("\n")

ref = _t('sel.css("article.theme-summary.story")')
#_t('sel.xpath("//article[has-class-old(\'theme-summary\', \'story\')]")', ref=ref)
_t('sel.xpath("//article[has-class-set(\'theme-summary\', \'story\')]")', ref=ref)
_t('sel.xpath("//article[has-class-plain(\'theme-summary\', \'story\')]")', ref=ref)
print("\n")

ref = _t('sel.css(".story a")')
_t('sel.css(".story").xpath(".//a")', ref=ref)
#_t('sel.xpath("//*[has-class-old(\'story\')]//a")', ref=ref)
_t('sel.xpath("//*[has-class-set(\'story\')]//a")', ref=ref)
_t('sel.xpath("//*[has-one-class(\'story\')]//a")', ref=ref)
_t('sel.xpath("//*[has-class-plain(\'story\')]//a")', ref=ref)
print("\n")
