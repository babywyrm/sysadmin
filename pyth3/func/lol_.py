class Foo:
    def getattr(self, arg):
        def x():
            return "good"
        return getattr(self, arg, None)

    def x(self):
        return "bad"

f = Foo()
print f.getattr("x")() # => bad


class Bar:
    def getattr(self, arg):
        def x():
            return "good"
        if arg in locals():
            return locals()[arg]
        else:
            raise

    def x(self):
        return "bad"

b = Bar()
print b.getattr("x")() # => good

#########
#########

# Applies functions in `fs` in order whose input starts with `iv` and
# each function's output is fed into the next function in the chain.
# Should any function return `None`, the chain is broken, execution
# stops and `None` is returned.
def chain(iv, *fs):
    v = iv
    for f in fs: 
        v = f(v)
        if v is None:
            break
    return v

# Allows for an XPath-like querying of a nested dict.
#
# The `fields` param is a `.`-delimited string of field names describing
# the traversal path of the query. The first field will be extracted from
# `d`, the second field from the dict found from the first extraction, and
# so on and so forth until all nested fields have been extracted. If any
# of the extractions finds a non-dict field, or the field does not exist,
# it will return the `default` parameter, which defaults to `None`.
def dict_xquery(fields, d, default=None):
    v = d 
    for field in fields.split('.'):
        if not isinstance(v, dict):
            v = default
            break
        v = v.get(field)
    return v

# Maps over a list `stack`, potentially nested, applying `f` to each
# element in all sublists, ignoring `None` elements, and returning
# the transformed list, which will be flat. (i.e. no nested lists)
#
# This can also be used to simply flatten a list, e.g.:
#
#   flattened_list = flatmap(lamdba x: x, a_nested_list)
#
def flatmap(f, *stack):
    rv = []
    stack = list(stack)
    while stack:
        x = stack.pop(0)
        if x is None:
            continue
        if hasattr(x, '__iter__') and not isinstance(x, dict):
            for y in reversed(x):
                stack.insert(0, y)
        else:
            rv.append(f(x))
    return rv
 
#########
#########

  
