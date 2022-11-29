# importing pandas module
import pandas as pd
 
# reading csv file from url
data = pd.read_csv("https://media.geeksforgeeks.org/wp-content/uploads/nba.csv")
  
# dropping null value columns to avoid errors
data.dropna(inplace = True)
 
 
# substring to be searched
sub ='er'
 
# start var
start = 2
 
# creating and passing series to new column
data["Indexes"]= data["Name"].str.find(sub, start)
 
# display
data

###################


    How do I select by partial string from a pandas DataFrame?

This post is meant for readers who want to

    search for a substring in a string column (the simplest case) as in df1[df1['col'].str.contains(r'foo(?!$)')]
    search for multiple substrings (similar to isin), e.g., with df4[df4['col'].str.contains(r'foo|baz')]
    match a whole word from text (e.g., "blue" should match "the sky is blue" but not "bluejay"), e.g., with df3[df3['col'].str.contains(r'\bblue\b')]
    match multiple whole words
    Understand the reason behind "ValueError: cannot index with vector containing NA / NaN values" and correct it with str.contains('pattern',na=False)

...and would like to know more about what methods should be preferred over others.

(P.S.: I've seen a lot of questions on similar topics, I thought it would be good to leave this here.)

    Friendly disclaimer, this is post is long.

Basic Substring Search

# setup
df1 = pd.DataFrame({'col': ['foo', 'foobar', 'bar', 'baz']})
df1

      col
0     foo
1  foobar
2     bar
3     baz

str.contains can be used to perform either substring searches or regex based search. The search defaults to regex-based unless you explicitly disable it.

Here is an example of regex-based search,

# find rows in `df1` which contain "foo" followed by something
df1[df1['col'].str.contains(r'foo(?!$)')]

      col
1  foobar

Sometimes regex search is not required, so specify regex=False to disable it.

#select all rows containing "foo"
df1[df1['col'].str.contains('foo', regex=False)]
# same as df1[df1['col'].str.contains('foo')] but faster.
   
      col
0     foo
1  foobar

Performance wise, regex search is slower than substring search:

df2 = pd.concat([df1] * 1000, ignore_index=True)

%timeit df2[df2['col'].str.contains('foo')]
%timeit df2[df2['col'].str.contains('foo', regex=False)]

6.31 ms ± 126 µs per loop (mean ± std. dev. of 7 runs, 100 loops each)
2.8 ms ± 241 µs per loop (mean ± std. dev. of 7 runs, 100 loops each)

Avoid using regex-based search if you don't need it.

Addressing ValueErrors
Sometimes, performing a substring search and filtering on the result will result in

    ValueError: cannot index with vector containing NA / NaN values

This is usually because of mixed data or NaNs in your object column,

s = pd.Series(['foo', 'foobar', np.nan, 'bar', 'baz', 123])
s.str.contains('foo|bar')

0     True
1     True
2      NaN
3     True
4    False
5      NaN
dtype: object


s[s.str.contains('foo|bar')]
# ---------------------------------------------------------------------------
# ValueError                                Traceback (most recent call last)

Anything that is not a string cannot have string methods applied on it, so the result is NaN (naturally). In this case, specify na=False to ignore non-string data,

s.str.contains('foo|bar', na=False)

0     True
1     True
2    False
3     True
4    False
5    False
dtype: bool

How do I apply this to multiple columns at once?
The answer is in the question. Use DataFrame.apply:

# `axis=1` tells `apply` to apply the lambda function column-wise.
df.apply(lambda col: col.str.contains('foo|bar', na=False), axis=1)

       A      B
0   True   True
1   True  False
2  False   True
3   True  False
4  False  False
5  False  False

All of the solutions below can be "applied" to multiple columns using the column-wise apply method (which is OK in my book, as long as you don't have too many columns).

If you have a DataFrame with mixed columns and want to select only the object/string columns, take a look at select_dtypes.
Multiple Substring Search

This is most easily achieved through a regex search using the regex OR pipe.

# Slightly modified example.
df4 = pd.DataFrame({'col': ['foo abc', 'foobar xyz', 'bar32', 'baz 45']})
df4

          col
0     foo abc
1  foobar xyz
2       bar32
3      baz 45

df4[df4['col'].str.contains(r'foo|baz')]

          col
0     foo abc
1  foobar xyz
3      baz 45

You can also create a list of terms, then join them:

terms = ['foo', 'baz']
df4[df4['col'].str.contains('|'.join(terms))]

          col
0     foo abc
1  foobar xyz
3      baz 45

Sometimes, it is wise to escape your terms in case they have characters that can be interpreted as regex metacharacters. If your terms contain any of the following characters...

. ^ $ * + ? { } [ ] \ | ( )

Then, you'll need to use re.escape to escape them:

import re
df4[df4['col'].str.contains('|'.join(map(re.escape, terms)))]

          col
0     foo abc
1  foobar xyz
3      baz 45

re.escape has the effect of escaping the special characters so they're treated literally.

re.escape(r'.foo^')
# '\\.foo\\^'

Matching Entire Word(s)

By default, the substring search searches for the specified substring/pattern regardless of whether it is full word or not. To only match full words, we will need to make use of regular expressions here—in particular, our pattern will need to specify word boundaries (\b).

For example,

df3 = pd.DataFrame({'col': ['the sky is blue', 'bluejay by the window']})
df3

                     col
0        the sky is blue
1  bluejay by the window
 

Now consider,

df3[df3['col'].str.contains('blue')]

                     col
0        the sky is blue
1  bluejay by the window

v/s

df3[df3['col'].str.contains(r'\bblue\b')]

               col
0  the sky is blue

Multiple Whole Word Search

Similar to the above, except we add a word boundary (\b) to the joined pattern.

p = r'\b(?:{})\b'.format('|'.join(map(re.escape, terms)))
df4[df4['col'].str.contains(p)]

       col
0  foo abc
3   baz 45

Where p looks like this,

p
# '\\b(?:foo|baz)\\b'

A Great Alternative: Use List Comprehensions!

Because you can! And you should! They are usually a little bit faster than string methods, because string methods are hard to vectorise and usually have loopy implementations.

Instead of,

df1[df1['col'].str.contains('foo', regex=False)]

Use the in operator inside a list comp,

df1[['foo' in x for x in df1['col']]]

       col
0  foo abc
1   foobar

Instead of,

regex_pattern = r'foo(?!$)'
df1[df1['col'].str.contains(regex_pattern)]

Use re.compile (to cache your regex) + Pattern.search inside a list comp,

p = re.compile(regex_pattern, flags=re.IGNORECASE)
df1[[bool(p.search(x)) for x in df1['col']]]

      col
1  foobar

If "col" has NaNs, then instead of

df1[df1['col'].str.contains(regex_pattern, na=False)]

Use,

def try_search(p, x):
    try:
        return bool(p.search(x))
    except TypeError:
        return False

p = re.compile(regex_pattern)
df1[[try_search(p, x) for x in df1['col']]]

      col
1  foobar
 

More Options for Partial String Matching: np.char.find, np.vectorize, DataFrame.query.

In addition to str.contains and list comprehensions, you can also use the following alternatives.

np.char.find
Supports substring searches (read: no regex) only.

df4[np.char.find(df4['col'].values.astype(str), 'foo') > -1]

          col
0     foo abc
1  foobar xyz

np.vectorize
This is a wrapper around a loop, but with lesser overhead than most pandas str methods.

f = np.vectorize(lambda haystack, needle: needle in haystack)
f(df1['col'], 'foo')
# array([ True,  True, False, False])

df1[f(df1['col'], 'foo')]

       col
0  foo abc
1   foobar

Regex solutions possible:

regex_pattern = r'foo(?!$)'
p = re.compile(regex_pattern)
f = np.vectorize(lambda x: pd.notna(x) and bool(p.search(x)))
df1[f(df1['col'])]

      col
1  foobar
