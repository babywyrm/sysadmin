Python: Fetch item in list where dict key is some value using lambda
Asked 8 years, 7 months ago
Modified 8 years, 7 months ago
Viewed 13k times

9


Is it possible to fetch using lambda? I know that we can do sorted function with lambda and its VERY useful.

Is there a short form way of fetching an object in a list in which the object at key 'id' is equal to lets say 20?

We can of course use loop and loop over the entire thing.

x = [
    {'Car': 'Honda', 'id': 12},
    {'Car': 'Mazda', 'id': 45},
    {'Car': 'Toyota', 'id': 20}
    ]

desired_val = None
for item in list:
    if item['id'] == 20:
        desired_val = item
        break
Is it possible to achieve the same functionality using lambda? I am not very knowledgeable with lambda.

pythonlambda
Share
Improve this question
Follow
edited Jun 29, 2014 at 16:11
asked Jun 29, 2014 at 15:52
user1757703's user avatar
user1757703
2,88555 gold badges4040 silver badges6060 bronze badges
I was just wondering if this is faster or using lambda is faster. Time it. – 
vaultah
 Jun 29, 2014 at 15:53
@frostnational Is it possible to search with lambda? That's what I need. I can time it, that's not the issue. – 
user1757703
 Jun 29, 2014 at 15:53
In Python 3, you could use next(filter(...)) – 
tobias_k
 Jun 29, 2014 at 15:56
1
You say "fetch an object", but you set desired_val to 20, not to item. Was that intended? – 
DSM
 Jun 29, 2014 at 16:01
@DSM ahh sorry. In my implementation its an object but I put val to 20 arbitrarily. I understand how this could hurt future users looking at this. I'll fix it. – 
user1757703
 Jun 29, 2014 at 16:05
Show 1 more comment
4 Answers
Sorted by:

Highest score (default)

8


Using lambda here isn't necessary. Lambda isn't something magical, it's just a shorthand for writing a simple function. It's less powerful than an ordinary way of writing a function, not more. (That's not to say sometimes it isn't very handy, just that it doesn't have superpowers.)

Anyway, you can use a generator expression with the default argument. Note that here I'm returning the object itself, not 20, because that makes more sense to me.

>>> somelist = [{"id": 10, "x": 1}, {"id": 20, "y": 2}, {"id": 30, "z": 3}]
>>> desired_val = next((item for item in somelist if item['id'] == 20), None)
>>> print(desired_val)
{'y': 2, 'id': 20}
>>> desired_val = next((item for item in somelist if item['id'] == 21), None)
>>> print(desired_val)
None
Share
Improve this answer
Follow
answered Jun 29, 2014 at 16:09
DSM's user avatar
DSM
335k6262 gold badges585585 silver badges487487 bronze badges
Add a comment

6


Using a lambda as you asked, with a generator expression, which is generally considered more readable than filter, and note this works equally well in Python 2 or 3.

lambda x: next(i for i in x if i['id'] == 20)
Usage:

>>> foo = lambda x: next(i for i in x if i['id'] == 20)
>>> foo(x)
{'Car': 'Toyota', 'id': 20}
And this usage of lambda is probably not very useful. We can define a function just as easily:

def foo(x):
    return next(i for i in x if i['id'] == 20)
But we can give it docstrings, and it knows its own name and has other interesting attributes that anonymous functions (that we then name) don't have.

Additionally, I really think what you're getting at is the filter part of the expression.

In

filter(lambda x: x[id]==20, x)
we have replaced that functionality with the conditional part of the generator expression. The functional part of generator expressions (list comprehensions when in square brackets) are similarly replacing map.

Share
Improve this answer
Follow
edited Jun 29, 2014 at 16:25
answered Jun 29, 2014 at 16:01
Russia Must Remove Putin's user avatar
Russia Must Remove Putin♦
363k8888 gold badges401401 silver badges330330 bronze badges
Add a comment

5


I would propose to you that your own method is the best way to find the first item in a list matching a criteria.

It is straightforward and will break out of the loop once the desired target is found.

It is also the fastest. Here compared to numerous way to return the FIRST dict in the list with 'id'==20:

```

from __future__ import print_function

def f1(LoD, idd=20):
    # loop until first one is found then break and return the dict found
    desired_dict = None
    for di in LoD:
        if di['id'] == idd:
            desired_dict = di
            break
    return desired_dict

def f2(LoD, idd=20):
    # The genexp goes through the entire list, then next() returns either the first or None
    return next((di for di in LoD if di['id'] == idd), None)   

def f3(LoD, idd=20):
    # NOTE: the 'filter' here is ifilter if Python2
    return next(filter(lambda di: di['id']==idd, LoD), None)

def f4(LoD, idd=20):
    desired_dict=None
    i=0
    while True:
        try:
            if LoD[i]['id']==idd:
                desired_dict=LoD[i]
                break
            else: 
                i+=1
        except IndexError:
            break

    return desired_dict         

def f5(LoD, idd=20):
    try:
        return [d for d in LoD if d['id']==idd][0]               
    except IndexError:
        return None            


if __name__ =='__main__':
    import timeit   
    import sys
    if sys.version_info.major==2:
        from itertools import ifilter as filter

    x = [
        {'Car': 'Honda', 'id': 12},
        {'Car': 'Mazda', 'id': 45},
        {'Car': 'Toyota', 'id': 20}
        ]  * 10   # the '* 10' makes a list of 30 dics...

    result=[]    
    for f in (f1, f2, f3, f4, f5):
        fn=f.__name__
        fs="f(x, idd=20)"
        ft=timeit.timeit(fs, setup="from __main__ import x, f", number=1000000)
        r=eval(fs)
        result.append((ft, fn, r, ))         

    result.sort(key=lambda t: t[0])           

    for i, t in enumerate(result):
        ft, fn, r = t
        if i==0:
            fr='{}: {:.4f} secs is fastest\n\tf(x)={}\n========'.format(fn, ft, r)   
        else:
            t1=result[0][0]
            dp=(ft-t1)/t1
            fr='{}: {:.4f} secs - {} is {:.2%} faster\n\tf(x)={}'.format(fn, ft, result[0][1], dp, r)

        print(fr)
If the value 'id'==20 is found, prints:

f1: 0.4324 secs is fastest
    f(x)={'Car': 'Toyota', 'id': 20}
========
f4: 0.6963 secs - f1 is 61.03% faster
    f(x)={'Car': 'Toyota', 'id': 20}
f3: 0.9077 secs - f1 is 109.92% faster
    f(x)={'Car': 'Toyota', 'id': 20}
f2: 0.9840 secs - f1 is 127.56% faster
    f(x)={'Car': 'Toyota', 'id': 20}
f5: 2.6065 secs - f1 is 502.77% faster
    f(x)={'Car': 'Toyota', 'id': 20}
And, if not found, prints:

f1: 1.6084 secs is fastest
    f(x)=None
========
f2: 2.0128 secs - f1 is 25.14% faster
    f(x)=None
f5: 2.5494 secs - f1 is 58.50% faster
    f(x)=None
f3: 4.4643 secs - f1 is 177.56% faster
    f(x)=None
f4: 5.7889 secs - f1 is 259.91% faster
    f(x)=None
Of course, as written, these functions only return the first dict in this list with 'id'==20. If you want ALL of them, you might use a list comprehension or filter with a lambda.

You can see that as you wrote the function originally, modified to return a list instead, it is still competitive:

```
def f1(LoD, idd):
    desired_lst = []
    for item in LoD:
        if item['id'] == idd:
            desired_lst.append(item)

    return desired_lst

def f2(LoD, idd):
    return [d for d in LoD if d['id']==idd]    

def f3(LoD, idd):
    return list(filter(lambda x: x['id']==idd, LoD) )   
Using the same code to time it, these functions print:

f2: 2.3849 secs is fastest
    f(x)=[{'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}]
========
f1: 3.0051 secs - f2 is 26.00% faster
    f(x)=[{'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}]
f3: 5.2386 secs - f2 is 119.66% faster
    f(x)=[{'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}, {'Car': 'Toyota', 'id': 20}]
In this case, the list comprehension is better.
```
Share
Improve this answer
Follow
edited Jun 29, 2014 at 21:20
answered Jun 29, 2014 at 16:35
dawg's user avatar
dawg
95.8k2323 gold badges126126 silver badges203203 bronze badges
Looks like the straightforward function loop and break construction beats the generator. Good job. – 
Russia Must Remove Putin
♦
 Jun 29, 2014 at 16:48
Thank You Mr. dawg (nice name, it's funny) sir. This is very helpful. A dog just answered a programming question :O – 
user1757703
 Jun 29, 2014 at 17:08 
Add a comment

5


In Py3k filter returns an iterator, so you can use next to get its first value:

val = next(filter(lambda x: x['id'] == 20, list))
For Python 2 use itertools.ifilter, because the built-in filter constructs the list with results:

from itertools import ifilter
val = next(ifilter(lambda x: x['id'] == 20, list))
Consider passing the default value to next that will be returned in case of empty iterator:

In [3]: next(filter(bool, [False]), 'default value here')
Out[3]: 'default value here'
Share
Improve this answer
Follow
edited Jun 29, 2014 at 16:07
answered Jun 29, 2014 at 15:57
vaultah's user avatar
vaultah
42.9k1212 gold badges113113 silver badges143143 bronze badges
For Python3 this is okay, but for Python2 it will first create the entire list just to then use the first element and throw the rest away. Maybe rather use itertools.ifilter? – 
tobias_k
 Jun 29, 2014 at 15:58 
@tobias_k I've added it before noticing your suggestion :) – 
vaultah
 Jun 29, 2014 at 16:02
