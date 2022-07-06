# Comprehensions in Python the Jedi way

by [Bjørn Friese](https://frieze.dk)

> Beautiful is better than ugly.
> Explicit is better than implicit.

-- <cite>[The Zen of Python](https://www.python.org/dev/peps/pep-0020/)</cite>

I frequently deal with collections of things in the programs I write. Collections of droids, jedis, planets, lightsabers, starfighters, etc. When programming in Python, these collections of things are usually represented as lists, sets and dictionaries. Oftentimes, what I want to do with collections is to transform them in various ways. Comprehensions is a powerful syntax for doing just that. I use them extensively, and it's one of the things that keep me coming back to Python. Let me show you a few examples of the incredible usefulness of comprehensions.

All of the tasks presented in the examples can be accomplished with the extensive standard library available in Python. These solutions would arguably be more terse and efficient in some cases. I don't have anything against the standard library. To me there is a certain elegance and beauty in the explicit nature of comprehensions. Everything you need to know is right there in the code in a concise and readable form – no need to dig through the docs.

> Note: I'm using Python 3.5. List, set, and dictionary comprehensions are available in Python 2.7 and above, but the functions and syntax used in the examples might not be available/valid for other versions of Python.

## Bleeps and bloops

![](https://imgur.com/oKCXrwA.gif)

We are trying to have a meaningful conversation with R2-D2, but he just bleeps and bloops in a seemingly random pattern. After scratching our head for a while, we start jotting down the sequence of bleeps `0` and bloops `1`:

```python
bbs = '01110011001000000110111001101111001000000010000001101001001000000111001101101110001000000110010100100000001000000110100000100000001000000110010100100000011100100010000000100000011100000110110100100000011011110010000001100011'
```

Hmm. That looks interesting. Maybe it's octets of bits denoting ASCII characters? Let's try splitting up the bit string into octets.

Using an imperative approach that might look something like this:

```python
octets = []
for i in range(0, len(bbs), 8):
  octets.append(bbs[i:i+8])
```

First initialize a new list. For every 8th index in the string we slice a string of length 8 and append it to the list of octets.

Can we do better than this? Of course we can! Take a look at this functional approach:

```python
octets = list(map(lambda i: bbs[i:i+8], range(0, len(bbs), 8)))
```

We [`map`](https://docs.python.org/3/library/functions.html#map) the indexes of the octets to a lambda function that return an octet starting at that index. The `map` function returns an iterable which we turn into a list with the [`list`](https://docs.python.org/3/library/functions.html#func-list) function. This is slightly more concise than the imperative approach, but arguably less readable.

We decide to ask master Yoda for advice. He suggests the following:

```python
octets = [bbs[i:i+8] for i in range(0, len(bbs), 8)]
```

Wait, is that the force? Nope, that right there is a comprehension. A list comprehension to be more exact.

The brackets `[]`  indicate that we are making a new list. Inside the brackets we first have an expression: `bbs[i:i+8]`. Next up is a `for` clause: `for i in range(0, len(bbs), 8)`. The `for` clause defines the iterator that we use as a basis for our new list, and the initial expression defines the resulting element in the new list.

> Bonus info: The stuff inside the brackets is called a [generator expression](https://www.python.org/dev/peps/pep-0289/) and can be used on it's own to create iterators.

Now that we know what a list comprehension is, we can use it again to turn the octets into characters:

```python
chrs = [chr(int(octet, 2)) for octet in octets]
```

And we get:

```python
['s', ' ', 'n', 'o', ' ', ' ', 'i', ' ', 's', 'n', ' ', 'e', ' ', ' ', 'h', ' ', ' ', 'e', ' ', 'r', ' ', ' ', 'p', 'm', ' ', 'o', ' ', 'c']
```

Hmm, that looks promising, but it's still kind of fragmented. What if we removed the spaces?

Normally we would [`filter`](https://docs.python.org/3/library/functions.html#filter) out all the `' '` characters:

```python
chrs = list(filter(lambda c: c != ' ', chrs))
```

That would work, but now that we know the true power of the comprehension, we can simply do this instead:

```python
chrs = [c for c in chrs if c != ' ']
```

We can use `if` clauses in our list comprehensions to perform a filtering operations. Neat!

Finally we join up the letters into a string to make the message more readable:

```python
message = ''.join(chrs)
```

Err, what is a "snoisneherpmoc"? Maybe R2-D2 spoke the message in reverse for some reason.

```python
message = ''.join(reversed(chrs))
```

Ah! The message is "comprehensions". R2-D2 knows what's up.

## Droid dating

For this example we are making a dating service for heroic droids. We want a list of all the ways to match up 2 droids from the following list:

```python
droids = [
  {'name': 'BB-8', 'fav_jedi': 'Rey'},
  {'name': 'R2-D2', 'fav_jedi': 'Luke Skywalker'},
  {'name': 'C-3PO', 'fav_jedi': 'Luke Skywalker'},
]
```

We could use [`itertools.combinations`](https://docs.python.org/3/library/itertools.html#itertools.combinations) to do this, but for now let's imagine it doesn't exist and that we have to write our own code for once.

Let's start out by creating a list of all the possible permutations of 2 droids the old school way:

```python
matches = []
for i in range(len(droids)):
  for j in range(i + 1, len(droids)):
    matches.append((droids[i], droids[j]))
```

We can make that a little nicer if we use the built in [`enumerate`](https://docs.python.org/3/library/functions.html#enumerate) function and some list slicing:

```python
matches = []
for i, a in enumerate(droids):
  for b in droids[i + 1:]:
    matches.append((a, b))
```

That can be turned into a cute one liner with a nested list comprehension (yes, you can nest them!):

```python
matches = [(a, b) for i, a in enumerate(droids) for b in droids[i + 1:]]
```

Finally, we might want to score these matches based on whether the droids share a favourite jedi. This just happens to be really easy to do with an inline conditional expression:

```python
scores = ['Great' if a['fav_jedi'] == b['fav_jedi'] else 'Miserable' for a, b in matches]
```

Let's zip the matches with the scores and print them in a nice and readable format:

```python
print(['{[name]} + {[name]} = {}'.format(*m, s) for m, s in zip(matches, scores)])
# ['BB-8 + R2-D2 = Miserable', 'BB-8 + C-3PO = Miserable', 'R2-D2 + C-3PO = Great']
```

And thus we can conclude that R2-D2 and C-3PO are a great match.

![](https://i.imgur.com/dmWRo5t.gif)

## Lift-off

Darth Vader and Luke Skywalker can't find their ships right before the big chase around the Death Star. Let's help them out.

```python
pilots = [
  {'name': 'Luke Skywalker', 'ship_id': 0},
  {'name': 'Darth Vader', 'ship_id': 1},
]
ships = [
  {'id': 0, 'model': 'T-65B X-wing'},
  {'id': 1, 'model': 'TIE Advanced x1'},
]
```

No problem, we just join the two lists using a nested list comprehension:

```python
pilot_ships = [(p, s) for p in pilots for s in ships if p['ship_id'] == s['id']]
```

For each pilot we iterate over all the ships. If the pilots `ship_id` is equal to the ships `id` they are a match, and we add the tuple to the list.

Let's see if we got this right:

```python
print(['{[name]} → {[model]}'.format(p, s) for p, s in pilot_ships])
# ['Luke Skywalker → T-65B X-wing', 'Darth Vader → TIE Advanced x1']
```

Ready for lift-off!

![](http://imgur.com/P8G3W8w.gif)

## Planets

We are presented with a dictionary of episodes each containing a (non-exhaustive) list of names of planets that appears in that episode:

```python
episodes = {
  'Episode I': {'planets': ['Naboo', 'Tatooine', 'Coruscant']},
  'Episode II': {'planets': ['Geonosis', 'Kamino', 'Geonosis']},
  'Episode III': {'planets': ['Felucia', 'Utapau', 'Coruscant', 'Mustafar']},
  'Episode IV': {'planets': ['Tatooine', 'Alderaan', 'Yavin 4']},
  'Episode V': {'planets': ['Hoth', 'Dagobah', 'Bespin']},
  'Episode VI': {'planets': ['Tatooine', 'Endor']},
  'Episode VII': {'planets': ['Jakku', 'Takodana', 'Ahch-To']},
}
```

How can we get a collection of unique planets that appeared throughout the episodes? First we use a nested list comprehension to flatten the planets into a single list:

```python
planets_flat = [planet for episode in episodes.values() for planet in episode['planets']]
```

> Note: The nested comprehension is consumed from left to right, and thus we need to have the episodes loop _before_ the planets loop.

From here we could wrap the resulting list in a set like this to remove the duplicates:

```python
planets_set = set(planets_flat)
```

But we won't bother with that. We got a secret weapon that will simplify and obliterate this task:

```python
planets_set = {planet for episode in episodes.values() for planet in episode['planets']}
```

Set comprehensions!

![](https://i.imgur.com/NLg1gzC.gif)

## Lightsabers

I recently stumbled upon the [`collections.Counter`](https://docs.python.org/3/library/collections.html#collections.Counter) class while reading some code a friend had written. He was using it to buld a dictionary of frequencies of certain values appearing in a list of dictionaries roughly like this:

```python
import collections

jedis = [
  {'name': 'Ahsoka Tano', 'lightsaber_color': 'green'},
  {'name': 'Anakin Skywalker', 'lightsaber_color': 'blue'},
  {'name': 'Anakin Solo', 'lightsaber_color': 'blue'},
  {'name': 'Ben Skywalker', 'lightsaber_color': 'blue'},
  {'name': 'Count Duku', 'lightsaber_color': 'red'},
  {'name': 'Darth Craidus', 'lightsaber_color': 'red'},
  {'name': 'Darth Maul', 'lightsaber_color': 'red'},
  {'name': 'Darth Vader', 'lightsaber_color': 'red'},
  {'name': 'Jacen Solo', 'lightsaber_color': 'green'},
  {'name': 'Ki-Adi-Mundi', 'lightsaber_color': 'blue'},
  {'name': 'Kit Fisto', 'lightsaber_color': 'green'},
  {'name': 'Luke Skywalker', 'lightsaber_color': 'green'},
  {'name': 'Obi-Wan Kenobi', 'lightsaber_color': 'blue'},
  {'name': 'Palpatine', 'lightsaber_color': 'red'},
  {'name': 'Plo-Koon', 'lightsaber_color': 'blue'},
  {'name': 'Qui-Gon Jinn', 'lightsaber_color': 'green'},
  {'name': 'Yoda', 'lightsaber_color': 'green'},
]

frequencies = collections.Counter(jedi['lightsaber_color'] for jedi in jedis)

print(frequencies)
# Counter({'blue': 6, 'green': 6, 'red': 5})
```

I thought that was a really cool solution. Note that we are using a generator expression here rather than a list comprehension, since we don't need the list (`Counter` takes an iterable which is exactly what you get from a generator expression).

But do we really need to import a class and read the documentation for said class to accomplish this? No! Dictionary comprehensions can do this:

```python
colors = [jedi['lightsaber_color'] for jedi in jedis]
frequencies = {color: colors.count(color) for color in set(colors)}

print(frequencies)
# {'green': 6, 'red': 5, 'blue': 6}
```

![](https://i.imgur.com/l1L9s0K.gif)

This approach uses an additional line to create a list of colors, but on the other hand it's easy to understand what's going on without reading the `Counter` documentation.

> Note: The solution with comprehensions run in quadratic time while `collections.Counter` runs in linear time. If you need to do this efficiently use `collections.Counter`.

## That's all

I hope you feel like you now got a comprehensive overview of comprehensions. I urge you to give them a test drive if you haven't already.

Thanks for reading this article. Let me know how you use comprehensions in the comments section.

![](https://imgur.com/BBE9UUl.gif)

## Thanks

- [Thomas Dybdahl Ahle](https://github.com/thomasahle) and [Andreas Bruun Okholm](https://dk.linkedin.com/in/andreas-okholm-9474b14b) for thorough reviews and inspiration.
- [Origami Yoda](http://origamiyoda.com/submission/star-wars-all-lightsaber-colors-and-meanings/) for their awesome list of light saber colors and jedis.
- [Wookieepedia](http://starwars.wikia.com/wiki/Main_Page) for all sorts of Star Wars trivia.

## License

<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a><br /><span xmlns:dct="http://purl.org/dc/terms/" property="dct:title">Comprehensions in Python the Jedi way</span> by <a xmlns:cc="http://creativecommons.org/ns#" href="https://frieze.dk" property="cc:attributionName" rel="cc:attributionURL">Bjørn Friese</a> is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">Creative Commons Attribution-ShareAlike 4.0 International License</a>.


'''
Use a nested list comprehension to find all of the numbers from 1-100 that are divisible by any single digit besides 1 (2-9)
'''

#old school
no_dups = set()
for n in range(1, 100):
  for x in range(2,10):
    if n % x == 0:
      no_dups.add(n)
print(no_dups)
print()

#nested list comprehension

result = [number for number in range(1,100) if True in [True for x in range(2,10) if number % x == 0]]
print(result)

##########################
##########################

# Python provides an alternative way to do map and filter operations, called a list comprehension. 
# Many programmers find them easier to understand and write. List comprehensions are concise ways to 
# create lists from other lists. The general syntax is:

# [<transformer_expression> for <loop_var> in <sequence> if <filtration_expression>]

things = [2, 5, 9]
yourlist = [value * 2 for value in things] # t[<trans.exp is "value * 2"> <item variable is "value"> <sequence is "things">]
print(yourlist)

# Output: [4, 10, 18]


# The if clause of a list comprehension can be used to do a filter operation. To perform a pure filter 
# operation, the expression can be simply the variable that is bound to each item. For example, the following 
# list comprehension will keep only the even numbers from the original list.

def keep_evens(nums):
    new_list = [num for num in nums if num % 2 == 0]
    return new_list

print(keep_evens([3, 4, 6, 7, 0, 1]))

# Output: [4, 6, 0]


# You can also combine map and filter operations by chaining them together, or with a single list comprehension.

things = [3, 4, 6, 7, 0, 1]
#chaining together filter and map:
# first, filter to keep only the even numbers
# double each of them
print(map(lambda x: x*2, filter(lambda y: y % 2 == 0, things)))

# equivalent version using list comprehension
print([x*2 for x in things if x % 2 == 0])

# Output: 
#[8, 12, 0]
#[8, 12, 0]



# 2. The for loop below produces a list of numbers greater than 10. Below the given code, use list 
# comprehension to accomplish the same thing. Assign it the the variable lst2. Only one line of code is 
# needed.

L = [12, 34, 21, 4, 6, 9, 42]
lst = []
for x in L:
    if x > 10:
        lst.append(x)
print(lst)
# Answer:
lst2 = [x for x in L if x > 10]
print(lst2)

# Output:
#[12, 34, 21, 42]
#[12, 34, 21, 42]


#3. Write code to assign to the variable compri all the values of the key name in any of the 
# sub-dictionaries in the dictionary tester. Do this using a list comprehension.

import json

tester = {'info': [{"name": "Lauren", 'class standing': 'Junior', 'major': "Information Science"},{'name': 'Ayo', 'class standing': "Bachelor's", 'major': 'Information Science'}, {'name': 'Kathryn', 'class standing': 'Senior', 'major': 'Sociology'}, {'name': 'Nick', 'class standing': 'Junior', 'major': 'Computer Science'}, {'name': 'Gladys', 'class standing': 'Sophomore', 'major': 'History'}, {'name': 'Adam', 'major': 'Violin Performance', 'class standing': 'Senior'}]}
inner_list = tester['info']
compri = [d['name'] for d in inner_list]
print(compri)

# Output: ​['Lauren', 'Ayo', 'Kathryn', 'Nick', 'Gladys', 'Adam']

##########################
##########################


