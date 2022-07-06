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


