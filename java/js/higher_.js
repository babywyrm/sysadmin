Briefly describe the development and use of JavaScript high-order functions

##
#
https://github.com/xitu/gold-miner/blob/master/article/2021/Algorithms-in-JavaScript-with-visual-examples.md
#
##


As a JavaScript developer, you will often use higher-order functions, so it is important that you have a correct understanding of these functions. Currently, I see that some developers are often reduce()confused about the use of . Therefore, my article will explain it in detail. You should try to understand it step by step, and I believe you will be able to master it.

Higher-order functions
In simple words, higher-order functions are those functions that take other functions as arguments or return other functions. The functions passed as arguments in higher-order functions are called callbacks.

Advantages of higher-order functions:

They help us write concise code.
Since the code is concise, debugging will be easier.
JavaScript now has some built-in higher-order functions that you may have used without realizing it, such as filter(), reduce(), , sort()and forEach().

filter()
filterThe method returns a new array of elements that pass a specific test provided by a callback function. Because filterrequires a callback function, it filter()is called a higher-order function.

filter()The callback function parameters passed into the higher-order function are as follows:

The value of the element (required)
The index of the element (optional)
Array object (optional)
let arr = [1,2,3,4,5]; 

const resultant Array = arr.filter((element ) => {
    return element > 3; 
})

console.log(resultantArray); // [4, 5]
In the above example, arrthe elements in the array are passed to filter()the callback method in turn to perform a specific test, that is element > 3, those elements that pass the test are pushed resultantArrayinto , which is why the output result is [4,5], because 4 and 5 are the elements that pass the test.

The parameter elementwill get arrthe element value of the array in turn, it will first become 1, then be tested 1 > 3, if true, 1 will be pushed into the result array, otherwise it will jump to the next element.

Example:

// 筛选年龄小于 18 岁的人

const ageArray = [10, 12, 35, 55, 40, 32, 15]; 

const filterAgeArray = ageArray.filter((age)=> {
    return age < 18; >
}); 

console.log(filterAgeArray); 
// [10, 12, 15]

-----------------

// 筛选正数

const numArray = [-2, 1, 50, 20, -47, -40]; 

const positiveArray = numArray.filter((num) => {
    return num > 0; 
}); 

console.log(positiveArray);
// [1, 50, 20]

-----------------

// 筛选包含 `sh` 的名字

const namesArray = ["samuel", "rahul", "harsh", "hitesh"]; 

const filterNameArray = namesArray.filter((name) =>{
    return name.includes("sh"); 
}); 

console.log(filterNameArray); 
// ["harsh", "hitesh"]
map()
As the name suggests, map()the method is used to map the values ​​of the existing array to new values, push the new values ​​into a new array, and then return the new array. Now it map()also requires a callback function, so it is called a higher-order function.

Now, map()the callback function passed into the method requires three parameters:

The value of the element (required)
The index of the element (optional)
Array object (optional)
const numArray = [1, 5, 3, 6, 4, 7]; 

const increasedArray = numArray.map((element) => {
    return element + 1; 
}); 

console.log(increasedArray);
[2, 6, 4, 7, 5, 8]
Just filter()like in , numArraythe elements of will be passed to map()the callback function in turn (as elementthe argument), where they will be mapped into a element + 1new value of , which will then be put into increasedArray.

First, 1will be passed as the element parameter and mapped to a new value, , element + 1so that 1 + 1(because the element here is 1), 2will be pushed increasedArrayinto . Next, 5、3、6、4、7the above process is repeated for .

Example:

// 对数组中的每个数字进行指数化处理

const numArray = [2, 3, 4, 5, 15]; 

const poweredArray = numArray.map((number) => {
    return number * number; 
}); 

console.log(poweredArray); 
// [4, 9 ,16, 25, 144, 225]

// 设置学生的分数

const studentsArray = [
    {
        name: "Rahul", 
        marks: 45, 
    }, 
    {
        name: "Samuel", 
        marks: 85, 
    }, 
    {
        name: "Chris", 
        marks: 25, 
    },
]; 

const ScoreArray = studentsArray.map((student) => {
    return student.marks; 
}); 

console.log(scoreArray); 
// [45, 85, 25]
reduce()
reduce()The method is used to restore an array to a single value, just like filter()and map(), reduce()and it also requires a callback function as a parameter, so it is called a higher-order function.

But reduce()it requires one more argument in addition to the callback function, which is initialValue（初始值）. Again, like filter()and map(), the callback function passed to reduce()requires a number of arguments, but reduce()the callback function passed to requires 4arguments instead of 3.

Initial value (required)
The value of the element (required)
The index of the element (optional)
Array object (optional)
// reduce() 示例

const numArray = [1, 2, 3, 4, 5]; 

const sum = numArray.reduce((total, num) => {
    return total + num; 
}); 

console.log(sum);
First understand what is total argument. total argumentis reduce()the previous value returned by the function. Now when reduce()is run for the first time, there will be no previous return value, so the first is total argumentequal to initialValue( reduce()the second parameter passed in ).

Now it is not used in the example initialValue. When we do not pass initialValue, reduce()the method will skip numArraythe first element of and become total argumentthe value of . What is going on?

In the example, nothing is passed initialValue, so numArraythe first element of , such as , 1will become total argumentthe value of , numArraythe second element of will numbe passed as the argument, the function will return total + num, such as 1 + 2 = 3, 3which will become totalthe new value of , and now numArraythe third element of will be numpassed as the argument to  reduce()the callback, which will again return total + num, i.e. 3 + 3 = 6, 6which will become totalthe new value of , and so on.

The above explanation is a bit confusing but if you try to follow it step by step you will get it  reduce().

initialValue parameter

initialValueis total argumentthe initial value of . When reduce()is run for the first time, there is no previous return value, so numArraythe first element of the existing array ( in the example) becomes total argumentthe value of , so can be given · total argument 一个初始值，而不是这样做（记住initialValue 将是total argument  的初始值，total argument 将成为the previous return value of reduce()`).

Note: When using initialValuethe argument, numArrayits first element is not skipped, so every element will be passed to reduce()the callback.

reduce()Syntax with initial value:

const resultantArray = existingArray.reduce((total,element,index.array)=> {
    // 返回某些东西
}, initialValue);
