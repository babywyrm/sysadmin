
##
#
https://gist.github.com/jFransham/369a86eff00e5f280ed25121454acec1
#
##


# Achieving warp speed with Rust

### Contents:
- [Number one optimization tip: don't](#number-one-optimization-tip-dont)
- [Never optimize blindly](#never-optimize-blindly)
- [Don't bother optimizing one-time costs](#dont-bother-optimizing-one-time-costs)
- [Improve your algorithms](#improve-your-algorithms)
- [CPU architecture primer](#cpu-architecture-primer)
- [Keep as much as possible in cache](#keep-as-much-as-possible-in-cache)
- [Keep as much as possible in registers](#keep-as-much-as-possible-in-registers)
- [Avoid `Box<Trait>`](#avoid-boxtrait)
- [Use stack-based variable-length datatypes](#use-stack-based-variable-length-datatypes)
- [Loop unrolling is still cool](#loop-unrolling-is-still-cool)
- [`assert!` conditions beforehand](#assert-conditions-beforehand)
- [Use link-time optimization](#use-link-time-optimization)
- [Don't use `#[inline(always)]`](#dont-use-inlinealways)
- [Parallelize, but not how you think](#parallelize-but-not-how-you-think)
- [A case study](#a-case-study)
- [Wrapping up](#wrapping-up)

---

If you're looking to write fast code in Rust, good news! Rust makes it really
easy to write really fast code. The focus on zero-cost abstractions, the
lack of implicit boxing and the static memory management means that even naïve
code is often faster than the equivalent in other languages, and certainly
faster than naïve code in any equally-safe language. Maybe, though, like most
programmers you've spent your whole programming career safely insulated from
having to think about any of the details of the machine, and now you want to dig
a little deeper and find out the real reason that Python script you rewrote in
Rust runs 100x faster and uses a 10th of the memory. After all, they both do the
same thing and run on the same CPU, right?

So, here's an optimization guide, aimed at those who know how to program but
maybe don't know how it maps to real ones and zeroes on the bare metal of your
CPU. I'll try to weave practical tips about optimizing Rust code with
explanations of the reason why it's faster than the alternative, and we'll end
with a case study from the Rust standard library.

This post assumes decent familiarity with programming, a beginner's familiarity
with Rust and almost no familiarity with CPU architecture.

## Number one optimization tip: don't

Ok, I'll start with a few disclaimers before I get into the meat. Firstly,
unless you're running into performance problems in real-life usage, optimize
your code for readability before you optimize it for runtime performance.
Compilers and humans alike are better at understanding boring, straightforward
code, so if you write that first you'll be likely to have "good enough"
performance with the added benefit of being maintainable. If you write nice,
refactorable code it'll be easy to change if you later realize that it's being
wasteful.

That's not to say that performance doesn't matter. You shouldn't only optimize
_slow_ programs. A long-running program using high amounts of CPU but not
causing visible slowness is just as bad as a program that takes 30s instead of
3s to process some data, it's just that the former is wasting battery and the
latter is wasting time. Weigh up the time it would take to optimize the code
against the benefit you would get from the optimization.

The reason maintainability is so important is that lot of optimizations are
"try it and see" - if you're unable to make sweeping changes to your code
without breaking it you're going to have a really bad time. Now, speaking of
"try it and see"...

## Never optimize blindly

There are lots of performance-tracing tools out there. A famous tool/set of
tools for C and other systems languages is [`valgrind`][valgrind], which are
extremely powerful but can be scary to get started with, so if you just want to
have a quick overview of what your program is doing from a performance
standpoint check out [this article on analyzing Rust with `perf`][perf], a
fantastic and easy-to-use performance tool for Linux. Unless there's a glaring
flaw, like pervasive `clone`ing or a blatantly sub-optimal algorithm, `perf`
will likely give better results than simply optimizing stuff that "looks slow".

Another tool that's good to help you avoid gotchas of all kinds (not just
performance) is [`clippy`][clippy], but you already knew that because you're
using it on all your code to begin with, right?

`perf` also shows the cumulative cost of each function over the course of the
program's runtime, which leads me to my next point:

[perf]: http://blog.adamperry.me/rust/2016/07/24/profiling-rust-perf-flamegraph/
[clippy]: https://github.com/Manishearth/rust-clippy
[valgrind]: http://valgrind.org/

## Don't bother optimizing one-time costs

Your config-parsing code can be as slow as you like and it's unlikely to matter.
Don't just optimize the slowest function in your program, optimize the one that
takes up the most of your runtime. Those may be the same function, but if you
get a 2 millisecond improvement on a function that's called 1000 times, that's
better than a 1 second improvement on a function that's called once.

## Improve your algorithms

Now, as with every article on performance, this is where I add in the requisite
disclaimer of _use better algorithms first_. Don't invent new algorithms unless
you do that for a living, but in all likelihood if you're running into
performance problems it's more likely to be due to poor algorithms than to poor
implementations. Most programmers test their code on small datasets, but if you
have `O(n²)` complexity that won't appear until you've tried it on a larger
dataset. If you don't know what your algorithm is, which is likely since most
code is written without a specific algorithm in mind, just try to have as few
loops as possible and remember that every use of `collect` has to iterate over
the entire collection at least once, and so the more work you can do using less
loops the better. This is the same as optimization in any language though, so
this is all I'll say on algorithmic complexity for now. If you want to find out
more, there are some excellent resources out there.

## CPU architecture primer

So maybe the complexity of your algorithm can't be improved, and to make any
improvements you need to get into the down-to-the-metal stuff. This is where the
difference comes in between languages like Rust and C and languages like Python
and Ruby. It's entirely possible that you know this already, but it's worth
going over to make sure we're all on the same page. 

There are two parts to any computation, the stuff it does and the stuff it does
it on. The instructions, and the data.

Instructions are stored in the instruction cache - a chunk of really, really
fast memory that's directly readable by the CPU. Each instruction can put and/or
take data from the CPU's registers, which is a small number of small pieces of
memory, either 32 or 64 bits depending on your computer's word size. Only a
small amount of data can be in registers at any one time, however, and you can't
take a pointer to a register, so sometimes the CPU must access the computer's
RAM. Since RAM is slow, the CPU tries to read in bulk and then store the result
in increasingly small, increasingly fast caches. If it tries to access data that
isn't in the smallest cache, it has to read the slightly larger cache,
continuing up until it reaches RAM. The upshot is: you want to keep your data as
small as possible, and for data that is accessed together to be close to each
other so the CPU loads as much of it at once as possible. This should be enough
information to get you through the rest of this article, but if you want to dive
deeper into it you can check out the [structure and implementation section in
the Wikipedia page for the CPU][cpu structure].

[cpu structure]: https://en.wikipedia.org/wiki/Central_processing_unit#Structure_and_implementation

## Keep as much as possible in cache

The further away your data is from your CPU the slower your program will be. The
very worst place for data to be is on a different computer. A less awful - but
still very awful - place for data to be is on your hard drive. Better still is
in your RAM but as mentioned before, RAM is slow. _Almost_ the best possible
place for your data is in CPU cache. You may have heard some folklore that
allocating is bad, and this is the main reason why. Accessing two different
locations one after another on the stack is fine, since they're likely to be on
the same cache line. Accessing two different locations one after another on the
heap is significantly slower, since it's much less likely they they're directly
next to each other. We'll go into exactly why this is in a moment. 

If you have to allocate, because you need variable-size containers, shared
ownership or owned trait objects (see below for why you probably don't need
trait objects), try to put data that will be accessed in
sequence in order in RAM, so that when the CPU reads one element it necessarily
has to read the next few elements too, meaning it doesn't need to stall waiting
for RAM in order to operate on them.

As a rule of thumb for whether something has to allocate: if you can tell me the
amount of space the value will use up without running the program, it's stored
on the stack. If you don't know something's size until runtime, it's allocated
on the heap.

This means that `String`, `Vec`, `HashMap` and `Box<Trait>`/`Box<[T]>` all
allocate, but any user-defined struct does not (it may contain something that
_does_ allocate, but it doesn't require any extra allocation to construct if
you already have an instance of the allocating type). `Box<T>` where `T` has a
statically-known size also allocates, so be careful of recursive enums. If
you're creating a tree structure that then becomes immutable, like with an AST,
you might want to consider using a `TypedArena` to get tighter control over
memory use. `TypedArena` is still unstable though, and it increases complexity,
so it's not suitable for all use-cases.

This is why you may have heard some complaints about Haskell's use of a linked
list of characters to represent a string. I'm not going to beat [gankro's
wonderful rant on the subject][linked lists], but suffice to say that this is
more-or-less the worst possible data structure to choose when each individual
element is small and the number of elements is large, because it needs to store
a pointer for every element, instead of a single integer for the entire array.

Not only that, but without some truly crazy compiler optimizations this means
that each element may not be directly after the element before it in memory.
We'll get to how to calculate this in a moment, but essentially that means that
Haskell's `String` type can cause a cache miss up to twice _per element_,
whereas if you had a vector of `Char`s (assuming 32-bit chars) it could only
cause a maximum of 1 cache miss for every 16 elements. This is why the
performance-savvy in languages such as Haskell and Lisp know to use vector-like
constructs when possible.

Back in the world of Rust, this means that you should avoid indirection-heavy
representations `Vec<Vec<_>>` to represent a matrix, since this means that each
sub-vec will likely be in a different location. Use a data structure that uses a
flat `Vec` as a backing array and builds on top of it, unless you really do need
to have the inner `Vec`s be both jagged (each sub-vec is of different size) and
growable (you can change the size of each sub-vec independently at runtime). You
probably don't need either, let alone both. If you need them to be a uniform
size, store a `Vec` and a dimension tuple, if you need them to be jagged but
don't need them to be growable, store a list of indices and return slices of the
flat `Vec` using those. For an example of why this is good, let's dive into some
basic math. Let's assume a matrix backed by flat vector and a number of columns
(the number of rows can be inferred from columns + data length): 

```rust
// This isn't how Vec is defined in the standard library but it's a simplified
// version with the same memory layout.
struct Vec<T> {
    pointer: *mut T,
    capacity: usize,
    len: usize,
}

struct Matrix<T> {
    data: Vec<T>,
    num_columns: usize,
}
```

So a matrix with N rows and M columns needs `N * M * size_of::<T>()` space for
the elements, plus `size_of::<*mut T>() + 3 * size_of::<usize>()` for the
"metadata" (the vector's pointer and the `capacity`, `length` and `num_columns`
fields). If we're on a 64-bit CPU with 64 byte cache lines like the i7, we end
up with both `*mut T` and `usize` being 4 bytes each. If we had a 4x4 matrix of
`f32` (also 4 bytes in size) this would mean: 

```
Metadata size = 4 + 3 * 4 = 16
Maximum 2 cache misses

Data size = 4 * 4 * 4 = 64
Maximum 2 cache misses
```

Since the metadata and the data could be in separate parts of memory, we have to
calculate maximum cache misses separately. Both the metadata and the data could
cross a cache line and require two cache misses to load. This means that the
whole matrix would miss the cache 4 times in the worst case. If we had a
`Vec<Vec<f32>>` representation that would mean the size of: 

```
Matrix metadata size = 4 + 2 * 4 = 12
Maximum 2 cache misses

Inner vector metadata size = 4 * (4 + 2 * 4) = 48
Maximum 2 cache misses

Data size = 4 * 4 = 16
Maximum 2 cache misses per row (8 cache misses total)
```

This means that the `Vec<Vec<f32>>` representation could miss the cache up to
12 times to read the whole array, much worse than the flat representation.

Even better, if you statically know the matrix's size you can use
statically-sized arrays like `[[T; N]; N]`. These are even cheaper than flat
vectors, although you obviously can't use them for data with a variable size at
runtime. The 4x4 array in the previous example would be `[[f32; 4]; 4]` and take
up 64 bytes, meaning that it would only take 2 cache misses to load in the worst
case. 

[linked lists]: http://cglab.ca/~abeinges/blah/too-many-lists/book/#an-obligatory-public-service-announcement
[rust-forest]: https://github.com/SimonSapin/rust-forest

## Keep as much as possible in registers

Now, the absolute best place for your data - registers. The more work you can do
without non-local writes the more that rustc and LLVM can assume about your
data's access patterns. This is good because it means that data can be mapped to
the CPU's physical registers, which are the fastest memory on your entire
computer, but even better, if you make your data suitable for registers then
anything that happens to that data can be aggressively optimized. Writes and
reads through pointers have certain ordering restrictions on them that prevent
optimization, but there are no such restrictions on register-allocated data. 

It's worth noting that since Rust restricts pointers more than C does, the
ordering restrictions on pointers could be relaxed. This hasn't been implemented
in LLVM yet since most of the optimization work is based on leveraging the rules
of C and C-family languages. Even if they did implement relaxations on the
reordering rules, however, storing data in registers will still be easier to
optimize.

So how do you get rustc to allocate things to registers? Essentially, the less
pointers you have to write at runtime the better. Writing to local variables
is better than writing through a mutable pointer. As much as possible, you
should try to constrain mutable writes to the data that you have ownership over.
So a mutable loop counter is fine, but passing a mutable reference to a loop
counter through multiple layers of functions is not (unless they end up getting
inlined, of course). This is really just an extension of one of my first points:
clean, boring code is easier to optimize than spaghetti.

## Avoid `Box<Trait>`
  
The canonical way to create trait objects is `Box<Trait>`, but the majority of
code can get away with `&mut Trait`, which also has dynamic dispatch but saves
an allocation. If you absolutely need ownership then use a `Box`, but most
use-cases can use an `&Trait` or `&mut Trait`. Even better is to avoid using a
trait object all together. `impl Trait` is the obvious way to avoid them, but
that doesn't allow you to store a heterogenous collection of elements that
implement a single trait since it's basically type inference in a fancy hat. A
good trick for when you want to allow a variable but finite number of
implementors of a type because you want to choose between them or iterate over
them, use either a tuple or a recursive generic struct like this:

```rust
struct Cons<Head, Tail>(Head, Tail);
```

Since data structures in Rust don't add any indirection or space overhead, you
can implement a trait for this structure recursively and have a function that
can take any number of parameters that runs as fast as an equivalent function
that takes a fixed number of parameters. Here's an example of how this could
look for a function that takes a list of functions and calls them:

Allocating version: 

```rust
fn call_all_fns(fns: Vec<Box<FnBox() -> ()>>) {
    for f in fns {
        f();
    }
}
```

Allocation-free version:

```rust
struct Cons<First, Second>(First, Second);

trait HCons: Sized {
    fn cons<T>(self, other: T) -> Cons<Self, T> {
        Cons(self, other)
    }
}

impl<T: Sized> HCons for T {}

// This is a hack to get around the fact that manually implementing the `Fn`
// traits is currently unstable.
trait Callable {
    fn call(self);
}

impl<F: Fn() -> ()> Callable for F {
    fn call(self) { self() }
}

impl<First: Callable, Second: Callable> Callable for Cons<First, Second> {
    fn call(self) {
        self.0.call();
        self.1.call();
    }
}

fn call_all_fns_no_alloc<T: Callable>(fns: T) {
    fns.call();
}
```

Here's what they both look like in use:

```rust
fn main() {
    let first_fn = || { println!("Hello!"); };
    let second_fn = || { println!("World!"); };
    
    call_all_fns(vec![Box::new(first_fn), Box::new(second_fn)]);
    
    let first_fn = || { println!("Hello!"); };
    let second_fn = || { println!("World!"); };
    
    call_all_fns_no_alloc(first_fn.cons(second_fn));
}
```

The functions passed to `call_all_fns_no_alloc` are eligible for inlining, they
require no space overhead, and their instructions and data are directly next to
each other in memory and are therefore much faster to access than if each of
them were boxed. For example, in `combine` there's a `choice` function that
takes an array that could contain trait objects, but it also supplies a `.or()`
combinator (and a `choice!` macro that expands to recursive `.or` calls) that
returns an `Or<A, B>` that in turn implements `Parser`. This means that dispatch
is static and the objects are all stored in order in memory (because it's just a
set of recursive structs). You will still need dynamic dispatch for some cases,
but using this method means that the number of cases where this is necessary is
very small.

## Use stack-based variable-length datatypes

Fixed-length datatypes are trivially storable on the stack, but for
dynamically-sized data it's not so simple. However, [`smallvec`][small1],
[`smallstring`][small2] and [`tendril`][small3] are all variable-length
datatypes that allow you to store small numbers of elements on the
stack (shameless plug: `smallstring` was written by me). Due to the law of small
numbers, you are very likely to have more of these small strings than larger
ones. This is good because it reduces allocation, but it's _great_ if you're
storing these in a `Vec` or `HashMap`, since you will have less indirection and
therefore better cache use. A good rule of thumb is to never have more than one
layer of pointers to dereference before you reach your value (NASA enforces this
rule in their C code, albeit for reliability and not performance).

Libraries like `smallvec` are great for cache locality, since an array of
`SmallVec<[T; 4]>` will have exactly the same cache-locality as an array of just
`T` - as long as the length of each `SmallVec` is below 8 it just gets stored in
order. Going back to the cache-miss calculations from earlier:

```rust
// This is a gross oversimplification of how this type is implemented in the
// crate, but it's enough to explain how it works.
enum SmallVec<T> {
    Small([T; 4]),
    Big(Vec<T>),
}

type Matrix<T> = SmallVec<SmallVec<T>>;
```

As long as there are less than or equal to 4 elements in the `SmallVec`, the
size of each instance is the size of the data plus the size of the tag, which
is:

```rust
let size_of_data = size_of::<T>() * 4;
let size_of_tag  = max(size_of::<u8>(), align_of::<T>());
size_of_data + size_of_tag
```

The obvious question is why the size of the tag isn't just `size_of::<u8>()`.
This is because if `T` was more than 1 byte in size, this would mean that all of
the elements would all be unaligned by 1 byte, which is bad. CPUs work much
slower on unaligned data, but unless you write a compiler you will never have to
think about that. The size of the data and its alignment don't have to be the
same. For structs, for example, the alignment is typically the largest alignment
of any of its members. For primitive types like pointers, integers and floats
the alignment is the same as its size. The alignment and size of an `f32` are
both 4. The alignment of a `SmallVec<f32>` is the largest alignment of its
members, which is same as the alignment of `[f32; 4]`, which is the same as the
alignment of `f32`: 4.

Consider we had a 4x4 matrix of `f32`, this would mean that the size of the
matrix would be:

```
Inner SmallVec size = 4 * 4 + 4
Matrix size = 4 * (4 * 4 + 4) + 4 = 84
Maximum 3 cache misses
```

We don't need to calculate the inner and outer cache misses seperately because
they are guaranteed to be next to each other in memory.

From a cache standpoint this is as good as the flat vector representation, but
there's nothing stopping you from accidentally making the inner vectors
different lengths and breaking the invariant that an array's rows should be the
same length.

I want to make something clear: you will never do these calculations in the
process of optimizing your program. This is merely some mathematical
justification for the voodoo folklore that "allocation is bad", since that is
often countered by "`malloc` is fast". Both statements are true - the actual
process of allocating and deallocating memory is fast, but data structures that
allocate are worse for use-cases that require maximum speed.

[small1]: https://github.com/servo/rust-smallvec
[small2]: https://github.com/jFransham/smallstring
[small3]: https://github.com/servo/tendril

## Loop unrolling is still cool

[Duff's device][duff] is fun, but array-length-generic unrolled loops are
unlikely to be faster than the equivalent optimized naïve code nowadays, since
any optimizing compiler worth its bits will do this kind of optimization without
having to mangle your code and ruining future-you's day.

Having said that, if you know that an array is likely to be a multiple of N
size, try making it a `&[[T; N]]` and operating on a `[T; N]` in each iteration.
This reduces the number of iterations (and therefore, the number of times you
need to recalculate the loop variables) and allows the compiler to operate more
aggressively on the loop body.

You can also use more classical loop unrolling if it allows you to reduce the
"strength" of your operations. This means that if you have to calculate some
value for each iteration of the loop and calculating this value takes longer
than the body itself, manually unroll the body so you can calculate it less.
Example: you can implement an integer logarithm function like so:

```rust
fn log_base(mut n: usize, base: usize) -> usize {
    let mut out = 1;

    loop {
        if n < base { return out; }

        out += 1;
        n /= base;
    }
}
```

However, `n /= base; out += 1;` is slower to calculate than `n < base`. To take
advantage of this fact, you can unroll the loop like so:

```rust
fn log_base_unrolled(mut n: usize, base: usize) -> usize {
    const UNROLL_COUNT: usize = 4;

    // We use a fixed-size array to ensure that we don't get the array count and
    // the `out` skip value out of sync.
    let premultiplied_base: [_; UNROLL_COUNT] = [
        base,
        base * base,
        base * base * base,
        base * base * base * base,
    ];

    let mut out = 1;
    
    loop {
        if n < premultiplied_base[0] { return out; }
        if n < premultiplied_base[1] { return out + 1; }
        if n < premultiplied_base[2] { return out + 2; }
        if n < premultiplied_base[3] { return out + 3; }
        
        n /= precalculated_base[UNROLL_COUNT - 1];
        out += UNROLL_COUNT;
    }
}
```

Here are the benchmarks I used:

```rust
#[bench]
fn bench_log_base(b: &mut Bencher) {
    b.iter(|| {
        let input = black_box(5000000120510250);

        assert_eq!(log_base(input, 10), 16);
    });
}

#[bench]
fn bench_log_base_unrolled(b: &mut Bencher) {
    b.iter(|| {
        let input = black_box(5000000120510250);

        assert_eq!(log_base(input, 10), 16);
    });
}
```

`test::black_box` is a magic function that prevents rustc and LLVM calculating
those function calls at compile-time and converting them into a constant, which
usually they would (actually, it's not magic, it's just some inline assembly
that doesn't do anything, since neither rustc nor LLVM will try to optimize
anything that's been accessed by inline assembly).

This gives the following results:

```
test bench_log_base          ... bench:  18 ns/iter (+/- 0)
test bench_log_base_unrolled ... bench:   5 ns/iter (+/- 0)
```

Wait a minute, though, what happens when we give a non-constant value for
`base`?

```rust
#[bench]
fn bench_log_base_nonconstbase(b: &mut Bencher) {
    b.iter(|| {
        let input = black_box(5000000120510250);
        let base = black_box(10);

        assert_eq!(log_base(input, base), 16);
    });
}

#[bench]
fn bench_log_base_unrolled_nonconstbase(b: &mut Bencher) {
    b.iter(|| {
        let input = black_box(5000000120510250);
        let base = black_box(10);

        assert_eq!(log_base_unrolled(input, base), 16);
    });
}
```

```
test bench_log_base_unrolled_nonconstbase ... bench:  37 ns/iter (+/- 1)
test bench_log_base_nonconstbase          ... bench: 199 ns/iter (+/- 5)
```

They're both much slower! Can we do better? Turns out yes, we can:

```rust
fn log_base_increasing(n: usize, base: usize) -> usize {
    const UNROLL_COUNT: usize = 4;

    let premultiplied_base: [_; UNROLL_COUNT] = [
        base,
        base * base,
        base * base * base,
        base * base * base * base,
    ];

    if n < premultiplied_base[0] { return 1; }
    if n < premultiplied_base[1] { return 2; }
    if n < premultiplied_base[2] { return 3; }
    if n < premultiplied_base[3] { return 4; }

    let mut out = UNROLL_COUNT + 1;
    let mut mul = premultiplied_base[UNROLL_COUNT - 1];

    loop {
        if n < premultiplied_base[0] * mul { return out; }
        if n < premultiplied_base[1] * mul { return out + 1; }
        if n < premultiplied_base[2] * mul { return out + 2; }
        if n < premultiplied_base[3] * mul { return out + 3; }

        mul *= premultiplied_base[UNROLL_COUNT - 1];
        out += UNROLL_COUNT;
    }
}

#[bench]
fn bench_log_base_increasing(b: &mut Bencher) {
    b.iter(|| {
        let input = black_box(5000000120510250);

        assert_eq!(log_base_increasing(input, 10), 16);
    });
}

#[bench]
fn bench_log_base_increasing_nonconstbase(b: &mut Bencher) {
    b.iter(|| {
        let input = black_box(5000000120510250);
        let base = black_box(10);

        assert_eq!(log_base_increasing(input, base), 16);
    });
}
```

Let's check out the results now:

```
test bench_log_base                         ... bench:  18 ns/iter (+/- 0)
test bench_log_base_nonconstbase            ... bench: 199 ns/iter (+/- 5)

test bench_log_base_unrolled                ... bench:   5 ns/iter (+/- 0)
test bench_log_base_unrolled_nonconstbase   ... bench:  37 ns/iter (+/- 1)

test bench_log_base_increasing              ... bench:   6 ns/iter (+/- 0)
test bench_log_base_increasing_nonconstbase ... bench:   8 ns/iter (+/- 1)
```

Turns out the compiler was doing something sneaky: it can optimize integer
division by a constant [into a multiplication combined with a shift][division].
When it could no longer fold the constant into the function it slowed down
considerably. It's ok to rely on const-folding if it allows you to gain
considerable speedups and you know that the function will usually be called with
constant arguments, but be careful. The things to look out for are if statements
and integer division, both of which can be much slower with non-constant values
compared to constants.

The fastest method by far converts to an `f64`, calls `.log(base)` on that, and
then converts back. It doesn't work for large numbers, however, because of loss
of precision. This is probably a good time to note that although adding and
multiplying integers is faster than doing the same for floats, for code that
does division by a non-constant value or something more complex like
trigonometry, you should definitely use floats. The compiler can't do the
conversion for you - it won't apply optimizations that make your code less
precise - but you can check for areas where this would be an improvement and
make the change manually.

[duff]: https://en.wikipedia.org/wiki/Duff's_device
[division]: http://embeddedgurus.com/stack-overflow/2009/06/division-of-integers-by-constants/

## `assert!` conditions beforehand

If you want to reduce the number of implicit asserts that get compiled into the
code, then instead of this:

```rust
fn do_something_with_array(array: &[u8]) -> u8 {
    array[0] + array[1] + array[2] + array[3] + array[4] + array[5]
}
```

Do this:

```rust
fn do_something_with_array(array: &[u8]) -> u8 {
    assert!(array.len >= 5);
    array[0] + array[1] + array[2] + array[3] + array[4] + array[5]
}
```

This allows LLVM to realize that the later asserts are unreachable and elides
them. This is useful for any code that may assert multiple different qualities
about the same data, but is especially useful for indexing since we know that
if `array[n]` succeeds then `array[n - 1]` will succeed too. This is similar to
the point about fixed-length arrays in the previous section.

Essentially, try to consolidate checks into a single `assert!`. This means that
the later checks become statically unreachable. If LLVM/Rust still don't
optimize it away you can switch to using the unsafe indexing methods while
ensuring that they're still safe. This tip is shamelessly stolen from [a comment
on /r/rust][assert comment].

[assert comment]: https://www.reddit.com/r/rust/comments/6anp0d/suggestion_for_a_new_rustc_optimization/dhfzp93/

## Use link-time optimization

Normally, Rust can only inline functions that are either defined in-crate or,
in the case of functions in other libraries, have `#[inline]` specified. LTO
allows the compiler to inline cross-crate, at the cost of a compile-time speed
penalty. I am of the opinion that compile times only matter for debug builds, so
that's a tradeoff I'm willing to make. As with everything else here, profile and
check that the tradeoff is worthwhile.

## Don't use `#[inline(always)]`

`#[inline(always)]` feels good as a performance hint, but the truth is that
optimizing compilers are really good at working out when a function would
benefit from being inlined, and Rust isn't constrained to the slower
standardized C calling convention and can use `fastcc`, making function calls
extremely cheap. You're more likely to cause the size of your executable to
bloat. This takes up more space on your hard drive, of course, but that's not
too much of a problem. If you have even a single bundled asset like images or
audio they will likely dwarf the size of your executable.

The real issue here is that it can make your program no longer fit in the CPU's
instruction cache. The CPU will only have to go to RAM for its instructions when
functions are called with instructions outside of the current cache line. The
larger your binary is, the more likely this is, and the more functions are
inlined, the larger your binary is. It's not the end of the world to have a
large binary, but unless you're really certain that something will be improved
by manually marking it as inline, and you have benchmarks to back that up,
it's just as likely that you'll slow a program down with careless inlining than
to speed it up. 

So now I've scared you off inlining, let's talk about when you should explicitly
add inlining annotations. Small functions that are called often are a good
target for inlining. `Iterator::next`, for example, or `Deref::deref`. The
overhead from calling these functions may be larger than the time it takes to
run the function itself. These are likely to be automatically inlined when
called internally, but marking these as `#[inline]` will allow users of your
library to inline them too, even if they don't use LTO. Only functions marked
`#[inline]` will be considered for cross-crate inlining, but that means the
definition has to be stored in the compiled library, causing bloat and
increasing compile times. `#[inline(always)]` is even more niche, but it's
sometimes nice to ensure that a tiny function will be inlined, or as a kind of
documentation that the function call is free for if someone comes along and
tries to manually inline it to improve performance. It really is very rare that
you would want to do this, though, and it's best to just trust the compiler.

The other class of functions that are good targets for annotating inlining are
ones that you know to often be called with constant parameters. We go into this
later on, but `{integer}::from_str_radix` is an exellent example of this. Most
uses of this function will have a constant as the second parameter, and so by
judicious use of `#[inline]` we can prevent branching and expensive operations
like division for the consumers of our library. It's not worth losing sleep
over though, since they could just use link-time optimization if they need to
squeeze out every last drop of performance.

Also, the compiler does really get it wrong sometimes, and can miss out on
inlining opportunities that would improve code speed. However, only add
`#[inline(always)]` annotation if you can prove with benchmarks that it improves
the speed, and adding these annotations is a bit of a dark art. You effort is
probably better spent elsewhere.

If you want to reduce the size of your code, you can try using
`panic = "abort"`. This removes the "landing pads" that allow Rust to show a
nice stack trace after a panic, and causes any panic to end the program
instantly. I have legitimately seen non-trivial speedups on benchmarks for the
`ion` shell after adding this option to the release build, and I can only
attribute it to making more code fit in the instruction cache. I have not tried
it with many other programs, but it would probably only affect medium to large
projects. Try it out on your codebase, it's as easy as adding one line to the
`Cargo.toml` and it may improve your code's speed. 

## Parallelize, but not how you think

There's an absolutely amazing library for Haskell called [Haxl][haxl], that
automatically tracks the data dependencies of your network requests and batches
them and runs them asynchronously as long as they don't overlap. It's something
that shows the power of computational abstractions like monads and it's not
something that has a, ahem, _parallel_ in any other language, as far as I know.
At least, not for IO. We've had this exact ability in the CPU for a long, long
time. The CPU tracks the data dependencies of computations and will parallelize
them wherever possible.

The reason data dependencies matter is that the CPU doesn't just execute one
instruction at a time. As long as two instructions don't share a register they
can safely be run simultaneously, so the CPU does so. This is essentially free
parallelism without the need for locks, work queues or anything that affects
your architecture at all, so you would be crazy not to take advantage of it.

Parallelizable computation also lends itself well to autovectorization, which is
the process where the compiler realizes that you're doing the same thing to
multiple different values and converts it to a special instruction that, well,
does the same thing to multiple different values.

For example, the compiler could translate the following numerical code:

```rust
(a1 + a2) + (b1 + b2) + (c1 + c2) + (d1 + d2)
```

into just one instruction that executes all four subexpressions as fast as a
single addition.

```
%intermediate-value = add-vectors [%a1 %b1 %c1 %d1] [%a2 %b2 %c2 %d2]
sum-parts %intermediate-value
```

[haxl]: https://github.com/facebook/haxl

## A case study

Let's write a version of `usize::from_str_radix` that's about 30% faster than
the one in the standard library. 

```rust
// We're redefining these here since they're private in the stdlib
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParseIntError {
    kind: IntErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IntErrorKind {
    Empty,
    InvalidDigit,
    Overflow,
    Underflow,
}

#[inline]
fn from_str_radix(input: &str, radix: usize) -> Result<usize, ParseIntError> {
    fn to_digit_ascii(ascii: u8, radix: usize) -> Result<usize, ParseIntError> {
        let decimal_digit = ascii.wrapping_sub(b'0');

        if radix > 10 && decimal_digit > 9 {
            let out = (ascii | 32).wrapping_sub(b'a') as usize;

            if out > radix - 10 {
                Err(ParseIntError { kind: IntErrorKind::InvalidDigit })
            } else {
                Ok(out + 10)
            }
        } else {
            let decimal_digit = decimal_digit as usize;
            if decimal_digit > radix {
                Err(ParseIntError { kind: IntErrorKind::InvalidDigit })
            } else {
                Ok(decimal_digit)
            }
        }
    }

    if radix > 36 {
        panic!("from_str_radix: radix is too high (maximum 36)");
    }

    let bytes = input.as_bytes();

    if bytes.len() == 0 {
        return Err(
            ParseIntError { kind: IntErrorKind::Empty }
        );
    }

    let bytes = match bytes[0] {
        b'+' => { &bytes[1..] },
        b'-' => { return Err(ParseIntError { kind: IntErrorKind::Underflow }) },
        _ => bytes,
    };

    let mut mul = radix;
    let mut index = bytes.len() - 1;

    let mut output = to_digit_ascii(bytes[index], radix)?;

    for &byte in bytes[..index].iter().rev() {
        let digit = to_digit_ascii(byte, radix)?;

        let next_output = output.wrapping_add(digit * mul);

        if output > next_output {
            return Err(
                ParseIntError { kind: IntErrorKind::Overflow }
            );
        }

        mul *= radix;
        output = next_output;
    }

    Ok(output)
}
```

I explicitly use `wrapping_*` functions not for optimization purposes (because
overflow checks are removed at runtime), but because overflow is required for
correct behaviour. You'll notice some optimizations here: 

* We start at the end and work backwards, keeping a "mul" counter. Originally I
  wrote a version of this that works forwards and multiplies `output` by radix
  each loop but the backwards method is 10% faster. This seems to be due to
  better instruction-level parallelism. The multiplications can be parallelized
  and only the addition relies on the previous iteration's value for `output`,
  and addition is much faster.

  Any folding operations can be improved in this way by exploiting the
  algebraic laws (in this case, the distributive law) to improve the number of
  operations that can be done in parallel.
* We rely on overflow to test `A < x < B` comparisons. This is only useful here
  because we already need the `x - A` value, so we're saving an extra comparison
  and a bitwise and. In most code `A < x && x < B` is as cheap or cheaper than
  `x - A < B` with overflow.
* We use `| 32` to unify the codepaths for upper- and lowercase letters,
  reducing the number of comparisons we need to do.
* We don't do `output + digit * mul` when `output == 0` and `mul == 1`. This
  seems to be consistently 1ns faster, but it's possible that this doesn't make
  a difference and the 1ns speedup I'm seeing is pure luck. I reran the
  benchmarks both with and without the change multiple times and saw a
  consistent difference but this doesn't rule out luck. This is the problem with
  microbenchmarks, when the difference becomes small enough you can't tell
  whether you're really making it faster.
* We use Rust's safe iterator interface, which is as fast as the C idiom of
  storing a "start" and "end" pointer so you can check whether the loop is
  finished with a simple `==`. If you ever hear someone say "Rust's safety
  guarantees are useless because you need to drop down to unsafe to get any real
  speed" (I've seen this almost verbatim on Hacker News before) you can show
  them this.
* We don't rely on const-folding in order to make our code fast, but it does run
  faster with a constant value for `radix`. Therefore, we add `#[inline]` to
  allow downstream crates to apply const-folding too.

The method I used for this is the basic method you should use for any
optimization work: write a representative benchmark and then progressively tweak
and rerun benchmarks until you can't shave off any more cycles. Doing this for
pure functions is much easier, so one of the first things you should do to
optimize any function that's called in a tight loop is to make it pure. This
avoids indirect writes and reads (reads and writes to places in memory that are
likely to be outside cache lines) and makes benchmarking much, much easier. If
you use test-driven development for reliability, this is the equivalent for
performance.

Extending this to work on signed integer types is an exercise for the reader.
Tip: unlike C, you can rely on signed integers overflowing with 2's complement
arithmetic. 

Here are the functions I used to benchmark the code:

```rust
#[bench]
fn bench_from_str(b: &mut Bencher) {
    b.iter(|| {
        let input = black_box("1235112512");
        assert_eq!(from_str_radix(input, 10), Ok(1235112512));
        let input = black_box("FFaf125A");
        assert_eq!(from_str_radix(input, 16), Ok(0xFFaf125A));
    });
}

#[bench]
fn bench_from_str_native(b: &mut Bencher) {
    b.iter(|| {
        let input = black_box("1235112512");
        assert_eq!(usize::from_str_radix(input, 10), Ok(1235112512));
        let input = black_box("FFaf125A");
        assert_eq!(usize::from_str_radix(input, 16), Ok(0xFFaf125A));
    });
}

#[bench]
fn bench_from_str_nonconstradix(b: &mut Bencher) {
    b.iter(|| {
        let input = black_box("1235112512");
        let radix = black_box(10);
        assert_eq!(from_str_radix(input, radix), Ok(1235112512));
        let input = black_box("FFaf125A");
        let radix = black_box(16);
        assert_eq!(from_str_radix(input, radix), Ok(0xFFaf125A));
    });
}

#[bench]
fn bench_from_str_native_nonconstradix(b: &mut Bencher) {
    b.iter(|| {
        let input = black_box("1235112512");
        let radix = black_box(10);
        assert_eq!(usize::from_str_radix(input, radix), Ok(1235112512));
        let input = black_box("FFaf125A");
        let radix = black_box(16);
        assert_eq!(usize::from_str_radix(input, radix), Ok(0xFFaf125A));
    });
}

#[bench]
fn bench_from_str_1char(b: &mut Bencher) {
    b.iter(|| {
        let input = black_box("1");
        assert_eq!(from_str_radix(input, 10), Ok(1));
        let input = black_box("F");
        assert_eq!(from_str_radix(input, 16), Ok(0xF));
    });
}

#[bench]
fn bench_from_str_native_1char(b: &mut Bencher) {
    b.iter(|| {
        let input = black_box("1");
        assert_eq!(usize::from_str_radix(input, 10), Ok(1));
        let input = black_box("F");
        assert_eq!(usize::from_str_radix(input, 16), Ok(0xF));
    });
}
```

Results:

```
test bench_from_str                      ... bench:          22 ns/iter (+/- 7)
test bench_from_str_native               ... bench:          36 ns/iter (+/- 0)
test bench_from_str_nonconstradix        ... bench:          26 ns/iter (+/- 0)
test bench_from_str_native_nonconstradix ... bench:          39 ns/iter (+/- 0)
test bench_from_str_1char                ... bench:           5 ns/iter (+/- 0)
test bench_from_str_native_1char         ... bench:          13 ns/iter (+/- 0)
```

Something I've noticed with benchmarks below 1ms is that it can take some time
to "spin up" the CPU. Occasionally the first benchmark in a set will take
20-30ns longer than the ones after it. If you duplicate the benchmark verbatim
and take the number with the lowest variance this avoids the issue. I think this
is due to the CPU needing to gather information in order to do proper branch
prediction. Ideally you'd just not do micro-benchmarks, but some functions do
legitimately call for it. Don't trust a benchmark, especially a microbenchmark,
until you've rerun it multiple times.

When I reran this particular benchmark (at least 10 times in total, not
including the benchmarks I ran while editing the code) to ensure that the
numbers were stable, and although the averages are extremely stable (the native
one sometimes was slightly slower, the 36ns value above is what I see most of
the time), the variances are mostly 0-3ns with spikes of 13-26ns. I don't have a
good explanation for this, expect a follow-up post with tips on writing better
benchmarks. 

This is a perfect example of why low-level optimization is important, since this
is exactly the kind of function that could be used hundreds of thousands of
times in parsers of textual data and a 10ns speedup here could lead to
meaningful improvements over the life of the program. It's also an example of
why you should avoid low-level optimization when possible. The original stdlib
implementation of this function isn't the most idiomatic code, but it's
significantly more readable than this. Having said that, though, it's a
testament to Rust's commitment to zero-cost abstractions that you can write
mostly-idiomatic, safe code and have it perform as well as equivalent C/C++ code
that would require use of unsafe pointer arithmetic. 

## Wrapping up

If I had to sum the trick to optimization up in a pithy QotW-ready snippet it
would be this:

> The fastest code is code that doesn't run at all, the second-fastest code is
> code that never stops running.

Ideally, you want to do less work, and if you're doing the minimum amount of
work you want to reduce the amount of time the CPU spends waiting around.

If you want more Rustic performance tips with more numbers I would consider
[BurntSushi's excellent post-mortem of ripgrep][ripgrep article] required
reading for anyone wanting to write fast software (it was the thing that
originally sent me down this deep, deep rabbit hole). For more general systems 
language-y points, check out Andrei Alexandrescu's talk ["Fastware"][fastware],
from which the `from_str_radix` and `log_base` code was adapted. A lot of the
points in this article are expansions upon points behind one of those two links.

I hope that whether you're a soft-shell Rustacean or a grizzled veteran, this
has given you a better sense of when some code may be poorly performing, and
what to do about it. Go make things go vroom.

[ripgrep article]: http://blog.burntsushi.net/ripgrep/
[fastware]: https://www.youtube.com/watch?v=o4-CwDo2zpg



##
##


This removes the "landing pads" that allow Rust to show a nice stack trace after a panic, and causes any panic to end the program instantly.

The landing pads are not used for printing a stack trace, but to unwind the stack (call drop impl for all values on the stack). stack traces are still shown with panic=abort.

@hluk
hluk commented on May 20, 2017
on a 64-bit CPU ... we end up with both *mut T and usize being 4 bytes each

I think for a 64-bit CPU this should be 8 bytes (at least for the pointer).

@bitshifter
bitshifter commented on May 13, 2018
Nice write up. For people who are doing a lot of scalar float work it might be good to mention that Rust doesn't have an equivalent to C/C++ -ffast-math. There's a bit of discussion here https://internals.rust-lang.org/t/pre-rfc-whats-the-best-way-to-implement-ffast-math/5740.

@GeorgeHahn
GeorgeHahn commented on Jul 10, 2019
Here are Rust compiler explorer links to the code in this post

Avoid Box<Trait>: https://rust.godbolt.org/z/hUd5Lb
Loop unrolling: https://rust.godbolt.org/z/b1d9ir
assert! beforehand: https://rust.godbolt.org/z/hHWWP1
from_str_radix case study: https://rust.godbolt.org/z/CM81d_

@silmeth
silmeth commented on Oct 20, 2019
A nitpick – in assert! conditions beforehand:

fn do_something_with_array(array: &[u8]) -> u8 {
    assert!(array.len >= 5);
    array[0] + array[1] + array[2] + array[3] + array[4] + array[5]
}
this should be assert!(array.len > 5);. In the current form array.len == 5 would pass the assert but would panic later in the array[5] access, so the last bound check would not be optimized out.

@DutchGhost
DutchGhost commented on Jan 25, 2020 • 
This isn't your fault, but more a codegen issue. The log_base_increasing function doesn't handle all inputs, due to overflow, resulting in an infinite loop, which LLVM doesn't like verry much.

https://play.rust-lang.org/?version=stable&mode=release&edition=2018&gist=b0b20816cffa875b18fc0af225c3b1fa

LLVM optimization issue: rust-lang/rust#28728

@yjhn
yjhn commented on Mar 13, 2021 • 
Bug report for assert! before accessing array / vector index: rust-lang/rust#50759

@AriFordsham
AriFordsham commented on Aug 9, 2021
an absolutely amazing library for Haskell called Haxl ... shows the power of computational abstractions like monads

Some Haskell pedantry: Haxl demonstrates the limitations of monads. it shows the power of applicatives. (Applicative Haxl can be made concurrent automatically, monadic usage must be serialised).

@porky11
porky11 commented on Nov 27, 2021
A nitpick – in assert! conditions beforehand:

fn do_something_with_array(array: &[u8]) -> u8 {
    assert!(array.len >= 5);
    array[0] + array[1] + array[2] + array[3] + array[4] + array[5]
}
this should be assert!(array.len > 5);. In the current form array.len == 5 would pass the assert but would panic later in the array[5] access, so the last bound check would not be optimized out.

It should be >= 6, right?

@RpxdYTX
RpxdYTX commented on Feb 24, 2022 • 
It should be >= 6, right?

That works aswell, but i feel that > 5 is more readable

@ANtlord
ANtlord commented on Mar 31 • 
Originally I wrote a version of this that works forwards and multiplies output by radix each loop but the backwards method is 10% faster

Could you share the version of the function without mul? I can't figure out how to avoid it. I have one idea in my mind. The idea involves computing the power of radix on every iteration. Given that, the complexity of the algorithm is higher. As a result, the optimization is algorithmic, which makes the idea irrelevant.
