
Julius (Caesar) — Yesterday at 8:16 PM
@Po1n7s a lambda is just a function that returns itself as a variable on its definition, then you call it using the variable name you gave it later, a lambda without a name is called an anonymous function, and these are often used for functional-style iterating over containers, which is probably what you're seeing in the code you're working with. I'm not clued in to how lambdas work in python but I can just tell you generally, as they tend to work similar everywhere.
What a lambda function is great for is generating a function that can be passed as a parameter to another function, where the receiving function can define a parameter that is a function of a certain "shape", that being parameters and in strong typed languages, parameter types and return types.
This is great for abstracting away the implementation details of iterating over data structures, and many standard libraries do this, and provide an interface, usually called something like Iterable, that implements those ways of iterating over a data structure, and these interfaces usually require the iterator functions to provide APIs that accept functions as parameters, so that the caller can define some internal logic for the internal iterator algorithm, or to perform some task, called from within the iterator implementation, but defined outside of it.
Julius (Caesar) — Yesterday at 8:31 PM
So you could maybe have a data structure that implements the hypothetical filter function that traverses the structure, calling the function on every item in the structure, returning only the items in that structure where, when that item is passed into the given lambda, causes that lambda to return True, that lambda (or callback in some languages) would accept an item and perform some task on the item, perhaps it checks an age item where it only returns true on values that are 21 or higher, your filter call would look something like
over_20 = <structure>.filter(lambda item: item.age >= 21)
Another use for lambdas could be for registering functions to an event system that trigger the function when some event happens, if you've done event driven programming you've already seen this, you might have a GUI that has a button, the button might have a function called OnClick that accepts a function as its parameter, which registers your function to do some shit when the button is clicked. That function could accept a lambda statement in your code
Julius (Caesar) — Yesterday at 9:21 PM
  
```
#[derive(Debug)] // for debug print
struct User {
    username: String,
    email: String,
    // could have some other shit too
}

impl User {
    // just a constructor so I don't have to to .to_owned() on each string
    fn new(username: &str, email: &str) -> User {
        User {
            username: username.to_owned(),
            email: email.to_owned(),
        }
    }
}

fn main() {

    let users = vec![
        User::new("Anthony", "anthony@kryptsec.com"),
        User::new("Peter",   "peter@kryptsec.com"),
        User::new("Poop",    "poop@hacker.com"),
        User::new("po1nt5",  "po1nt5@kryptsec.com"),
        User::new("tr33",    "tr33@kryptsec.com"),
    ];

    let p_users: Vec<&User> = users.iter() // take the users iterator
         // upon which we call .filter, passing it a lambda (in rust its called a closure) that
         // checks the first character of the username case-insensitive starts with the letter p
         //     sidenote, a lambda in rust looks like this: |<parameters>| <function body>
         //                                        or this: |<parameters>| { <function body> }
        .filter(|user| user.username.to_lowercase().starts_with("p"))
        // we can also add more filters here, for example the one below will filter the email
        .filter(|user| user.email.split_once("@").unwrap().1.to_lowercase() == "kryptsec.com")
        .collect(); // and collects them into a vector of references to the users in the users Vec

    // debug pretty print the struct
    println!("{:?}", p_users);
    // output: [User { username: "Peter", email: "peter@kryptsec.com" }, User { username: "po1nt5", email: "po1nt5@kryptsec.com" }\
  ]
}
```  
# in python, assuming we have the expected classes all set up and the libraries imported this is the procedural equivalent
p_users = []
for user in users:
    if user.username.lower()[0] == 'p' && user.email.lower().split("@")[1].lower() == "kryptsec.com":
        p_users.append(user)

# in functional python, this might look like the following (I dunno functional python)
p_users = users
    .filter(lambda user: user.username.lower()[0] == 'p' && user.email.lower().split(@)[1] == "kryptsec.com")
