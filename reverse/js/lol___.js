
    F = d3.time.format("%Y%U"),                 # Time formatter for "${year}${week_number}", with year as a 4 digit number
    q = d3.time.format("%m-%y"),                # Time formatter for month-year, each as a 2 digit integer
    y = d3.time.format("%b"),                   # Time formatter for abbreviated month name
    I = {},                                     # Keys are "$year$week_number" from F above, values are [Date, Score] pairs
    j = {},                                     # Keys are "$month-$year" from q above, values are a count of how many $week_numbers begin in that month
    a.forEach(function(t) {                     # Function to set I above
        var e;
        return
            e = F(t[0]),                        # Get "$year$week_number" for this day
            I[e] || (I[e] = []),                # Default I[e] to an empty list, if its not already been initialized
            I[e].push(t)                        # Push this [Date, Score] pair onto the appropriate keys array
    }),
    I = d3.entries(I),                          # Convert associative array to array of objects with {key, value} attributes
    I.forEach(function(t) {                     # Function to set j above
        var e;
        return
            e = q(t.value[0][0]),               # Get "$month-$year" for first day of this week (noteworthy: January 1st is a different week from December 31st, even if they fall on the same calendar line)
            j[e] || (j[e] = [t.value[0][0], 0]),# If key is not already initialized, create it with [First_Date, 0]
            j[e][1] += 1                        # Increment this months counter by one
    }),
    j = d3.entries(j).sort(function(t, e) {     # Convert hash of j[$month-$year] = [first_day_a_week_starts_in_this_month, counter_of_weeks_that_begin_in_this_month] to array of {key, value} objects
            return d3.ascending(t.value[0], e.value[0])
        }),
///
    M.selectAll("text.month")                   # Now were working on months
    .data(j)                                    # Using the $month-$year mapping
    .enter().append("text")                     # Make the text labels
    .attr("x", function(e) {                    # Set the x coordinate to $cell_size * $offset
        var n;
        return
            n = t * d,                          # Calculate $cell_size * $offset
            d += e.value[1],                    # Then increment the offset by the size of this month
            n                                   # Then return the previously calculated value
    })
    .attr("y", -5)                              # Set the y coord
    .attr("class", "month")                     # Class it up
    .style("display", function(t) {             # If it would be on the very left edge, hide it
        return t.value[1] <= 2 ? "none" : void 0
    })
    .text(function(t) {                         # The text is the abbreviated month name ("Jan")
        return y(t.value[0])
    }),
///
///algorithm to reverse a Singly Linked List in javascript


var LinkedList = function(head){
	this.head = head;
	this.length = 0;
};

var Node = function(value){
	this.value = value;
	this.next = null;
};

LinkedList.prototype.add = function (data){
	var thisnode = new Node(data);
	var currentNode = this.head
	this.length++;
	
	if(!currentNode){
		this.head = thisnode;
		
		return thisnode;
		
	}else{
		while(currentNode.next)
			currentNode = currentNode.next;
		
		currentNode.next = thisnode;
		return thisnode;
	}
}

LinkedList.prototype.reverse = function(){
	var prev = null,
		curr = this.head,
		next = null;
	console.log('reversing');
	while(curr.next){
		next = curr.next;
		curr.next = prev;
		prev = curr;
		curr = next;
	}
	this.head = prev;
	return node;
}

var node = new Node(1);

var newList = new LinkedList();

for(var i = 0; i < 6;i++){
	newList.add(Math.floor(Math.random()*100));
}
for(var i = 0,currentNode = newList.head; i < 5 && newList.head ;i++){
	
	console.log(currentNode.value);
	if(!currentNode.next){
		break;
	}else{
		currentNode = currentNode.next;
	}
	
}
newList.reverse();
for(var i = 0,currentNode = newList.head; i < 5 && newList.head ;i++){
	
	console.log(currentNode.value);
	if(!currentNode.next){
		break;
	}else{
		currentNode = currentNode.next;
	}
	
}
