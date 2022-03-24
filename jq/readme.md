http://www.w3schools.com/js
http://www.w3schools.com/jquery/
http://api.jquery.com/
http://www.html5canvastutorials.com/

--> events:
	$('#submit').click(function);
	$("p").dblclick(function);
	$("#id").change(function);
	$(canvas).mousedown(function);
	$(canvas).mousemove(function);
	$("#contact").on('submit', function);
	$('#web').on('input', function);
	$(document).on('change', 'input', function);

	blur		focus		load		resize		scroll
	unload		beforeun	load		click		dblclick
	mousedown	mouseup		mousemove	mouseover	mouseout
	mouseenter	mouseleave	change		select		submit
	keydown		keypress	keyup
	
--> selectors
	http://www.w3schools.com/jquery/trysel.asp

	$("#test") 			//id
	$(".test") 			//class
	
	$(this)				//current html element
	$("p")				//html element
	$("h1, p")			//h1 and p
	$("p.intro")			//html element with class intro
	$("p:first")			//first <p> element
	$("ul li:first")		//first <li> element of the first <ul>
	$("ul li:first-child")		//first <li> element of every <ul>
	$("tr:even")			//all even <tr> elements
	$("tr:odd")			//all odd <tr> elements
	$(":button")			//all <button> elements and <input> elements of type="button"
	
	$("[href]")			//all elements with an href attribute
	$("a[target='_blank']")		//all <a> elements with a target attribute value equal to "_blank"
	$("a[target!='_blank']")	//all <a> elements with a target attribute value NOT equal to "_blank"
	
--> html
	$("#test").html();
	$("#test2").html("<b>Hello world!</b>");
	$( "#result" ).html( html.join( "<br>" ) );
	
--> text 
	$("#test").text();	
	$("#test1").text("Hello world!");
	
--> atribute
	var attr = $("#w3s").attr("href");
	$("#w3s").attr("href", "http://www.w3schools.com/jquery");
	$("p").removeAttr("style");

--> val
	var is_name = input.val();
	$('#EmployeeId').val("fgg");

--> add/remove class
	input.removeClass("invalid").addClass("valid"); 

--> css
	var color = $( this ).css( "background-color" );
	$(".element").css("margin-left") = "200px";
	$("p").css("background-color", "yellow"); 
	$("p").css({"background-color": "yellow", "font-size": "200%"}); 
	$( this ).css( "width", "+=200" );
	
--> create html elements
	var txt = $("<p></p>").text("Text.");
	$("p").append(txt);
	var div = $('<div></div>').append($('<table></table>')
	var button = $('<button/>', {
		text: 'Button' + i,
		id: 'btn_' + i,
		class: 'cb',
		click: selectButton
	});
	
--> append (AT THE END) inside de element
	$("p").append("Some appended text."); 
	
--> prepend (AT THE BEGINNING) inside de element
	$("p").prepend("Some prepended text."); 
	
--> after (AFTER the element)
	$("img").after("Some text after");

--> before (BEFORE the element)
	$("img").before("Some text before"); 
	
--> remove
	$("#div1").remove(); 
	$("p").remove(".test"); // removes all <p> elements with class="test"
	
--> empty (removes the child elements)
	$("#div1").empty();
	
--> find
	$("ul").find("span") // all <span> elements that are descendants of <ul>
	$("div").find(".first") //descendant elements with class name "first"
	$("body").find("div,li,.first") // multiple descendant elements
	
	var $findSpanElements = $("span");
    	$("ul").find($findSpanElements)
	
-----------------------

    .closest(	// get the first element that matches the selector
    .parent(	// get the parent of each element in the current set of matched elements
    .parents(	// get the ancestors of each element in the current set of matched elements
    .children() // get the children of each element in the set of matched elements
    .siblings() // get the siblings of each element in the set of matched elements
    .find(	// get the descendants of each element in the current set of matched elements
    .next() 	// get the immediately following sibling of each element in the set of matched elements
    .prev(	// get the immediately preceding sibling of each element in the set of matched elements

-----------------------
	
canvas.width  = 400;
canvas.height = 300; 
canvas.style.width  = '800px';
canvas.style.height = '600px';
@aa226
