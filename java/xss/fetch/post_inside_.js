//
//

function submitForm() {
  // Create a new XMLHttpRequest object
  var xhr = new XMLHttpRequest();

  // Define the method and URL for the request
  xhr.open("POST", "/auth.php", true);

  // Set the appropriate headers for a form POST request
  xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

  // Define the data to send (email and password)
  var data = "email=tristan@mailroom.htb&password=your_password_here";
  
  // Set up a callback function to handle the response
  xhr.onreadystatechange = function () {
    if (xhr.readyState === 4) { // Request is complete
      if (xhr.status === 200) { // Request was successful
        // Handle the response here
        var response = JSON.parse(xhr.responseText);
        // You can do something with the response data here
        document.getElementById('message').textContent = response.message;
        document.getElementById('password').value = '';
        document.getElementById('message').removeAttribute("hidden");
      } else {
        // Handle errors here
        alert('Error: ' + xhr.status + ' ' + xhr.statusText);
      }
    }
  };

  // Send the POST request with the form data
  xhr.send(data);
}

// Call the submitForm function to initiate the POST request
submitForm();

//
//
