/*
Modern GitHub Gist API via jQuery + Personal Access Token (PAT) .. updated ..
Requirements:
  - Generate a PAT in GitHub with `gist` scope
  - Never embed your token in public code! Use environment injection
*/

const GITHUB_TOKEN = "ghp_yourGeneratedTokenHere"; // gist scope

// Create a Gist
$.ajax({
    url: "https://api.github.com/gists",
    method: "POST",
    headers: {
        "Authorization": "Bearer " + GITHUB_TOKEN,
        "Accept": "application/vnd.github+json"
    },
    contentType: "application/json",
    data: JSON.stringify({
        description: "A gist created via jQuery Ajax",
        public: true,
        files: {
            "file1.txt": { "content": "String file contents via ajax" }
        }
    })
}).done(function(response) {
    console.log("Created Gist:", response);

    const gistId = response.id;

    // Edit the gist we just created
    $.ajax({
        url: `https://api.github.com/gists/${gistId}`,
        method: "PATCH",
        headers: {
            "Authorization": "Bearer " + GITHUB_TOKEN,
            "Accept": "application/vnd.github+json"
        },
        contentType: "application/json",
        data: JSON.stringify({
            description: "Updated gist via ajax",
            files: {
                "file1.txt": { "content": "Updated string file contents via ajax" }
            }
        })
    }).done(function(updateResponse) {
        console.log("Updated Gist:", updateResponse);
    });
});

