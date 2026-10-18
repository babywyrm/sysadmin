///////////////
///////////////

function createTable(parsed) {
        var content = "";
        parsed.forEach(function (row, i) {
                if (i === 0) {
                        content += "<thead>";
                }
                content += "<tr>";
                row.forEach(function (cell) {
                        content += "<td>" + cell + "</td>";
                });
                content += "</tr>";
                if (i === 0) {
                        content += "</thead><tbody>";
                }
        });
        content += "</tbody>";

        document.getElementById("table").innerHTML = content;
}

function parseCSV(csv) {
        var resultArray = [];
        csv.split("\n").forEach(function (row) {
                var rowArray = [];
                row.split(",").forEach(function (cell) {
                        rowArray.push(cell);
                });
                resultArray.push(rowArray);
        });
        return resultArray;
}

document.addEventListener('keydown', function () {
        generateTable()
});

function generateTable() {
        parsed = parseCSV(document.getElementById("csv").value)
        createTable(parsed)
}

document.getElementById("share").addEventListener("click", function () {
        var myModal = new bootstrap.Modal(document.getElementById('myModal'), {
                keyboard: false
          })
          myModal.show()
          shareLink = document.getElementById("shareLink")
          shareLink.value = "?csv=" + encodeURIComponent(btoa(document.getElementById("csv").value))
});

var urlSearchParams = new URLSearchParams(window.location.search);
var params = Object.fromEntries(urlSearchParams.entries());

if (params.csv){
        document.getElementById("csv").value = atob(params.csv)
}else if (!document.getElementById("csv").value) {
        document.getElementById("csv").value = "#,User,active\n24895,Yawn,1\n95843,Thing,1\n57392,Mom,1"
}

//////////////////
//
//
