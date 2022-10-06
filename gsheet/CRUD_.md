
# Google App Script CRUD 
Inspired by [this gist](https://gist.github.com/nyancodeid/abc7f2c3ce47eda753dee8a2b63070ab).

## Getting Started
1. Create a new App Script project.
2. Paste the content of the file `google-app-script-crud.gs` in the default `Code.gs` file.
3. Create a new Spreadsheet.
4. Copy the Spreadsheet ID found in the URL into the variable `SHEET_ID` located in line 1 of your file.

### Sheet Structure Tips
* Every Sheet should have an `id` column as the recommended structure. Think of it as a relational database.
* There is no auto-increments in the script logic for the `id` column, but can be easy send in the payload just getting the total length of the table + 1.

## API

### Read
Query params:
```
@parameter-required action=read
@parameter-required table=<SHEET_NAME>
@parameter-optional id=<COLUMN_ID>
```
When providing the optional id, it will fetch that record in key-value format.
#### Example:
Request 
`GET https://<yourappscripturl>?action=read&table=employees`

Response:
```
{"success":true,"data":[{"id":1,"name":"Carls","email":"carls@employee.com","account":000000000,"row":2},{"id":2,"name":"Alf","email":"alf@employee.com","account":000000000,"row":3},{"id":3,"name":"Rich","email":"rich@employee.com","account":000000000,"row":4},{"id":4,"name":"Salem!","email":"salem@cats.org","account":000000000,"row":5}]}
```
### Insert

Query params:
```
@parameter-required action=insert
@parameter-required table=<SHEET_NAME>
@parameter-required data=JSON
```

#### Example:
Request 
`GET https://<yourappscripturl>?action=insert&table=employees&data={"id":5,"name":"John Doe","email":"john@mail.org","account":1111}`

Response:
```
{"success":true,"data":{"id":5,"name":"John Doe","email":"john@mail.org","account":1111}
```
### Update
Query params:
```
@parameter-required action=update
@parameter-required table=<SHEET_NAME>
@parameter-required id=ID
@parameter-required data=JSON
```
To update you only need to provide with the key-value JSON of what's going to change.
#### Example:
Request 
`GET https://<yourappscripturl>?action=update&table=employees&id=5&data={"name":"Johnnathan"}`

Response:
```
{"success":true,"data":{"id":5,"name":"Johnnathan","email":"john@mail.org","account":1111}
```

### Delete
Query params:
```
@parameter-required action=delete
@parameter-required table=<SHEET_NAME>
@parameter-required id=ID
```
#### Example:
Request 
`GET https://<yourappscripturl>?action=delete&table=employees&id=5`

Response:
```
{"success":true,"data":{"id":5,"name":"Johnnathan","email":"john@mail.org","account":1111}
```

## Author

* **Richard Blondet**  - [RichardBlondet](https://github.com/richardblondet)

## License

This project is licensed under the MIT License - see the [LICENSE]([https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT)) file for details.
