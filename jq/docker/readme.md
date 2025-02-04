# Advanced jq Hacks: A Collection of Useful Examples


---

## Table of Contents

1. [Introduction](#introduction)
2. [Basic Filtering and Selection](#basic-filtering-and-selection)
   - [Example 1: Find Docker Images with a Blank Tag](#example-1-find-docker-images-with-a-blank-tag)
   - [Example 2: Count Images with a Blank Tag](#example-2-count-images-with-a-blank-tag)
3. [Mapping and Transforming Data](#mapping-and-transforming-data)
   - [Example 3: Extract Repository Names from Images with a Blank Tag](#example-3-extract-repository-names-from-images-with-a-blank-tag)
   - [Example 4: Rename Keys in Objects](#example-4-rename-keys-in-objects)
4. [Working with Nested and Complex JSON](#working-with-nested-and-complex-json)
   - [Example 5: Extract Pod Names and Statuses from Kubernetes JSON](#example-5-extract-pod-names-and-statuses-from-kubernetes-json)
   - [Example 6: Group Pods by Namespace](#example-6-group-pods-by-namespace)
5. [Advanced Filtering and Aggregation](#advanced-filtering-and-aggregation)
   - [Example 7: Find Keys with Null or Empty Values](#example-7-find-keys-with-null-or-empty-values)
   - [Example 8: Combine Filters with Conditions](#example-8-combine-filters-with-conditions)
6. [Additional Useful jq Functions and Tips](#additional-useful-jq-functions-and-tips)
   - [Mapping with `map()`](#mapping-with-map)
   - [Using `del()` to Remove Keys](#using-del-to-remove-keys)
   - [Chaining Filters](#chaining-filters)
   - [Raw Output with `-r`](#raw-output-with--r)
7. [Extra Examples](#extra-examples)
   - [Example 9: Pretty-Print and Explore a JSON File](#example-9-pretty-print-and-explore-a-json-file)
   - [Example 10: Conditional Value Transformation](#example-10-conditional-value-transformation)
   - [Example 11: Flatten Nested Arrays](#example-11-flatten-nested-arrays)
   - [Example 12: Extract Values from Deeply Nested Objects](#example-12-extract-values-from-deeply-nested-objects)
8. [Conclusion](#conclusion)

---

## Introduction

`jq` is a powerful command-line JSON processor that allows you to slice, filter, map, and transform structured data with ease. The examples below range from basic filters to more advanced queries that can handle deeply nested JSON structures.

---

## Basic Filtering and Selection

### Example 1: Find Docker Images with a Blank Tag

Assume you have a JSON file (`images.json`) like this:
```
json
[
  { "repository": "docker.io/library/ubuntu", "tag": "latest", "id": "abc123" },
  { "repository": "docker.io/library/myimage", "tag": "", "id": "def456" },
  { "repository": "docker.io/library/another", "tag": "", "id": "ghi789" }
]
Filter images with an empty "tag":

sh
Copy
jq '.[] | select(.tag == "")' images.json
Example 2: Count Images with a Blank Tag
Count the filtered images:

sh
Copy
jq '[.[] | select(.tag == "")] | length' images.json
Mapping and Transforming Data
Example 3: Extract Repository Names from Images with a Blank Tag
Generate an array of repository names for images with no tag:

sh
Copy
jq '[.[] | select(.tag == "") | .repository]' images.json
Example 4: Rename Keys in Objects
Transform the structure to output just the repository and image ID:


jq '.[] | {repo: .repository, imageID: .id}' images.json
Working with Nested and Complex JSON
Imagine a Kubernetes JSON output from kubectl get pods -o json:

```
```
{
  "items": [
    {
      "metadata": { "name": "pod1", "namespace": "default" },
      "status": { "phase": "Running", "hostIP": "10.0.0.1" }
    },
    {
      "metadata": { "name": "pod2", "namespace": "default" },
      "status": { "phase": "Pending", "hostIP": "10.0.0.2" }
    }
  ]
}
```

Example 5: Extract Pod Names and Statuses from Kubernetes JSON
Extract key details from each pod:

```
jq '.items[] | {name: .metadata.name, status: .status.phase}' pods.json

```
Example 6: Group Pods by Namespace
```

Group pods into namespaces and list their names:


jq '.items 
    | group_by(.metadata.namespace) 
    | map({namespace: .[0].metadata.namespace, pods: map(.metadata.name)})' pods.json

```
# Advanced Filtering and Aggregation
```
Example 7: Find Keys with Null or Empty Values
List all paths (keys) in a JSON file (complex.json) where the value is null or empty:

```
```
jq 'paths 
    | select(getpath(.) == null or (getpath(.) == ""))' complex.json

Example 8: Combine Filters with Conditions
Filter Docker images that have a blank tag and where the repository starts with a specific prefix:


jq '.[] | select(.tag == "" and (.repository | startswith("docker.io/library/"))) ' images.json


Additional Useful jq Functions and Tips
Mapping with map()
Apply a transformation to every element in an array:

jq 'map(.repository)' images.json
Using del() to Remove Keys
Remove the id key from each object:

jq 'del(.[].id)' images.json
Chaining Filters
Combine filters and transformations:


jq '.[] | select(.tag == "") | {repository: .repository, note: "missing tag"}' images.json
Raw Output with -r
Print raw strings (without quotes) from JSON:


jq -r '.[] | .repository' images.json
Extra Examples
Example 9: Pretty-Print and Explore a JSON File
If you're not sure about the JSON structure, you can pretty-print it:

jq '.' file.json
Example 10: Conditional Value Transformation
Suppose you want to change a value if it meets a condition. For example, if a Docker image has an empty tag, set it to "untagged":

jq 'map(if .tag == "" then .tag = "untagged" else . end)' images.json
Example 11: Flatten Nested Arrays
If you have nested arrays and want to flatten them into a single array, you can use the flatten function. For example:

{
  "nested": [[1, 2], [3, 4], [5]]
}

Flatten the nested arrays:

```
jq '.nested | flatten' nested.json
```

Example 12: Extract Values from Deeply Nested Objects
Given a JSON structure with deeply nested values, you can extract them by specifying the full path. For example, suppose data.json contains:

```
{
  "level1": {
    "level2": {
      "level3": {
        "value": "desired_value"
      }
    }
  }
}
```

Extract the nested value:

```
jq '.level1.level2.level3.value' data.json
```

Alternatively, if you're unsure of the nesting depth, you can use the .. recursive descent operator:
```
jq '.. | objects | .value? // empty' data.json
```
This searches for any object with a key named value and prints its content.
