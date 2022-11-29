# Useful Pandas Snippets

A personal diary of DataFrame munging over the years.


#Get indices of rows that contain substring s in column col

print(len(df[df['col'].str.contains("s")].index.values[:]))


# Grab DataFrame rows where column has certain values
valuelist = ['value1', 'value2', 'value3']
df = df.loc[:,df.columns.isin(valuelist)]

# Grab DataFrame rows where column doesn't have certain values
valuelist = ['value1', 'value2', 'value3']
df = df.loc[:,~df.columns.isin(value_list)]


##
##
##


## Data Types and Conversion

Convert Series datatype to numeric (will error if column has non-numeric values)  
(h/t [@makmanalp](https://github.com/makmanalp))

```
pd.to_numeric(df['Column Name'])
```

Convert Series datatype to numeric, changing  non-numeric values to NaN  
(h/t [@makmanalp](https://github.com/makmanalp) for the updated syntax!)

```
pd.to_numeric(df['Column Name'], errors='coerce')
```

Change data type of DataFrame column

```
df.column_name = df.column_name.astype(np.int64)
```

## Exploring and Finding Data

Get a report of all duplicate records in a DataFrame, based on specific columns

```
dupes = df[df.duplicated(
    ['col1', 'col2', 'col3'], keep=False)]
```

List unique values in a DataFrame column  
(h/t [@makmanalp](https://github.com/makmanalp) for the updated syntax!)

```
df['Column Name'].unique()
```

For each unique value in a DataFrame column, get a frequency count

```
df['Column Name'].value_counts()
```

Grab DataFrame rows where column = a specific value

```
df = df.loc[df.column == 'somevalue']
```

Grab DataFrame rows where column value is present in a list

```
test_data = {'hi': 'yo', 'bye': 'later'}
df = pd.DataFrame(list(d.items()), columns=['col1', 'col2'])
valuelist = ['yo', 'heya']
df[df.col2.isin(valuelist)]
```

Grab DataFrame rows where column value is not present in a list

```
test_data = {'hi': 'yo', 'bye': 'later'}
df = pd.DataFrame(list(d.items()), columns=['col1', 'col2'])
valuelist = ['yo', 'heya']
df[~df.col2.isin(valuelist)]
```

Select from DataFrame using criteria from multiple columns  
(use `|` instead of `&` to do an OR)

```
newdf = df[(df['column_one']>2004) & (df['column_two']==9)]
```
Loop through rows in a DataFrame  
(if you must)

```
for index, row in df.iterrows():
    print (index, row['some column'])
```

Much faster way to loop through DataFrame rows if you can work with tuples  
(h/t [hughamacmullaniv](https://github.com/hughamacmullaniv))

```
for row in df.itertuples():
    print(row)
```

Get top n for each group of columns in a sorted DataFrame  
(make sure DataFrame is sorted first)

```
top5 = df.groupby(
    ['groupingcol1',
    'groupingcol2']).head(5)
```

Grab DataFrame rows where specific column is null/notnull

```
newdf = df[df['column'].isnull()]
```

Select from DataFrame using multiple keys of a hierarchical index

```
df.xs(
    ('index level 1 value','index level 2 value'),
    level=('level 1','level 2'))
```

Slice values in a DataFrame column (aka Series)

```
df.column.str[0:2]
```

Get quick count of rows in a DataFrame

```
len(df.index)
```

Get length of data in a DataFrame column

```
df.column_name.str.len()
```

## Updating and Cleaning Data

Delete column from DataFrame

```
del df['column']
```

Rename several DataFrame columns

```
df = df.rename(columns = {
    'col1 old name':'col1 new name',
    'col2 old name':'col2 new name',
    'col3 old name':'col3 new name',
})
```

Lower-case all DataFrame column names

```
df.columns = map(str.lower, df.columns)
```

Even more fancy DataFrame column re-naming  
lower-case all DataFrame column names (for example)

```
df.rename(columns=lambda x: x.split('.')[-1], inplace=True)
```

Lower-case everything in a DataFrame column

```
df.column_name = df.column_name.str.lower()
```

Sort DataFrame by multiple columns

```
df = df.sort_values(
    ['col1','col2','col3'],ascending=[1,1,0])
```

Change all NaNs to None (useful before loading to a db)

```
df = df.where((pd.notnull(df)), None)
```

More pre-db insert cleanup...make a pass through the DataFrame, stripping whitespace from strings and changing any empty values to `None`  
(not especially recommended but including here b/c I had to do this in real life once)

```
df = df.applymap(lambda x: str(x).strip() if len(str(x).strip()) else None)
```

Get rid of non-numeric values throughout a DataFrame:

```
for col in refunds.columns.values:
  refunds[col] = refunds[col].replace(
      '[^0-9]+.-', '', regex=True)
 ```

Set DataFrame column values based on other column   values  
(h/t: [@mlevkov](https://github.com/mlevkov))

```
df.loc[(df['column1'] == some_value) & (df['column2'] == some_other_value), ['column_to_change']] = new_value
```

Clean up missing values in multiple DataFrame columns

```
df = df.fillna({
    'col1': 'missing',
    'col2': '99.999',
    'col3': '999',
    'col4': 'missing',
    'col5': 'missing',
    'col6': '99'
})
```
Doing calculations with DataFrame columns that have missing values. In example below, swap in 0 for df['col1'] cells that contain null.

```
df['new_col'] = np.where(
    pd.isnull(df['col1']), 0, df['col1']) + df['col2']
```

Split delimited values in a DataFrame column into two new columns  

```
df['new_col1'], df['new_col2'] = zip(
    *df['original_col'].apply(
        lambda x: x.split(': ', 1)))
```

Collapse hierarchical column indexes

```
df.columns = df.columns.get_level_values(0)
```

## Reshaping, Concatenating, and Merging Data

Pivot data (with flexibility about what what becomes a column and what stays a row).  

```
pd.pivot_table(
  df,values='cell_value',
  index=['col1', 'col2', 'col3'], #these stay as columns; will fail silently if any of these cols have null values
  columns=['col4']) #data values in this column become their own column
 ```

Concatenate two DataFrame columns into a new, single column  
(useful when dealing with composite keys, for example)  
(h/t [@makmanalp](https://github.com/makmanalp) for improving this one!)

```
df['newcol'] = df['col1'].astype(str) + df['col2'].astype(str)
```

## Display and formatting
Set up formatting so larger numbers aren't displayed in scientific notation  
(h/t [@thecapacity](https://github.com/thecapacity))

```
pd.set_option('display.float_format', lambda x: '%.3f' % x)
```

To display with commas and no decimals

```
pd.options.display.float_format = '{:,.0f}'.format
```

## Creating DataFrames

Create a DataFrame from a Python dictionary

```
df = pd.DataFrame(list(a_dictionary.items()), columns = ['column1', 'column2'])
```

Convert Django queryset to DataFrame

```
qs = DjangoModelName.objects.all()
q = qs.values()
df = pd.DataFrame.from_records(q)
```
